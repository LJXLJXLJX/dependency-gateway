"""Conda admission, cache freshness, fallback and HTTP transport regressions."""

from __future__ import annotations

import bz2
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from dependency_gateway.core.config import (
    ConfigError,
    GatewayConfig,
    SourceConfig,
    load_config,
)
from dependency_gateway.gateway.engine import Gateway
from dependency_gateway.gateway.fetcher import Fetcher
from dependency_gateway.gateway.inventory import cache_object
from dependency_gateway.gateway.request_stats import request_module_for_ecosystem
from dependency_gateway.gateway.server import GatewayHTTPServer
from dependency_gateway.storage.gpfs import FileStorage


def conda_source(**overrides: object) -> SourceConfig:
    return SourceConfig.from_dict(
        {
            "name": "conda-channels",
            "kind": "conda-channel",
            "ecosystem": "conda",
            "base_url": "https://mirror.example/cloud/",
            "allowed_path_prefixes": ["conda-forge/linux-64/", "conda-forge/noarch/"],
            "allowed_exact_paths": [
                "conda-forge/notices.json",
                "conda-forge/channeldata.json",
            ],
            "metadata_ttl_seconds": 300,
            "allow_query": False,
            "proxy_mode": "direct",
            **overrides,
        }
    )


class CondaConfigTest(unittest.TestCase):
    def test_manifest_sources_and_fallback_paths(self) -> None:
        config = load_config(
            Path(__file__).resolve().parents[1] / "config/sources.json"
        )
        for name, paths in {
            "conda-defaults": ("main/linux-64/repodata.json", "r/noarch/repodata.json"),
            "conda-channels": ("conda-forge/linux-64/repodata.json.zst",),
        }.items():
            source = config.source(name)
            self.assertEqual(
                (source.kind, source.ecosystem), ("conda-channel", "conda")
            )
            self.assertEqual(source.proxy_mode, "direct")
            self.assertEqual(source.fallback_upstreams[0].proxy_mode, "configured")
            for path in paths:
                candidates = source.fetch_candidates(path)
                self.assertEqual(len(candidates), 2)
                for upstream, url in candidates:
                    self.assertEqual(url, upstream.base_url + path)
                    self.assertTrue(
                        source.allows_upstream_url(upstream, url, candidate_url=url)
                    )
            for path in (
                "bioconda/noarch/repodata.json",
                "main/win-64/repodata.json",
                "conda-forge/osx-arm64/repodata.json",
            ):
                with (
                    self.subTest(source=name, path=path),
                    self.assertRaises(ConfigError),
                ):
                    source.build_url(path)

    def test_protocol_accepts_metadata_and_both_package_formats(self) -> None:
        source = conda_source()
        for filename in (
            "repodata.json",
            "current_repodata.json",
            "repodata.json.zst",
            "repodata.json.bz2",
            "current_repodata.json.zst",
            "repodata.jlap",
            "python-3.12.0-h123_0.conda",
            "six-1.16.0-pyhd8ed1ab_1.tar.bz2",
        ):
            path = "conda-forge/noarch/" + filename
            with self.subTest(path=path):
                self.assertEqual(source.build_url(path), source.base_url + path)
        for path in ("conda-forge/channeldata.json", "conda-forge/notices.json"):
            self.assertEqual(source.freshness_ttl(path, "application/json", 60), 300)

    def test_rejects_unreviewed_protocol_paths_queries_and_traversal(self) -> None:
        source = conda_source()
        for path in (
            "conda-forge/linux-64/arbitrary.json",
            "conda-forge/linux-64/install.sh",
            "conda-forge/linux-64/nested/python-3.12-h123_0.conda",
            "conda-forge/linux-64/repodata_shards.msgpack.zst",
            "conda-forge/linux-64/shards/abc.msgpack.zst",
            "conda-forge/linux-64/../noarch/repodata.json",
            "conda-forge/linux-64/%2e%2e/noarch/repodata.json",
            "conda-forge/linux-64/python.conda",
            "conda-forge/label/dev/linux-64/repodata.json",
        ):
            with self.subTest(path=path), self.assertRaises(ConfigError):
                source.build_url(path)
        with self.assertRaisesRegex(ConfigError, "query"):
            source.build_url(
                "conda-forge/linux-64/repodata.json", "url=https://other.example"
            )

    def test_requires_conda_ecosystem_ttl_allowlist_and_no_query(self) -> None:
        for overrides in (
            {"ecosystem": "generic"},
            {"metadata_ttl_seconds": None},
            {"allowed_path_prefixes": []},
            {"allow_query": True},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ConfigError):
                conda_source(**overrides)

    def test_metadata_refreshes_and_packages_remain_immutable(self) -> None:
        source = conda_source(mutable_path_prefixes=["conda-forge/"])
        for filename in (
            "repodata.json",
            "repodata.json.zst",
            "current_repodata.json.bz2",
            "repodata.jlap",
        ):
            self.assertEqual(
                source.freshness_ttl(
                    "conda-forge/linux-64/" + filename, "application/octet-stream", 60
                ),
                300,
            )
        for filename in (
            "python-3.12.0-h123_0.conda",
            "six-1.16.0-pyhd8ed1ab_1.tar.bz2",
        ):
            self.assertIsNone(
                source.freshness_ttl(
                    "conda-forge/noarch/" + filename, "application/octet-stream", 60
                )
            )

    def test_redirect_origin_and_reviewed_path_boundaries(self) -> None:
        source = conda_source()
        upstream = source.primary_upstream
        candidate = source.build_url("conda-forge/linux-64/repodata.json")
        self.assertFalse(
            source.allows_upstream_url(
                upstream,
                "https://untrusted.example/cloud/conda-forge/linux-64/repodata.json",
                candidate_url=candidate,
            )
        )
        self.assertFalse(
            source.allows_upstream_url(
                upstream,
                "https://mirror.example/cloud/bioconda/noarch/repodata.json",
                candidate_url=candidate,
            )
        )


class CondaUpstream(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.requests.append(self.path)
        prefix, _, path = self.path.lstrip("/").partition("/")
        if prefix == "primary" and self.server.redirect_primary:
            self.send_response(302)
            self.send_header("Location", "https://untrusted.example/" + path)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if prefix == "primary" and self.server.fail_primary:
            self.send_error(503)
            return
        obj = self.server.objects.get(path)
        if obj is None:
            self.send_error(404)
            return
        body, content_type = obj
        etag = '"' + hashlib.sha256(body).hexdigest() + '"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class CondaGatewayTest(unittest.TestCase):
    index_path = "conda-forge/noarch/repodata.json"
    package_path = "conda-forge/noarch/six-1.16.0-pyhd8ed1ab_1.tar.bz2"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = FileStorage(Path(self.temp.name))
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), CondaUpstream)
        self.upstream.requests = []
        self.upstream.fail_primary = False
        self.upstream.redirect_primary = False
        self.package = b"conda package fixture"
        self.index = json.dumps(
            {
                "info": {"subdir": "noarch"},
                "repodata_version": 1,
                "packages": {
                    self.package_path.rsplit("/", 1)[-1]: {
                        "name": "six",
                        "version": "1.16.0",
                        "build": "pyhd8ed1ab_1",
                        "sha256": hashlib.sha256(self.package).hexdigest(),
                    }
                },
            }
        ).encode()
        self.upstream.objects = {
            self.index_path: (self.index, "application/json"),
            self.index_path + ".bz2": (
                bz2.compress(self.index),
                "application/octet-stream",
            ),
            # A valid Zstandard frame containing one raw block with the JSON {}.
            self.index_path + ".zst": (
                b"\x28\xb5\x2f\xfd\x20\x02\x11\x00\x00{}",
                "application/octet-stream",
            ),
            self.package_path: (self.package, "application/octet-stream"),
            "conda-forge/linux-64/python-3.12.0-h123_0.conda": (
                b"binary conda fixture",
                "application/octet-stream",
            ),
        }
        self.start_server(self.upstream)
        origin = f"http://127.0.0.1:{self.upstream.server_port}"
        self.source = conda_source(
            base_url=origin + "/primary/",
            fallback_upstreams=[
                {
                    "base_url": origin + "/fallback/",
                    "proxy_mode": "direct",
                }
            ],
        )
        self.engine = Gateway(
            config=GatewayConfig({self.source.name: self.source}),
            storage=self.storage,
            fetcher=Fetcher(
                self.storage, proxy_url=None, timeout=2, max_object_bytes=1024**2
            ),
            index_ttl_seconds=300,
            cache_mode="all",
        )
        self.addCleanup(self.engine.close)
        self.server = GatewayHTTPServer(("127.0.0.1", 0), self.engine)
        self.start_server(self.server)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.opener = build_opener(ProxyHandler({}))

    def start_server(self, server: ThreadingHTTPServer) -> None:
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.01)
        )
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def request(self, path: str, **kwargs):
        return self.opener.open(
            Request(self.origin + "/v1/cache/conda-channels/" + path, **kwargs),
            timeout=2,
        )

    def expire(self, path: str) -> None:
        entry = self.storage.load(self.source.build_url(path))
        self.assertIsNotNone(entry)
        self.storage.touch(entry, 0)

    def test_index_and_package_miss_hit_preserve_bytes_and_checksums(self) -> None:
        for path, body in (
            (self.index_path, self.index),
            (self.package_path, self.package),
            (self.index_path + ".bz2", bz2.compress(self.index)),
            (
                self.index_path + ".zst",
                self.upstream.objects[self.index_path + ".zst"][0],
            ),
            (
                "conda-forge/linux-64/python-3.12.0-h123_0.conda",
                b"binary conda fixture",
            ),
        ):
            for state in ("MISS", "HIT"):
                with (
                    self.subTest(path=path, state=state),
                    self.request(path) as response,
                ):
                    self.assertEqual(response.headers["X-Dependency-Gateway"], state)
                    self.assertEqual(response.read(), body)
            self.assertEqual(self.upstream.requests.count("/primary/" + path), 1)

    def test_expired_json_and_compressed_index_revalidate_then_refresh(self) -> None:
        for path in (
            self.index_path,
            self.index_path + ".bz2",
            self.index_path + ".zst",
        ):
            with self.request(path) as response:
                response.read()
            self.expire(path)
            with self.request(path) as response:
                self.assertEqual(
                    response.headers["X-Dependency-Gateway"], "REVALIDATED"
                )
                self.assertEqual(response.read(), self.upstream.objects[path][0])
            updated = b'{"info":{"subdir":"noarch"},"packages":{}}'
            if path.endswith(".bz2"):
                updated = bz2.compress(updated)
            if path.endswith(".zst"):
                # A single raw last block; the fixture fits in a one-byte frame size.
                updated = (
                    b"\x28\xb5\x2f\xfd\x20"
                    + bytes([len(updated)])
                    + ((len(updated) << 3) | 1).to_bytes(3, "little")
                    + updated
                )
            self.upstream.objects[path] = (updated, self.upstream.objects[path][1])
            self.expire(path)
            with self.request(path) as response:
                self.assertEqual(response.headers["X-Dependency-Gateway"], "REFRESH")
                self.assertEqual(response.read(), updated)

    def test_old_package_head_and_range_remain_cache_hits(self) -> None:
        with self.request(self.package_path) as response:
            response.read()
        self.expire(self.package_path)
        with self.request(self.package_path, method="HEAD") as response:
            self.assertEqual(response.headers["X-Dependency-Gateway"], "HIT")
            self.assertEqual(int(response.headers["Content-Length"]), len(self.package))
            self.assertEqual(response.read(), b"")
        with self.request(
            self.package_path, headers={"Range": "bytes=2-7"}
        ) as response:
            self.assertEqual(response.status, 206)
            self.assertEqual(response.headers["X-Dependency-Gateway"], "HIT")
            self.assertEqual(response.read(), self.package[2:8])
        self.assertEqual(
            self.upstream.requests.count("/primary/" + self.package_path), 1
        )

    def test_primary_failure_falls_back_under_the_same_cache_identity(self) -> None:
        self.upstream.fail_primary = True
        with self.request(self.package_path) as response:
            self.assertEqual(response.headers["X-Dependency-Gateway"], "MISS")
            self.assertEqual(response.read(), self.package)
        self.assertIsNotNone(
            self.storage.load(self.source.build_url(self.package_path))
        )
        with self.request(self.package_path) as response:
            self.assertEqual(response.headers["X-Dependency-Gateway"], "HIT")
            response.read()
        self.assertEqual(
            self.upstream.requests,
            ["/primary/" + self.package_path, "/fallback/" + self.package_path],
        )

    def test_expired_index_survives_upstream_outage(self) -> None:
        with self.request(self.index_path) as response:
            response.read()
        self.expire(self.index_path)
        self.upstream.objects.clear()
        with self.request(self.index_path) as response:
            self.assertEqual(response.headers["X-Dependency-Gateway"], "STALE")
            self.assertEqual(response.read(), self.index)
        self.assertIsNotNone(self.storage.load(self.source.build_url(self.index_path)))

    def test_untrusted_redirect_is_rejected_before_safe_fallback(self) -> None:
        self.upstream.redirect_primary = True
        with self.request(self.package_path) as response:
            self.assertEqual(response.read(), self.package)
        self.assertEqual(
            self.upstream.requests,
            ["/primary/" + self.package_path, "/fallback/" + self.package_path],
        )

    def test_invalid_paths_and_query_never_contact_upstream(self) -> None:
        for path in (
            "bioconda/noarch/repodata.json",
            self.index_path + "?url=bad",
            "conda-forge/noarch/arbitrary.json",
        ):
            with self.subTest(path=path), self.assertRaises(HTTPError) as error:
                self.request(path)
            self.assertEqual(error.exception.code, 400)
            error.exception.close()
        self.assertEqual(self.upstream.requests, [])

    def test_proxy_only_preserves_existing_direct_bypass_policy(self) -> None:
        self.engine.cache_mode = "proxy-only"
        for _ in range(2):
            with self.request(self.package_path) as response:
                self.assertEqual(response.headers["X-Dependency-Gateway"], "BYPASS")
                self.assertEqual(response.read(), self.package)
        self.assertIsNone(self.storage.load(self.source.build_url(self.package_path)))
        self.assertEqual(len(self.upstream.requests), 2)

    def test_conda_inventory_and_stats_are_classified(self) -> None:
        for path in (self.index_path, self.package_path):
            with self.request(path) as response:
                response.read()
        entry = self.storage.load(self.source.build_url(self.package_path))
        obj = cache_object(self.source, self.package_path, entry)
        self.assertEqual(
            (obj.ecosystem, obj.package, obj.version, obj.platform_tag),
            ("conda", "six", "1.16.0", "noarch"),
        )
        self.assertEqual(obj.object_type, "artifact")
        with self.opener.open(self.origin + "/v1/objects?ecosystem=conda") as response:
            self.assertIn("conda-channels", response.read().decode())
        self.assertEqual(request_module_for_ecosystem("conda"), "conda")
        self.assertEqual(self.engine.stats()["modules"]["conda"]["miss"], 2)


if __name__ == "__main__":
    unittest.main()
