"""Conda dry-run resolution, domestic artifact probes and verified Gateway warm-up."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ....core.ecosystems.conda import _PACKAGE
from ..models import ProbeResult, ProbeSettings, WarmResult
from .pip.resolver import CommandRunner, _run_container

_TUNA = "https://mirrors.tuna.tsinghua.edu.cn/anaconda/"
_CHANNELS = {
    "conda-forge": (
        "conda-channels/conda-forge",
        _TUNA + "cloud/conda-forge",
        "https://conda.anaconda.org/conda-forge",
    ),
    "pkgs/main": (
        "conda-defaults/main",
        _TUNA + "pkgs/main",
        "https://repo.anaconda.com/pkgs/main",
    ),
    "pkgs/r": (
        "conda-defaults/r",
        _TUNA + "pkgs/r",
        "https://repo.anaconda.com/pkgs/r",
    ),
}
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./:@_-]{0,511}$")
_NETWORK_ERRORS = (HTTPError, URLError, TimeoutError, OSError)


def _channel_names(value: str, gateway_url: str = "") -> list[str]:
    if value == "defaults":
        return ["pkgs/main", "pkgs/r"]
    if value in _CHANNELS:
        return [value]
    for name, (route, domestic, official) in _CHANNELS.items():
        if value.rstrip("/") in {
            domestic,
            official,
            gateway_url.rstrip("/") + "/" + route,
        }:
            return [name]
    raise ValueError(
        "conda channel is outside the reviewed defaults/conda-forge policy"
    )


def _artifact_route(url: str, gateway_url: str = "") -> str:
    parsed = urlsplit(url)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("conda artifact URL has credentials, query or fragment")
    for route, domestic, official in _CHANNELS.values():
        for root in (
            domestic,
            official,
            gateway_url.rstrip("/") + "/" + route if gateway_url else "",
        ):
            if root and url.startswith(root + "/"):
                parts = url[len(root) + 1 :].split("/")
                if (
                    len(parts) == 2
                    and parts[0] in {"linux-64", "noarch"}
                    and _PACKAGE.fullmatch(parts[1])
                ):
                    return route + "/" + "/".join(parts)
    raise ValueError(
        "conda artifact is outside the reviewed channel/platform/package policy"
    )


def _domestic_url(route: str) -> str:
    for prefix, domestic, _official in _CHANNELS.values():
        if route.startswith(prefix + "/"):
            return domestic + route[len(prefix) :]
    raise ValueError("unknown conda artifact route")


def _checksum(record: dict[str, object]) -> tuple[str, str]:
    for algorithm, length in (("sha256", 64), ("md5", 32)):
        value = str(record.get(algorithm) or "").lower()
        if re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
            return algorithm, value
    raise ValueError("conda repodata has no valid SHA-256 or MD5 checksum")


class _ArtifactRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _artifact_route(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _consumer_fields(contexts: Sequence[dict[str, object]]) -> dict[str, object]:
    ids_set = {str(c["environment_id"]) for c in contexts if c.get("environment_id")}
    for context in contexts:
        values = context.get("consumer_environment_ids", [])
        if isinstance(values, (list, tuple)):
            ids_set.update(str(value) for value in values)
    ids = tuple(sorted(ids_set))
    builds_set = set()
    for context in contexts:
        values = context.get("build_contexts", [])
        if isinstance(values, (list, tuple)):
            builds_set.update(str(value) for value in values)
    builds = tuple(sorted(builds_set))
    return {
        "environment_id": ids[0] if len(ids) == 1 else None,
        "consumer_environment_ids": ids,
        "build_contexts": builds,
    }


class CondaProvider:
    manager = "conda"

    def __init__(self, command_runner: CommandRunner = _run_container):
        self.command_runner = command_runner

    @staticmethod
    def _resolver_image() -> str:
        image = os.environ.get("DEPENDENCY_GATEWAY_CONDA_RESOLVER_IMAGE", "")
        if not _IMAGE.fullmatch(image):
            raise ValueError(
                "configure DEPENDENCY_GATEWAY_CONDA_RESOLVER_IMAGE with a preloaded micromamba image"
            )
        return image

    @staticmethod
    def _options(
        row: dict[str, object], context: dict[str, object]
    ) -> dict[str, object]:
        raw = context.get("resolution_options") or row.get("resolution_options")
        if not isinstance(raw, dict):
            raise TypeError("conda preparation requires analyzed resolution options")
        if raw.get("unsupported_reason"):
            # Reasons from the analyzer are fixed text, never raw task arguments.
            raise ValueError("conda analysis has an unresolved or unsupported context")
        specs, channels = raw.get("specs"), raw.get("channels")
        if (
            not isinstance(specs, list)
            or not specs
            or not all(isinstance(s, str) for s in specs)
        ):
            raise ValueError("conda context is missing its joint package spec set")
        if (
            not isinstance(channels, list)
            or not channels
            or not all(isinstance(c, str) for c in channels)
        ):
            raise ValueError("conda context is missing its ordered channel list")
        if raw.get("platform") != "linux-64":
            raise ValueError(
                "conda preparer currently supports only linux-64 plus noarch dependencies"
            )
        if raw.get("channel_priority", "flexible") not in {
            "flexible",
            "strict",
            "disabled",
        }:
            raise ValueError("unsupported conda channel priority")
        for channel in channels:
            _channel_names(channel)
        for spec in specs:
            qualified = spec.rsplit("::", 1)
            if len(qualified) == 2 and len(_channel_names(qualified[0])) != 1:
                raise ValueError("multi-channel qualified MatchSpecs are unsupported")
            package_spec = qualified[-1]
            if (
                not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*", package_spec)
                or "://" in package_spec
                or "$" in package_spec
                or any(c in package_spec for c in "\x00\r\n")
                or len(spec) > 1024
            ):
                raise ValueError(
                    "conda package spec is dynamic or outside the MatchSpec policy"
                )
        return {
            "channels": list(channels),
            "specs": list(specs),
            "platform": "linux-64",
            "channel_priority": raw.get("channel_priority", "flexible"),
            "no_deps": bool(raw.get("no_deps", False)),
        }

    @staticmethod
    def _identity(options: dict[str, object]) -> str:
        return (
            "conda:"
            + hashlib.sha256(json.dumps(options, sort_keys=True).encode()).hexdigest()[
                :16
            ]
        )

    def _resolve(
        self,
        options: dict[str, object],
        *,
        gateway_url: str,
        timeout_seconds: float,
        work_dir: Path,
    ) -> list[dict[str, object]]:
        image = self._resolver_image()
        roots: dict[str, str] = {}
        for value in options["channels"]:
            for name in _channel_names(value, gateway_url):
                route, domestic, _official = _CHANNELS[name]
                roots.setdefault(
                    name,
                    gateway_url.rstrip("/") + "/" + route if gateway_url else domestic,
                )
        specs = []
        for spec in options["specs"]:
            if "::" in spec:
                channel, spec = spec.rsplit("::", 1)
                name = _channel_names(channel, gateway_url)[0]
                route, domestic, _official = _CHANNELS[name]
                root = (
                    gateway_url.rstrip("/") + "/" + route if gateway_url else domestic
                )
                roots.setdefault(name, root)
                spec = root + "::" + spec
            specs.append(spec)
        name = "dg-conda-" + uuid.uuid4().hex
        command = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            name,
            "--network",
            "host",
            "--user",
            "0:0",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--entrypoint",
            "micromamba",
        ]
        for key in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            command.extend(["--env", key + "="])
        command.extend(
            [
                "--env",
                "NO_PROXY=*",
                "--env",
                "no_proxy=*",
                "--env",
                "MAMBA_ROOT_PREFIX=/tmp/dg-root",
                "--env",
                "CONDA_REPODATA_USE_SHARDS=false",
                "--env",
                "MAMBA_REPODATA_USE_SHARDS=false",
                image,
                "create",
                "--no-rc",
                "--dry-run",
                "--json",
                "--prefix",
                "/tmp/dg-solve",
                "--platform",
                "linux-64",
                "--override-channels",
            ]
        )
        for root in roots.values():
            command.extend(["--channel", root])
        priority = options.get("channel_priority")
        if priority == "strict":
            command.append("--strict-channel-priority")
        elif priority == "disabled":
            command.append("--no-channel-priority")
        elif priority != "flexible":
            raise ValueError("unsupported conda channel priority")
        if options.get("no_deps"):
            command.append("--no-deps")
        command.extend(specs)
        print(
            f"conda resolver: {len(specs)} joint specs; container={name}; observe with: docker logs -f {name}",
            file=sys.stderr,
            flush=True,
        )
        output = self.command_runner(command, timeout_seconds, name)
        try:
            document = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError("conda resolver returned invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or document.get("success") is not True
            or not isinstance(document.get("actions"), dict)
        ):
            raise RuntimeError("conda dry-run did not produce a successful transaction")
        records: dict[str, dict[str, object]] = {}
        for phase in ("LINK", "FETCH"):
            values = document["actions"].get(phase, [])
            if not isinstance(values, list):
                raise TypeError("conda transaction has invalid artifact records")
            for record in values:
                if not isinstance(record, dict):
                    raise TypeError("conda transaction has invalid artifact records")
                url = str(record.get("url") or "")
                if not url and record.get("channel") and record.get("fn"):
                    url = str(record["channel"]).rstrip("/") + "/" + str(record["fn"])
                route = _artifact_route(url, gateway_url)
                match = _PACKAGE.fullmatch(route.rsplit("/", 1)[-1])
                if record.get("name") != match.group("name") or str(
                    record.get("version")
                ) != match.group("version"):
                    raise ValueError(
                        "conda artifact filename does not match its package/version record"
                    )
                normalized = {
                    **records.get(route, {}),
                    **record,
                    "url": url,
                    "route": route,
                    "fn": route.rsplit("/", 1)[-1],
                    "build": match.group("build"),
                }
                records[route] = normalized
        if not records:
            raise RuntimeError("conda transaction contains no packages")
        for record in records.values():
            _checksum(record)
        return list(records.values())

    @staticmethod
    def _sample(
        record: dict[str, object], options: dict[str, object], settings: ProbeSettings
    ) -> ProbeResult:
        route = _artifact_route(str(record["url"]))
        url = _domestic_url(route)
        started = time.monotonic()
        common = {
            "requirement": f"{record['name']}={record['version']}={record['build']}",
            "filename": str(record["fn"]),
            "version": str(record["version"]),
            "sha256": str(record.get("sha256") or "") or None,
            "md5": str(record.get("md5") or "") or None,
            "domestic_source": "tuna",
            "domestic_url": url,
            "platform": route.split("/")[-2],
            "resolution_options": options,
        }
        try:
            with build_opener(ProxyHandler({}), _ArtifactRedirects()).open(
                Request(url, headers={"Range": f"bytes=0-{settings.sample_bytes - 1}"}),
                timeout=settings.timeout_seconds,
            ) as response:
                _artifact_route(response.geturl())
                content = response.read(settings.sample_bytes)
            elapsed = max(time.monotonic() - started, 1e-9)
            slow = elapsed >= settings.slow_seconds or (
                len(content) >= settings.sample_bytes
                and len(content) / elapsed
                < settings.sample_bytes / settings.slow_seconds
            )
            return ProbeResult(
                "conda",
                str(record["name"]),
                CondaProvider._identity(options),
                "slow" if slow else "fast",
                "domestic conda artifact sample completed",
                elapsed_seconds=elapsed,
                bytes_sampled=len(content),
                bytes_per_second=len(content) / elapsed,
                **common,
            )
        except (*_NETWORK_ERRORS, ValueError) as exc:
            return ProbeResult(
                "conda",
                str(record["name"]),
                CondaProvider._identity(options),
                "unavailable",
                f"domestic conda artifact request failed: {type(exc).__name__}",
                **common,
            )

    def probe(
        self,
        package_rows: Sequence[dict[str, object]],
        settings: ProbeSettings,
        *,
        work_dir: Path,
    ) -> list[ProbeResult]:
        settings.validate()
        jobs: dict[str, tuple[dict[str, object], list[dict[str, object]]]] = {}
        results = []
        for row in package_rows:
            raw_contexts = row.get("contexts")
            contexts = (
                [item for item in raw_contexts if isinstance(item, dict)]
                if isinstance(raw_contexts, (list, tuple))
                else []
            )
            contexts = contexts or [{}]
            for context in contexts:
                if not isinstance(context, dict):
                    continue
                try:
                    options = self._options(row, context)
                    self._resolver_image()
                except (TypeError, ValueError) as exc:
                    results.append(
                        ProbeResult(
                            "conda",
                            str(row.get("package", "")),
                            None,
                            "unsupported",
                            str(exc),
                            requirement=str(
                                context.get("requirement") or row.get("package", "")
                            ),
                            **_consumer_fields([context]),
                        )
                    )
                    continue
                identity = self._identity(options)
                jobs.setdefault(identity, (options, []))[1].append(context)
        for identity, (options, contexts) in jobs.items():
            consumers = _consumer_fields(contexts)
            try:
                records = self._resolve(
                    options,
                    gateway_url="",
                    timeout_seconds=max(300, settings.timeout_seconds * 20),
                    work_dir=work_dir,
                )
            except (
                subprocess.TimeoutExpired,
                RuntimeError,
                OSError,
                TypeError,
                ValueError,
            ) as exc:
                for spec in options["specs"]:
                    package = re.match(
                        r"^[A-Za-z0-9_][A-Za-z0-9_.-]*", spec.rsplit("::", 1)[-1]
                    ).group()
                    results.append(
                        ProbeResult(
                            "conda",
                            package,
                            identity,
                            "unavailable",
                            f"domestic conda resolver failed: {type(exc).__name__}",
                            requirement=spec,
                            resolution_options=options,
                            **consumers,
                        )
                    )
                continue
            with ThreadPoolExecutor(max_workers=settings.concurrency) as executor:
                samples = executor.map(
                    partial(self._sample, options=options, settings=settings), records
                )
                results.extend(replace(sample, **consumers) for sample in samples)
        return results

    @staticmethod
    def _fetch_to_cache(
        record: dict[str, object], *, gateway_url: str, timeout_seconds: float
    ) -> WarmResult:
        package, requirement = (
            str(record.get("name", "")),
            str(record.get("requirement") or record.get("name", "")),
        )
        common: dict[str, object] = {"requirement": requirement}
        try:
            route = _artifact_route(str(record.get("url") or ""), gateway_url)
            if _PACKAGE.fullmatch(route.rsplit("/", 1)[-1]).group("name") != package:
                raise ValueError("conda artifact does not match the requested package")
            algorithm, expected = _checksum(record)
        except ValueError as exc:
            return WarmResult("conda", package, None, "failed", str(exc), **common)
        url = gateway_url.rstrip("/") + "/" + route
        common["gateway_url"] = url
        digest, size = hashlib.new(algorithm), 0
        opener = build_opener(ProxyHandler({}))
        try:
            with opener.open(
                Request(url, headers={"X-Dependency-Gateway-Prefer-Fallback": "1"}),
                timeout=timeout_seconds,
            ) as response:
                first = response.headers.get("X-Dependency-Gateway", "")
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            common.update(first_cache_state=first, size=size)
            if digest.hexdigest() != expected:
                return WarmResult(
                    "conda",
                    package,
                    None,
                    "failed",
                    "Gateway conda object checksum does not match repodata",
                    **common,
                )
            with opener.open(
                Request(url, method="HEAD"), timeout=timeout_seconds
            ) as response:
                verification = response.headers.get("X-Dependency-Gateway", "")
            common["verification_cache_state"] = verification
            if verification != "HIT":
                return WarmResult(
                    "conda",
                    package,
                    None,
                    "failed",
                    f"Gateway conda verification returned {verification or 'no cache state'}",
                    **common,
                )
            return WarmResult(
                "conda",
                package,
                None,
                "already-cached" if first == "HIT" else "cached",
                "conda artifact cached, checksum-checked and HIT-verified",
                **common,
            )
        except _NETWORK_ERRORS as exc:
            return WarmResult(
                "conda",
                package,
                None,
                "failed",
                f"Gateway conda cache request failed: {type(exc).__name__}",
                **common,
            )

    def warm(
        self,
        rows: Sequence[dict[str, object]],
        *,
        gateway_url: str,
        timeout_seconds: float,
        work_dir: Path,
    ) -> list[WarmResult]:
        results, resolved, warmed = [], {}, {}
        for row in rows:
            consumers = _consumer_fields([row])
            try:
                options = self._options(row, row)
                identity = self._identity(options)
                if row.get("domestic_url") and row.get("filename"):
                    records = [
                        {
                            "name": row["package"],
                            "url": row["domestic_url"],
                            "sha256": row.get("sha256"),
                            "md5": row.get("md5"),
                            "requirement": row.get("requirement") or row["package"],
                        }
                    ]
                else:
                    if identity not in resolved:
                        resolved[identity] = self._resolve(
                            options,
                            gateway_url=gateway_url,
                            timeout_seconds=max(300, timeout_seconds),
                            work_dir=work_dir,
                        )
                    records = resolved[identity]
                for record in records:
                    key = (str(record.get("url")), _checksum(record))
                    if key not in warmed:
                        warmed[key] = self._fetch_to_cache(
                            record,
                            gateway_url=gateway_url,
                            timeout_seconds=timeout_seconds,
                        )
                    result = replace(warmed[key], environment=identity, **consumers)
                    if result not in results:
                        results.append(result)
            except (
                subprocess.TimeoutExpired,
                RuntimeError,
                OSError,
                TypeError,
                ValueError,
            ) as exc:
                results.append(
                    WarmResult(
                        "conda",
                        str(row.get("package", "")),
                        str(row.get("environment") or "") or None,
                        "not-actionable"
                        if isinstance(exc, (TypeError, ValueError))
                        else "failed",
                        f"conda warm preparation failed: {type(exc).__name__}",
                        requirement=str(
                            row.get("requirement") or row.get("package", "")
                        ),
                        **consumers,
                    )
                )
        return results
