"""Conda analysis -> dry-run resolution -> checksum/HIT-verified warm-up."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import test_conda_gateway as gateway_fixture
from dependency_gateway.harbor_tasks.analyzer import (
    analyze,
    identify_install,
    normalize_package,
)
from dependency_gateway.harbor_tasks.analyzer.conda import conda_manifest
from dependency_gateway.harbor_tasks.preparer.models import (
    ProbeResult,
    ProbeSettings,
    WarmResult,
)
from dependency_gateway.harbor_tasks.preparer.orchestrator import (
    _providers,
    probe_packages,
    warm_packages,
)
from dependency_gateway.harbor_tasks.preparer.providers.conda import (
    CondaProvider,
    _artifact_route,
)
from dependency_gateway.harbor_tasks.preparer.report import write_probe_report

IMAGE_ENV = {
    "DEPENDENCY_GATEWAY_CONDA_RESOLVER_IMAGE": "registry.example/public-mirror/micromamba:2.0.5"
}
OPTIONS = {
    "channels": ["conda-forge"],
    "specs": ["six=1.16.0", "python=3.12"],
    "platform": "linux-64",
    "channel_priority": "flexible",
    "no_deps": False,
}


def record(
    package: str = "six",
    version: str = "1.16.0",
    build: str = "pyhd8ed1ab_1",
    *,
    url_root: str = "https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge",
    body: bytes = b"conda package fixture",
) -> dict[str, object]:
    filename = f"{package}-{version}-{build}.tar.bz2"
    return {
        "name": package,
        "version": version,
        "build": build,
        "fn": filename,
        "url": f"{url_root}/noarch/{filename}",
        "sha256": hashlib.sha256(body).hexdigest(),
        "md5": hashlib.md5(body).hexdigest(),
    }


class CondaAnalyzerTest(unittest.TestCase):
    def dataset(self, dockerfile: str, files: dict[str, str] | None = None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        dataset = Path(temporary.name)
        environment = dataset / "task" / "environment"
        environment.mkdir(parents=True)
        (environment.parent / "task.toml").write_text("")
        (environment / "Dockerfile").write_text(dockerfile)
        for path, body in (files or {}).items():
            (environment / path).write_text(body)
        return analyze(dataset, "referenced")

    def test_create_install_and_env_create_recognition(self):
        for command in (
            ["conda", "create", "-n", "test", "python=3.12"],
            ["/opt/conda/bin/mamba", "install", "numpy"],
            ["micromamba", "env", "create", "-f", "env.yml"],
        ):
            self.assertEqual(identify_install(command).manager, "conda")
        self.assertEqual(
            normalize_package("conda", "conda-forge::lib-zlib=1.3.1=h123_0"), "lib-zlib"
        )
        self.assertEqual(normalize_package("conda", "numpy >=1.2,<2"), "numpy")

    def test_joint_specs_channel_order_platform_and_build_pins(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nRUN conda create -n env -cconda-forge --channel=https://repo.anaconda.com/pkgs/main --override-channels --platform=linux-64 --strict-channel-priority 'numpy>=1.2,<2' python=3.12=h123_0\n"
        )
        self.assertEqual(
            {row["package"] for row in result["packages"]}, {"numpy", "python"}
        )
        contexts = [row["contexts"][0] for row in result["packages"]]
        self.assertEqual(contexts[0]["environment_id"], contexts[1]["environment_id"])
        options = contexts[0]["resolution_options"]
        self.assertEqual(
            options["channels"], ["conda-forge", "https://repo.anaconda.com/pkgs/main"]
        )
        self.assertEqual(options["specs"], ["numpy>=1.2,<2", "python=3.12=h123_0"])
        self.assertEqual(options["channel_priority"], "strict")
        self.assertEqual(options["platform"], "linux-64")

    def test_yaml_environment_and_pip_dependencies(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nCOPY env.yml /env.yml\nRUN conda env create -f /env.yml\n",
            {
                "env.yml": "name: example\nchannels:\n  - conda-forge\n  - nodefaults\ndependencies:\n  - python=3.12\n  - numpy >=1.2,<2\n  - pip:\n      - requests==2.31.0\n",
            },
        )
        rows = {(row["manager"], row["package"]): row for row in result["packages"]}
        self.assertIn(("pip", "requests"), rows)
        self.assertIn(("conda", "pip"), rows)
        options = rows[("conda", "numpy")]["contexts"][0]["resolution_options"]
        self.assertEqual(options["channels"], ["conda-forge"])
        self.assertEqual(options["specs"], ["python=3.12", "numpy >=1.2,<2", "pip"])

    def test_plain_spec_file_and_inline_subdir(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nRUN CONDA_SUBDIR=linux-aarch64 conda create -f specs.txt\n",
            {"specs.txt": "# comment\npython=3.12\nsix 1.16.*\n"},
        )
        row = next(row for row in result["packages"] if row["package"] == "six")
        options = row["contexts"][0]["resolution_options"]
        self.assertEqual(options["platform"], "linux-aarch64")
        self.assertEqual(options["channels"], ["defaults"])

    def test_missing_complex_explicit_and_dynamic_specs_remain_visible(self):
        for file in (
            None,
            "channels: [conda-forge]\ndependencies: [numpy]\n",
            "@EXPLICIT\nhttps://private.example/a.conda\n",
        ):
            with self.subTest(file=file):
                result = self.dataset(
                    "FROM ubuntu:22.04\nRUN conda env create -f env.yml\n",
                    {"env.yml": file} if file else {},
                )
                self.assertEqual(len(result["packages"]), 1)
                self.assertIn(
                    "unsupported_reason",
                    result["packages"][0]["contexts"][0]["resolution_options"],
                )
        result = self.dataset("FROM ubuntu:22.04\nRUN conda create $PACKAGES\n")
        self.assertEqual(len(result["packages"]), 1)

    def test_private_channel_credentials_are_not_in_analysis(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nRUN conda install -c https://user:fake-sensitive-value@private.example/channel --override-channels numpy\n"
        )
        self.assertNotIn("fake-sensitive-value", json.dumps(result))
        row = result["packages"][0]
        self.assertEqual(
            row["contexts"][0]["resolution_options"]["channels"],
            ["<dynamic-or-redacted>"],
        )

    def test_environment_identity_distinguishes_channel_priority_and_joint_specs(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nRUN conda create -c conda-forge --override-channels python=3.11 numpy=1.26\nRUN conda create -c conda-forge --override-channels python=3.12 numpy=1.26\n"
        )
        numpy = next(row for row in result["packages"] if row["package"] == "numpy")
        self.assertEqual(len(numpy["contexts"]), 2)
        self.assertEqual(
            len({context["environment_id"] for context in numpy["contexts"]}), 2
        )

    def test_rc_configuration_and_unsupported_yaml_are_explicit(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nRUN conda install numpy\n",
            {".condarc": "channels:\n  - private\n"},
        )
        self.assertIn(
            "unsupported_reason",
            result["packages"][0]["contexts"][0]["resolution_options"],
        )
        for text in (
            "dependencies:\n  - &anchor numpy\n",
            "dependencies:\n  - pip:\n      nested: value\n",
        ):
            with self.assertRaises(ValueError):
                conda_manifest(text, yaml=True)

    def test_stage_subdir_and_inline_override_are_bound_in_order(self):
        result = self.dataset(
            "FROM ubuntu:22.04 AS base\nENV CONDA_SUBDIR=linux-aarch64\nRUN conda create numpy\nFROM base\nRUN CONDA_SUBDIR=linux-64 conda create --platform=linux-64 scipy\n"
        )
        rows = {row["package"]: row for row in result["packages"]}
        self.assertEqual(
            rows["numpy"]["contexts"][0]["resolution_options"]["platform"],
            "linux-aarch64",
        )
        self.assertEqual(
            rows["scipy"]["contexts"][0]["resolution_options"]["platform"], "linux-64"
        )
        result = self.dataset(
            "FROM ubuntu:22.04\nENV CONDA_SUBDIR=linux-aarch64\nRUN CONDA_SUBDIR=linux-64 conda create numpy\n"
        )
        self.assertEqual(
            result["packages"][0]["contexts"][0]["resolution_options"]["platform"],
            "linux-64",
        )

    def test_prior_run_rc_changes_are_not_silently_lost(self):
        result = self.dataset(
            "FROM ubuntu:22.04\nRUN conda config --add channels private\nRUN conda install numpy\n"
        )
        self.assertIn(
            "unsupported_reason",
            result["packages"][0]["contexts"][0]["resolution_options"],
        )


class CondaResolverTest(unittest.TestCase):
    def test_registered_provider_and_missing_image_are_explicit(self):
        self.assertIsInstance(_providers()["conda"], CondaProvider)
        runner = Mock()
        with (
            patch.dict("os.environ", {}, clear=True),
            tempfile.TemporaryDirectory() as directory,
        ):
            results = CondaProvider(runner).probe(
                [{"package": "six", "contexts": [{"resolution_options": OPTIONS}]}],
                ProbeSettings(),
                work_dir=Path(directory),
            )
        self.assertEqual(results[0].status, "unsupported")
        runner.assert_not_called()

    def test_real_solver_command_preserves_transport_order_and_qualified_specs(self):
        data = record()
        runner = Mock(
            return_value=json.dumps(
                {"success": True, "actions": {"FETCH": [data], "LINK": [data]}}
            )
        )
        options = {
            **OPTIONS,
            "channels": ["defaults", "conda-forge"],
            "specs": ["conda-forge::six=1.16.0", "python=3.12"],
            "channel_priority": "strict",
        }
        with (
            patch.dict("os.environ", IMAGE_ENV),
            tempfile.TemporaryDirectory() as directory,
        ):
            records = CondaProvider(runner)._resolve(
                options,
                gateway_url="http://gateway.example/v1/cache",
                timeout_seconds=10,
                work_dir=Path(directory),
            )
        self.assertEqual(len(records), 1)
        command = runner.call_args.args[0]
        self.assertIn("--dry-run", command)
        self.assertIn("--no-rc", command)
        self.assertIn("--strict-channel-priority", command)
        self.assertIn("never", command)
        roots = [
            command[i + 1] for i, value in enumerate(command) if value == "--channel"
        ]
        self.assertEqual(
            roots,
            [
                "http://gateway.example/v1/cache/conda-defaults/main",
                "http://gateway.example/v1/cache/conda-defaults/r",
                "http://gateway.example/v1/cache/conda-channels/conda-forge",
            ],
        )
        self.assertIn(
            "http://gateway.example/v1/cache/conda-channels/conda-forge::six=1.16.0",
            command,
        )
        self.assertIn("HTTP_PROXY=", command)
        self.assertIn("https_proxy=", command)
        self.assertIn("--read-only", command)

    def test_rejects_untrusted_records_missing_hashes_and_mismatched_filenames(self):
        bad_records = [
            record(url_root="https://untrusted.example/conda-forge"),
            {**record(), "sha256": "", "md5": ""},
            {**record(), "name": "wrong"},
        ]
        for data in bad_records:
            runner = Mock(
                return_value=json.dumps({"success": True, "actions": {"FETCH": [data]}})
            )
            with (
                self.subTest(data=data),
                patch.dict("os.environ", IMAGE_ENV),
                self.assertRaises(ValueError),
            ):
                CondaProvider(runner)._resolve(
                    OPTIONS, gateway_url="", timeout_seconds=10, work_dir=Path("/tmp")
                )

    def test_probe_resolves_joint_specs_once_and_includes_transitive_dependencies(self):
        rows = [
            {
                "manager": "conda",
                "package": package,
                "contexts": [
                    {
                        "requirement": package,
                        "resolution_options": OPTIONS,
                        "environment_id": "env-original",
                        "build_contexts": ["ctx-a"],
                    }
                ],
            }
            for package in ("six", "python")
        ]
        provider = CondaProvider()

        def sample(data, options, settings):
            return ProbeResult(
                "conda",
                data["name"],
                provider._identity(options),
                "slow",
                "test sample",
                resolution_options=options,
            )

        with (
            patch.dict("os.environ", IMAGE_ENV),
            patch.object(
                provider,
                "_resolve",
                return_value=[record(), record("lib-zlib", "1.3", "h123_0")],
            ) as resolve,
            patch.object(provider, "_sample", side_effect=sample),
            tempfile.TemporaryDirectory() as directory,
        ):
            report = probe_packages(
                {"packages": rows},
                settings=ProbeSettings(),
                work_dir=Path(directory),
                providers=[provider],
            )
        resolve.assert_called_once()
        self.assertEqual(
            {row["package"] for row in report["results"]}, {"six", "lib-zlib"}
        )
        self.assertEqual(report["summary"]["unsupported_results"], 0)
        self.assertEqual(
            report["results"][0]["consumer_environment_ids"], ("env-original",)
        )
        self.assertEqual(report["results"][0]["build_contexts"], ("ctx-a",))

    def test_unsupported_platform_channel_and_spec_never_run_solver(self):
        for options in (
            {**OPTIONS, "platform": "linux-aarch64"},
            {**OPTIONS, "channels": ["private"]},
            {**OPTIONS, "specs": ["$PACKAGE"]},
            {**OPTIONS, "specs": ["defaults::six"]},
        ):
            runner = Mock()
            with (
                patch.dict("os.environ", IMAGE_ENV),
                tempfile.TemporaryDirectory() as directory,
            ):
                result = CondaProvider(runner).probe(
                    [{"package": "six", "contexts": [{"resolution_options": options}]}],
                    ProbeSettings(),
                    work_dir=Path(directory),
                )
            self.assertEqual(result[0].status, "unsupported")
            runner.assert_not_called()

    def test_timeout_is_unavailable_and_preserves_spec_set_for_warm(self):
        provider = CondaProvider()
        with (
            patch.dict("os.environ", IMAGE_ENV),
            patch.object(
                provider,
                "_resolve",
                side_effect=subprocess.TimeoutExpired("micromamba", 1),
            ),
            tempfile.TemporaryDirectory() as directory,
        ):
            results = provider.probe(
                [{"package": "six", "contexts": [{"resolution_options": OPTIONS}]}],
                ProbeSettings(),
                work_dir=Path(directory),
            )
        self.assertEqual({row.package for row in results}, {"six", "python"})
        self.assertTrue(
            all(
                row.status == "unavailable" and row.resolution_options == OPTIONS
                for row in results
            )
        )

    def test_warm_unresolved_group_uses_gateway_and_warms_all_dependencies_once(self):
        provider = CondaProvider()
        rows = [
            {
                "manager": "conda",
                "package": package,
                "resolution_options": OPTIONS,
                "consumer_environment_ids": ["env-a", "env-b"],
                "build_contexts": ["ctx-a"],
            }
            for package in ("six", "python")
        ]
        records = [record(), record("lib-zlib", "1.3", "h123_0")]

        def fetch(data, **kwargs):
            return WarmResult("conda", data["name"], None, "cached", "verified")

        with (
            patch.object(provider, "_resolve", return_value=records) as resolve,
            patch.object(provider, "_fetch_to_cache", side_effect=fetch) as fetch_mock,
            tempfile.TemporaryDirectory() as directory,
        ):
            report = warm_packages(
                {"problems": rows},
                gateway_url="http://gateway.example/v1/cache",
                timeout_seconds=10,
                work_dir=Path(directory),
                providers=[provider],
            )
        resolve.assert_called_once()
        self.assertEqual(
            resolve.call_args.kwargs["gateway_url"], "http://gateway.example/v1/cache"
        )
        self.assertEqual(fetch_mock.call_count, 2)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(
            report["results"][0]["consumer_environment_ids"], ("env-a", "env-b")
        )

    def test_probe_report_json_and_csv_preserve_resolution_options_and_md5(self):
        rows = [
            ProbeResult(
                "conda",
                "six",
                "conda:test",
                "slow",
                "fixture",
                md5="a" * 32,
                resolution_options=OPTIONS,
            ).to_dict(),
            ProbeResult("pip", "requests", "pip:test", "fast", "fixture").to_dict(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_probe_report(root, {"results": rows, "summary": {}})
            loaded = json.loads((root / "package-probe-report.json").read_text())
            self.assertEqual(loaded["results"][0]["resolution_options"], OPTIONS)
            self.assertIn("md5", (root / "package-probe-report.csv").read_text())


class CondaWarmIntegrationTest(unittest.TestCase):
    # Reuse only fixture methods, without inheriting/duplicating gateway test cases.
    index_path = gateway_fixture.CondaGatewayTest.index_path
    package_path = gateway_fixture.CondaGatewayTest.package_path
    setUp = gateway_fixture.CondaGatewayTest.setUp
    start_server = gateway_fixture.CondaGatewayTest.start_server

    def test_analyzed_probe_record_warms_exact_package_and_verifies_hit(self):
        row = {
            "package": "six",
            "requirement": "six=1.16.0=pyhd8ed1ab_1",
            "filename": "six-1.16.0-pyhd8ed1ab_1.tar.bz2",
            "version": "1.16.0",
            "domestic_url": record()["url"],
            "sha256": hashlib.sha256(self.package).hexdigest(),
            "resolution_options": OPTIONS,
            "environment_id": "env-a",
            "build_contexts": ["ctx-a"],
        }
        provider = CondaProvider(
            Mock(side_effect=AssertionError("pinned artifacts must not be re-resolved"))
        )
        for expected in ("cached", "already-cached"):
            results = provider.warm(
                [row],
                gateway_url=self.origin + "/v1/cache",
                timeout_seconds=2,
                work_dir=Path(self.temp.name),
            )
            self.assertEqual(results[0].status, expected)
            self.assertEqual(results[0].verification_cache_state, "HIT")
            self.assertEqual(results[0].size, len(self.package))
            self.assertEqual(results[0].environment_id, "env-a")

    def test_checksum_mismatch_and_bypass_do_not_count_as_warmed(self):
        data = record()
        cache = self.origin + "/v1/cache"
        result = CondaProvider._fetch_to_cache(
            {**data, "sha256": "0" * 64}, gateway_url=cache, timeout_seconds=2
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("checksum", result.reason)
        self.engine.cache_mode = "proxy-only"
        other = record("python", "3.12.0", "h123_0", body=b"binary conda fixture")
        other["url"] = (
            "https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge/linux-64/python-3.12.0-h123_0.conda"
        )
        result = CondaProvider._fetch_to_cache(
            other, gateway_url=cache, timeout_seconds=2
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.verification_cache_state, "BYPASS")

    def test_md5_only_package_and_route_rejections(self):
        data = record()
        del data["sha256"]
        result = CondaProvider._fetch_to_cache(
            data, gateway_url=self.origin + "/v1/cache", timeout_seconds=2
        )
        self.assertEqual(result.status, "cached")
        for url in (
            str(record()["url"]) + "?token=fake",
            "https://private.example/a.conda",
            "https://conda.anaconda.org/bioconda/noarch/six-1.16.0-py_0.conda",
        ):
            with self.assertRaises(ValueError):
                _artifact_route(url)


if __name__ == "__main__":
    unittest.main()
