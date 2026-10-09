"""Static conda command/spec-file context; deliberately bounded YAML support."""

from __future__ import annotations

import ast
import json
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .dockerfile import docker_instructions, from_stage
from .external import sanitize_public_url

if TYPE_CHECKING:
    from .models import BuildContext, Install


def _public_channel(value: str) -> str:
    if "$" in value or "/t/" in value:
        return "<dynamic-or-redacted>"
    if "://" not in value:
        return value
    sanitized = sanitize_public_url(value)
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<dynamic-or-redacted>"
    if (
        sanitized is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return "<dynamic-or-redacted>"
    return sanitized[0]


def _public_spec(value: str) -> str:
    if "::" in value:
        channel, spec = value.rsplit("::", 1)
        return _public_channel(channel) + "::" + spec
    if "://" in value or "$" in value:
        return "<dynamic-or-redacted>"
    return value


def conda_arguments(install: Install) -> tuple[list[str], list[str], dict[str, object]]:
    specs, files, channels = [], [], []
    options: dict[str, object] = {
        "client": install.command.split()[0],
        "operation": install.command.split()[-1],
    }
    args = list(install.arguments)
    valued = {
        "-c": "channel",
        "--channel": "channel",
        "-f": "file",
        "--file": "file",
        "--platform": "platform",
        "--subdir": "platform",
        "-n": "target",
        "--name": "target",
        "-p": "target",
        "--prefix": "target",
    }
    ignored = {
        "-y",
        "--yes",
        "-q",
        "--quiet",
        "-v",
        "-vv",
        "-vvv",
        "--dry-run",
        "--json",
    }
    flags = {
        "--override-channels": ("override_channels", True),
        "--strict-channel-priority": ("channel_priority", "strict"),
        "--no-channel-priority": ("channel_priority", "disabled"),
        "--no-deps": ("no_deps", True),
    }
    index = 0
    while index < len(args):
        token = args[index]
        option, separator, inline = token.partition("=")
        if (
            not separator
            and token.startswith(("-c", "-n", "-p", "-f"))
            and not token.startswith("--")
            and len(token) > 2
        ):
            option, inline, separator = token[:2], token[2:], "="
        if option in valued:
            if not separator:
                index += 1
                inline = args[index] if index < len(args) else ""
            key = valued[option]
            if not inline:
                options["unsupported_reason"] = "conda option is missing its value"
            elif key == "channel":
                channels.append(_public_channel(inline))
            elif key == "file":
                files.append(inline)
            elif key != "target":
                options[key] = inline if "$" not in inline else "<dynamic-or-redacted>"
        elif token in flags:
            key, value = flags[token]
            options[key] = value
        elif token in ignored:
            pass
        elif token.startswith("-"):
            options["unsupported_reason"] = (
                "conda command has an unsupported resolution option"
            )
        else:
            specs.append(_public_spec(token))
        index += 1
    if channels:
        options["channels"] = channels
    return specs, files, options


def _scalar(value: str) -> str:
    value = value.strip()
    if value.startswith(("'", '"')):
        decoded = ast.literal_eval(value)
        if not isinstance(decoded, str):
            raise ValueError("expected a scalar string")
        return decoded
    return value.split(" #", 1)[0].strip()


def conda_manifest(text: str, *, yaml: bool) -> tuple[list[str], list[str], list[str]]:
    """Read JSON or ordinary block-list environment YAML and plain MatchSpec files.

    Complex YAML/locks are rejected, rather than partially parsed or executed.
    """
    if not yaml:
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if any(line.startswith(("@", "-")) or "://" in line for line in lines):
            raise ValueError(
                "explicit conda locks or option-bearing spec files are unsupported"
            )
        return [_public_spec(line) for line in lines], [], []
    if text.lstrip().startswith("{"):
        doc = json.loads(text)
        if not isinstance(doc, dict) or set(doc) - {
            "name",
            "prefix",
            "channels",
            "dependencies",
        }:
            raise ValueError("unsupported environment document")
        channels, dependencies = doc.get("channels", []), doc.get("dependencies", [])
        if (
            not isinstance(channels, list)
            or not all(isinstance(item, str) for item in channels)
            or not isinstance(dependencies, list)
        ):
            raise ValueError("invalid environment lists")
        specs, pip = [], []
        for item in dependencies:
            if isinstance(item, str):
                specs.append(_public_spec(item))
            elif (
                isinstance(item, dict)
                and set(item) == {"pip"}
                and isinstance(item["pip"], list)
                and all(isinstance(value, str) for value in item["pip"])
            ):
                pip.extend(_public_spec(value) for value in item["pip"])
            else:
                raise ValueError("unsupported environment dependency")
        return specs, [_public_channel(item) for item in channels], pip
    specs, channels, pip = [], [], []
    section = ""
    pip_indent = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise ValueError("tab-indented environment YAML is unsupported")
        indent, line = len(raw) - len(raw.lstrip()), raw.strip()
        if indent == 0:
            pip_indent = None
            key, separator, value = line.partition(":")
            if not separator or key not in {
                "name",
                "prefix",
                "channels",
                "dependencies",
            }:
                raise ValueError("unsupported environment YAML key")
            section = key
            if section in {"channels", "dependencies"} and value.strip() not in {
                "",
                "[]",
            }:
                raise ValueError("environment YAML requires block lists")
            continue
        if section not in {"channels", "dependencies"} or not line.startswith("- "):
            raise ValueError("unsupported environment YAML structure")
        value = line[2:].strip()
        if section == "dependencies" and value == "pip:":
            if pip_indent is not None:
                raise ValueError("nested pip environment entries are unsupported")
            pip_indent = indent
            continue
        if pip_indent is not None and indent > pip_indent:
            pip.append(_public_spec(_scalar(value)))
            continue
        pip_indent = None
        value = _scalar(value)
        if (
            not value
            or value.startswith(("&", "*", "!", "{", "["))
            or value.endswith(":")
        ):
            raise ValueError("complex environment YAML is unsupported")
        (channels if section == "channels" else specs).append(
            _public_channel(value) if section == "channels" else _public_spec(value)
        )
    return specs, channels, pip


def _stage_settings(
    environment: Path, source: Path, text: str, context: BuildContext | None
) -> dict[str, object]:
    if context is None:
        return {}
    dockerfile = environment.parent / context.dockerfile
    if not dockerfile.is_file() or not dockerfile.resolve().is_relative_to(
        environment.resolve()
    ):
        return {}
    stage, state, aliases, matches = -1, {}, {}, []
    alias = None
    changed = False
    for instruction, body in docker_instructions(
        dockerfile.read_text(encoding="utf-8", errors="replace")
    ):
        if instruction == "FROM":
            if alias:
                aliases[alias.lower()] = dict(state)
            image, alias, _platform = from_stage(body)
            state = dict(aliases.get((image or "").lower(), {}))
            changed = bool(state)
            stage += 1
        if stage > context.stage_index:
            break
        if instruction == "ENV":
            try:
                values = shlex.split(body)
            except ValueError:
                values = []
            if values and "=" not in values[0]:
                values = [values[0] + "=" + " ".join(values[1:])]
            for value in values:
                key, _, setting = value.partition("=")
                if key == "CONDA_SUBDIR":
                    changed = True
                    state["platform"] = (
                        setting
                        if re.fullmatch(r"[a-z0-9-]+", setting)
                        else "<dynamic-or-redacted>"
                    )
                elif key.startswith("CONDA_OVERRIDE_"):
                    changed = True
                    state["unsupported_reason"] = (
                        "task-specific conda virtual-package overrides are not reconstructed"
                    )
        if instruction == "RUN":
            if re.search(r"\b(?:conda|mamba|micromamba)\s+config\b", body):
                changed = True
                state["unsupported_reason"] = (
                    "task-local conda rc configuration is not reconstructed"
                )
            if stage == context.stage_index and (
                (source == dockerfile and body == text)
                or (source != dockerfile and source.name in body)
            ):
                matches.append(dict(state))
    if matches and all(value == matches[0] for value in matches):
        return matches[0]
    if changed:
        return {
            "unsupported_reason": "conda stage environment cannot be bound unambiguously to this command"
        }
    return {}


def conda_install_context(
    install: Install,
    *,
    environment: Path,
    source: Path,
    text: str,
    tokens: list[str],
    context: BuildContext | None,
) -> tuple[list[str], dict[str, object], list[str]]:
    specs, files, options = conda_arguments(install)
    for token in tokens:
        if token.startswith("CONDA_SUBDIR="):
            value = token.partition("=")[2]
            options.setdefault(
                "platform",
                value
                if re.fullmatch(r"[a-z0-9-]+", value)
                else "<dynamic-or-redacted>",
            )
    inherited = _stage_settings(environment, source, text, context)
    for key, value in inherited.items():
        options.setdefault(key, value)
    pip_specs: list[str] = []
    file_channels: list[str] = []
    for requested in files:
        if "$" in requested:
            options["unsupported_reason"] = "conda environment file path is dynamic"
            continue
        candidates = {
            path.resolve()
            for path in (source.parent / requested, environment / requested)
            if path.is_file() and path.resolve().is_relative_to(environment.resolve())
        }
        if not candidates:
            candidates = {
                path.resolve()
                for path in environment.rglob(Path(requested).name)
                if path.is_file()
                and path.resolve().is_relative_to(environment.resolve())
            }
        if len(candidates) != 1:
            options["unsupported_reason"] = (
                "conda environment file is missing or ambiguous"
            )
            continue
        path = candidates.pop()
        try:
            values, channels, pip = conda_manifest(
                path.read_text(encoding="utf-8"),
                yaml=path.suffix.lower() in {".yaml", ".yml", ".json"},
            )
            specs.extend(values)
            file_channels.extend(channels)
            pip_specs.extend(pip)
        except (ValueError, SyntaxError, OSError):
            options["unsupported_reason"] = (
                "conda environment file format is unsupported"
            )
    if pip_specs and not any(
        re.match(r"^pip(?:\s|[=<>!\[]|$)", spec) for spec in specs
    ):
        specs.append("pip")
    channels = list(options.get("channels", [])) + file_channels
    if "nodefaults" in channels:
        channels = [channel for channel in channels if channel != "nodefaults"]
        options["override_channels"] = True
    base_image = context.base_image if context else ""
    if not options.get("override_channels"):
        if "miniforge" in base_image.lower() or "mambaforge" in base_image.lower():
            channels.append("conda-forge")
        elif options["client"] == "micromamba":
            if not channels:
                options["unsupported_reason"] = "micromamba has no declared channel"
        else:
            channels.append("defaults")
    options["channels"] = list(dict.fromkeys(channels))
    options.setdefault(
        "platform",
        {
            None: "linux-64",
            "linux/amd64": "linux-64",
            "linux/arm64": "linux-aarch64",
        }.get(context.platform if context else None, "<unsupported>"),
    )
    if (
        re.search(r"\b(?:conda|mamba|micromamba)\s+config\b", text)
        or any(environment.rglob(".condarc"))
        or any(environment.rglob(".mambarc"))
    ):
        options["unsupported_reason"] = (
            "task-local conda rc configuration is not reconstructed"
        )
    if not specs:
        options["unsupported_reason"] = options.get(
            "unsupported_reason", "conda command declares no static package specs"
        )
        specs = ["__conda_unresolved_environment__"]
    if not any(re.match(r"^[A-Za-z0-9_]", spec.rsplit("::", 1)[-1]) for spec in specs):
        options["unsupported_reason"] = "conda command has no resolvable static specs"
        specs.append("__conda_unresolved_environment__")
    options["specs"] = specs
    return specs, options, pip_specs
