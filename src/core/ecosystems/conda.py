"""Conda channel path admission and inventory for colocated repodata/packages."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import EcosystemHandler

if TYPE_CHECKING:
    from ..config.source import SourceConfig


_SUBDIR = re.compile(r"^(?:noarch|(?:linux|osx|win|freebsd)-[A-Za-z0-9_]+)$")
_PACKAGE = re.compile(
    r"^(?P<name>[A-Za-z0-9_][A-Za-z0-9_.-]*)-"
    r"(?P<version>[A-Za-z0-9_.+!]+)-(?P<build>[A-Za-z0-9_.]+)"
    r"\.(?:conda|tar\.bz2)$"
)
_REPODATA = frozenset(
    f"{stem}{suffix}"
    for stem in ("repodata.json", "current_repodata.json")
    for suffix in ("", ".bz2", ".zst")
) | {"repodata.jlap"}
_CHANNEL_METADATA = frozenset({"channeldata.json", "notices.json"})


def is_conda_metadata(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in _REPODATA | _CHANNEL_METADATA


def _validate_path(source: SourceConfig, decoded: str) -> str | None:
    parts = decoded.split("/")
    filename = parts[-1]
    if filename in _CHANNEL_METADATA:
        return None
    if (
        len(parts) >= 2
        and _SUBDIR.fullmatch(parts[-2])
        and (filename in _REPODATA or _PACKAGE.fullmatch(filename))
    ):
        return None
    return "upstream path does not match the conda channel protocol allowlist"


def _inventory_fields(
    source: SourceConfig, decoded_path: str, filename: str, content_type: str
) -> dict[str, str | None]:
    match = _PACKAGE.fullmatch(filename)
    if match:
        return {
            "package": match.group("name"),
            "version": match.group("version"),
            "platform_tag": decoded_path.split("/")[-2].replace("-", "_"),
            "object_type": "artifact",
        }
    return {
        "package": "@metadata",
        "version": decoded_path.rsplit("/", 1)[0],
        "object_type": "metadata",
    }


HANDLER = EcosystemHandler(
    name="conda",
    kinds=("conda-channel",),
    ecosystems=("conda",),
    validate_path=_validate_path,
    inventory_fields=_inventory_fields,
)
