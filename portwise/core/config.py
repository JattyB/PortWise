from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when a PortWise configuration is invalid."""


@dataclass(slots=True)
class Profile:
    name: str
    context: str
    nmap_steps: list[str]
    modules: dict[str, bool]
    reports: list[str]
    raw: dict[str, Any]


@dataclass(slots=True)
class PortWiseConfig:
    path: Path
    project: dict[str, Any]
    scanner: dict[str, Any]
    profiles: dict[str, Profile]
    raw: dict[str, Any]

    def get_profile(self, name: str) -> Profile:
        try:
            return self.profiles[name]
        except KeyError as exc:
            available = ", ".join(sorted(self.profiles))
            raise ConfigError(f"Unknown profile '{name}'. Available profiles: {available}") from exc


def load_config(path: Path | str) -> PortWiseConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    profiles_data = data.get("profiles")
    if not isinstance(profiles_data, dict) or not profiles_data:
        raise ConfigError("Configuration must define at least one profile.")

    profiles: dict[str, Profile] = {}
    for name, raw in profiles_data.items():
        if not isinstance(raw, dict):
            raise ConfigError(f"Profile '{name}' must be a mapping.")
        profiles[name] = Profile(
            name=name,
            context=str(raw.get("context", data.get("project", {}).get("context", "unknown"))),
            nmap_steps=list(raw.get("nmap_steps", [])),
            modules=dict(raw.get("modules", {})),
            reports=list(raw.get("reports", ["json"])),
            raw=raw,
        )

    return PortWiseConfig(
        path=config_path,
        project=dict(data.get("project", {})),
        scanner=dict(data.get("scanner", {})),
        profiles=profiles,
        raw=data,
    )
