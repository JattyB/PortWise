from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when a PortWise configuration is invalid."""


VALID_DEPTHS = ("recon", "full")
KNOWN_NMAP_STEPS = (
    "discovery",
    "tcp_top_1000",
    "tcp_full",
    "tcp_services",
    "udp_top_1000",
    "udp_services",
)
KNOWN_REPORT_FORMATS = ("json", "excel", "html", "pentest", "csv")


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
        try:
            data = yaml.safe_load(handle) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Could not parse YAML in {config_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"Top-level configuration in {config_path} must be a mapping (key: value).")

    _validate_section_type(data, "project", dict)
    _validate_section_type(data, "scanner", dict)
    _validate_scanner(data.get("scanner", {}))

    profiles_data = data.get("profiles")
    if not isinstance(profiles_data, dict) or not profiles_data:
        raise ConfigError("Configuration must define at least one profile under 'profiles:'.")

    profiles: dict[str, Profile] = {}
    for name, raw in profiles_data.items():
        if not isinstance(raw, dict):
            raise ConfigError(f"Profile '{name}' must be a mapping of settings.")
        _validate_profile(name, raw)
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


def _validate_section_type(data: dict[str, Any], key: str, expected: type) -> None:
    if key in data and not isinstance(data[key], expected):
        type_name = "a mapping" if expected is dict else f"a {expected.__name__}"
        raise ConfigError(f"Configuration section '{key}:' must be {type_name}.")


def _validate_scanner(scanner: dict[str, Any]) -> None:
    if not isinstance(scanner, dict):
        return
    depth = scanner.get("validation_level")
    if depth is not None and str(depth) not in VALID_DEPTHS:
        raise ConfigError(
            f"scanner.validation_level '{depth}' is invalid. "
            f"Use one of: {', '.join(VALID_DEPTHS)}."
        )


def _validate_profile(name: str, raw: dict[str, Any]) -> None:
    depth = raw.get("validation_level")
    if depth is not None and str(depth) not in VALID_DEPTHS:
        raise ConfigError(
            f"Profile '{name}': validation_level '{depth}' is invalid. "
            f"Use one of: {', '.join(VALID_DEPTHS)}."
        )

    steps = raw.get("nmap_steps", [])
    if steps is not None and not isinstance(steps, list):
        raise ConfigError(f"Profile '{name}': nmap_steps must be a list of step names.")
    for step in steps or []:
        if str(step) not in KNOWN_NMAP_STEPS:
            raise ConfigError(
                f"Profile '{name}': unknown nmap step '{step}'. "
                f"Known steps: {', '.join(KNOWN_NMAP_STEPS)}."
            )

    modules = raw.get("modules", {})
    if modules is not None and not isinstance(modules, dict):
        raise ConfigError(f"Profile '{name}': modules must be a mapping of name: true/false.")

    reports = raw.get("reports", [])
    if reports is not None and not isinstance(reports, list):
        raise ConfigError(f"Profile '{name}': reports must be a list of formats.")
    for fmt in reports or []:
        if str(fmt) not in KNOWN_REPORT_FORMATS:
            raise ConfigError(
                f"Profile '{name}': unknown report format '{fmt}'. "
                f"Known formats: {', '.join(KNOWN_REPORT_FORMATS)}."
            )
