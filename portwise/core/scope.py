"""Hard scope boundary for supplied and discovered targets."""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from portwise.core.config import ConfigError


@dataclass(slots=True)
class ScopePolicy:
    allow: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    override: bool = False

    def permits(self, value: str) -> bool:
        if self.override:
            return True
        host = (urlsplit(value).hostname or value).strip().lower().rstrip(".")
        if any(_matches(host, rule) for rule in self.exclude):
            return False
        return bool(self.allow) and any(_matches(host, rule) for rule in self.allow)

    def require(self, values: list[str]) -> None:
        denied = [value for value in values if not self.permits(value)]
        if denied:
            raise ConfigError("Refusing out-of-scope target(s): " + ", ".join(denied))


def policy_from_config(config: dict) -> ScopePolicy:
    raw = config.get("scope", {}) if isinstance(config.get("scope"), dict) else {}
    return ScopePolicy(
        allow=_rules(raw.get("allow", []), raw.get("allow_file")),
        exclude=_rules(raw.get("exclude", []), raw.get("exclude_file")),
        override=bool(raw.get("override", False)),
    )


def _rules(values, filename=None) -> list[str]:
    result = [str(item).strip().lower() for item in values] if isinstance(values, list) else []
    if filename:
        path = Path(filename)
        if path.exists():
            result.extend(line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
                          if line.strip() and not line.lstrip().startswith("#"))
    return result


def _matches(host: str, rule: str) -> bool:
    rule = rule.strip().lower().rstrip(".")
    if not rule:
        return False
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        domain = rule[2:] if rule.startswith("*.") else rule
        return host == domain or host.endswith("." + domain)
