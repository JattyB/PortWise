"""Operator-supplied credentials for authenticated assessment.

Authenticated checks are an explicit, per-engagement opt-in (master switch
``authenticated: true`` plus supplied credentials) and run only at ``full`` depth.
This module loads/normalises credentials and provides the opt-in gate. It never
invents or guesses credentials — only the operator's supplied set is used.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any


@dataclass(slots=True)
class Credential:
    service: str           # web | http | smb | snmp | ...
    username: str = ""
    password: str = ""
    domain: str = ""
    community: str = ""     # SNMP
    login_url: str = ""     # web form login
    username_field: str = "username"
    password_field: str = "password"
    extra: dict[str, Any] = field(default_factory=dict)

    def redacted(self) -> str:
        who = f"{self.domain}\\{self.username}" if self.domain else self.username
        if self.community:
            return f"{self.service}: community=<redacted>"
        return f"{self.service}: {who or '(no user)'}:<redacted>"

    def identity(self) -> str:
        """Stable non-reversible identifier used to correlate supplied credentials."""
        material = "\0".join((self.domain.lower(), self.username.lower(), self.password, self.community))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def authenticated_enabled(config: dict[str, Any]) -> bool:
    """True only when the operator explicitly enabled authenticated checks."""
    return bool(config.get("authenticated", False))


def parse_cred_arg(value: str) -> Credential:
    """Parse a CLI credential of the form ``service:user:pass`` or
    ``service:DOMAIN/user:pass`` or ``snmp::community``."""
    parts = value.split(":", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid --cred '{value}'. Use service:user:pass (or snmp::community).")
    service = parts[0].strip().lower()
    if service == "snmp":
        community = parts[2] if len(parts) == 3 else parts[1]
        return Credential(service="snmp", community=community.strip())
    user = parts[1].strip()
    password = parts[2] if len(parts) == 3 else ""
    domain = ""
    if "/" in user:
        domain, user = user.split("/", 1)
    elif "\\" in user:
        domain, user = user.split("\\", 1)
    return Credential(service=service, username=user, password=password, domain=domain.strip())


def load_credentials(config: dict[str, Any]) -> list[Credential]:
    """Build the credential list from config (``credentials:`` list of mappings)."""
    raw = config.get("credentials", [])
    creds: list[Credential] = []
    if not isinstance(raw, list):
        return creds
    for item in raw:
        if isinstance(item, Credential):
            creds.append(item)
            continue
        if not isinstance(item, dict):
            continue
        creds.append(Credential(
            service=str(item.get("service", "")).lower(),
            username=str(item.get("username", "")),
            password=str(item.get("password", "")),
            domain=str(item.get("domain", "")),
            community=str(item.get("community", "")),
            login_url=str(item.get("login_url", "")),
            username_field=str(item.get("username_field", "username")),
            password_field=str(item.get("password_field", "password")),
            extra={k: v for k, v in item.items() if k not in {
                "service", "username", "password", "domain", "community",
                "login_url", "username_field", "password_field"}},
        ))
    return creds


def credentials_for(config: dict[str, Any], *services: str) -> list[Credential]:
    """Credentials whose service matches any of ``services`` (case-insensitive).
    Returns [] when authenticated mode is off."""
    if not authenticated_enabled(config):
        return []
    wanted = {s.lower() for s in services}
    return [c for c in load_credentials(config) if c.service in wanted]


def snmp_communities_from_credentials(config: dict[str, Any]) -> list[str]:
    return [c.community for c in credentials_for(config, "snmp") if c.community]
