"""`portwise doctor` — report which optional engines are installed and what
checks they therefore enable.

PortWise runs native protocol checks regardless; optional engines add depth when
present and fall back to handoff commands when absent.
"""
from __future__ import annotations

from dataclasses import dataclass

from portwise.core.external_tool import ExternalTool


@dataclass(slots=True)
class EngineStatus:
    name: str
    binary: str
    available: bool
    path: str | None
    enables: str
    fallback: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "binary": self.binary,
            "available": self.available,
            "path": self.path,
            "enables": self.enables,
            "fallback": self.fallback,
        }


# (display name, binary, what it enables, fallback when absent)
_ENGINES: tuple[tuple[str, str, str, str], ...] = (
    ("nmap", "nmap", "discovery, TCP/UDP port + service detection (core scanning)",
     "core scanning is unavailable; provide Nmap XML via `portwise analyze`"),
    ("masscan", "masscan", "fast wide port sweeps (masscan -oJ)",
     "Nmap is used for port discovery instead"),
    ("nuclei", "nuclei", "templated web/vuln checks parsed from -jsonl",
     "skipped; equivalent nuclei command emitted via handoff"),
    ("ffuf", "ffuf", "content discovery parsed from -of json",
     "native content discovery only; ffuf command emitted via handoff"),
    ("gowitness", "gowitness", "web service screenshots for evidence/POC",
     "skipped; gowitness command emitted via handoff"),
    ("testssl", "testssl.sh", "deep TLS analysis imported from JSON",
     "native TLS handshake checks still run"),
    ("ssh-audit", "ssh-audit", "SSH algorithm cross-check",
     "native KEXINIT probe still runs"),
    ("searchsploit", "searchsploit", "ExploitDB exploit-availability lookup for CVEs",
     "exploit-availability flag omitted; nuclei template presence still used"),
)


def collect_engine_status() -> list[EngineStatus]:
    statuses: list[EngineStatus] = []
    for name, binary, enables, fallback in _ENGINES:
        tool = ExternalTool(name, binary=binary)
        path = tool.resolve()
        statuses.append(EngineStatus(
            name=name,
            binary=binary,
            available=path is not None,
            path=path,
            enables=enables,
            fallback=fallback,
        ))
    return statuses


def render_doctor(statuses: list[EngineStatus]) -> str:
    lines: list[str] = []
    lines.append("PortWise doctor — optional engine availability")
    lines.append("")
    present = [s for s in statuses if s.available]
    absent = [s for s in statuses if not s.available]
    lines.append(f"Detected {len(present)}/{len(statuses)} optional engines on PATH.")
    lines.append("")
    for status in statuses:
        mark = "[ok]  " if status.available else "[--]  "
        lines.append(f"{mark}{status.name:<12} {status.binary}")
        if status.available:
            lines.append(f"           path:    {status.path}")
            lines.append(f"           enables: {status.enables}")
        else:
            lines.append(f"           absent:  {status.enables}")
            lines.append(f"           fallback: {status.fallback}")
    lines.append("")
    if absent:
        lines.append("Install the absent engines to add depth, or run PortWise as-is —")
        lines.append("native protocol checks run regardless and handoff commands cover the rest.")
    else:
        lines.append("All optional engines detected; full orchestration depth is available.")
    return "\n".join(lines) + "\n"
