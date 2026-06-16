from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Indicative CVSS 3.1 vectors for common PortWise configuration findings.
# These represent a plausible worst-case base impact and MUST be confirmed
# by a tester before inclusion in a final client deliverable.
INDICATIVE_VECTORS: dict[str, str] = {
    "SMB Signing Not Required": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "SMBv1 Enabled": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "RDP NLA Disabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Anonymous FTP Login Enabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "DNS Recursion Enabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L",
    "DNS Zone Transfer Allowed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Default SNMP Community Accepted": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "Unauthenticated Redis Access": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Memcached Exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "TLS 1.0 Supported": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "TLS 1.1 Supported": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Expired TLS Certificate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Self-Signed TLS Certificate": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Weak Certificate Signature Algorithm": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "Weak SSH Key Exchange Algorithm": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Weak SSH Cipher": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "SMTP STARTTLS Missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Exposed Git Metadata": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Exposed Environment File": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Exposed phpinfo Page": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Exposed Spring Boot Actuator Endpoint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Directory Listing Enabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Dangerous HTTP Methods Allowed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "WinRM Exposed": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "Unauthenticated Elasticsearch Access": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "SNMP v1/v2c Exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


def parse_vector(vector_str: str) -> dict:
    """Parse a CVSS 3.1 vector string; return base_score, severity, and metrics dict."""
    parts = vector_str.strip().split("/")
    if len(parts) < 9 or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise ValueError(f"Invalid CVSS vector: {vector_str!r}")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"Invalid metric component: {part!r}")
        key, val = part.split(":", 1)
        metrics[key] = val

    for required in _METRIC_ORDER:
        if required not in metrics:
            raise ValueError(f"Missing metric {required!r} in vector: {vector_str!r}")

    scope = metrics["S"]
    av = _AV.get(metrics["AV"])
    ac = _AC.get(metrics["AC"])
    pr = (_PR_C if scope == "C" else _PR_U).get(metrics["PR"])
    ui = _UI.get(metrics["UI"])
    c = _CIA.get(metrics["C"])
    i_ = _CIA.get(metrics["I"])
    a = _CIA.get(metrics["A"])

    if any(v is None for v in (av, ac, pr, ui, c, i_, a)):
        raise ValueError(f"Unknown metric value in vector: {vector_str!r}")

    iscbase = 1.0 - (1.0 - c) * (1.0 - i_) * (1.0 - a)  # type: ignore[operator]

    if scope == "U":
        impact = 6.42 * iscbase
    else:
        impact = 7.52 * (iscbase - 0.029) - 3.25 * ((iscbase - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui  # type: ignore[operator]

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    return {"base_score": base_score, "severity": _severity(base_score), "metrics": metrics}


def build_vector(metrics: dict) -> str:
    """Build a CVSS 3.1 vector string from a metrics dict."""
    for required in _METRIC_ORDER:
        if required not in metrics:
            raise ValueError(f"Missing metric: {required}")
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in _METRIC_ORDER)


def lookup_indicative_vector(title: str) -> dict | None:
    """Fuzzy-match a finding title against the indicative CVSS table."""
    tl = title.lower()
    for key, vector in INDICATIVE_VECTORS.items():
        if key.lower() in tl or tl in key.lower():
            try:
                parsed = parse_vector(vector)
                return {"vector": vector, "base_score": parsed["base_score"], "severity": parsed["severity"], "indicative": True}
            except ValueError:
                continue
    return None


def _roundup(value: float) -> float:
    return math.ceil(value * 10) / 10


def _severity(score: float) -> str:
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
