"""Executive-summary narrative generation.

Produces a direct, technical summary of an engagement's findings — written the
way a senior pentester would brief a client: what was assessed, what matters
most, and what to fix first.
"""
from __future__ import annotations

from typing import Any

_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


def _norm(value: Any) -> str:
    return str(value or "").lower().strip()


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev = _norm(f.get("severity"))
        if sev in ("info", "informational"):
            sev = "informational"
        if sev in counts:
            counts[sev] += 1
    return counts


def summary_facts(data: dict[str, Any]) -> dict[str, Any]:
    findings = data.get("findings", []) or []
    state = (data.get("metadata", {}) or {}).get("state", {}) or {}
    sev = _severity_counts(findings)
    vulns = [f for f in findings if _norm(f.get("category")) == "vulnerability"]
    confirmed = [f for f in findings if _norm(f.get("confidence")) == "confirmed"]
    kev = [f for f in findings if f.get("kev")]
    exploitable = [f for f in findings if f.get("exploit_available")]
    cleartext = [f for f in findings if "plaintext-protocol" in (f.get("tags") or []) or "cleartext" in _norm(f.get("title"))]
    top = _top_findings(findings, 5)
    return {
        "targets": len(state.get("targets_loaded", []) or []),
        "live_hosts": len(state.get("live_hosts", []) or []),
        "services": sum(len(v) for v in (state.get("services_by_host", {}) or {}).values()),
        "total_findings": len(findings),
        "severity": sev,
        "vulnerabilities": len(vulns),
        "confirmed": len(confirmed),
        "kev": len(kev),
        "exploitable": len(exploitable),
        "cleartext": len(cleartext),
        "top": top,
    }


def _top_findings(findings: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    def rank(f: dict[str, Any]) -> tuple:
        sev = _norm(f.get("severity")).replace("ational", "")
        sev_idx = _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 9
        return (
            0 if f.get("exploit_available") else 1,
            0 if f.get("kev") else 1,
            sev_idx,
            str(f.get("priority", "P9")),
        )
    ranked = sorted(
        [f for f in findings if _norm(f.get("severity")) not in ("informational", "info")],
        key=rank,
    )
    return ranked[:n]


def executive_summary_text(data: dict[str, Any]) -> str:
    facts = summary_facts(data)
    sev = facts["severity"]
    project = data.get("project") or "the in-scope environment"

    lines: list[str] = []
    lines.append(
        f"This assessment of {project} examined {facts['services']} service(s) across "
        f"{facts['live_hosts']} live host(s) of {facts['targets']} target(s) supplied for the engagement."
    )

    sev_phrase = ", ".join(
        f"{sev[s]} {s}" for s in _SEV_ORDER if sev.get(s)
    ) or "no notable findings"
    lines.append(
        f"PortWise produced {facts['total_findings']} finding(s): {sev_phrase}. "
        f"Of these, {facts['vulnerabilities']} are categorised as vulnerabilities and "
        f"{facts['confirmed']} were actively confirmed."
    )

    risk_bits: list[str] = []
    if facts["exploitable"]:
        risk_bits.append(f"{facts['exploitable']} finding(s) have a known public exploit")
    if facts["kev"]:
        risk_bits.append(f"{facts['kev']} match CISA KEV (known exploited in the wild)")
    if facts["cleartext"]:
        risk_bits.append(f"{facts['cleartext']} expose data over cleartext protocols")
    if risk_bits:
        lines.append("Priority drivers: " + "; ".join(risk_bits) + ".")

    if facts["top"]:
        lines.append("Highest-priority items to remediate first:")
        for f in facts["top"]:
            tags = []
            if f.get("exploit_available"):
                tags.append("exploit available")
            if f.get("kev"):
                tags.append("KEV")
            suffix = f" [{', '.join(tags)}]" if tags else ""
            asset = f.get("asset", "")
            port = f.get("port")
            where = f"{asset}:{port}" if port else asset
            lines.append(f"  - [{_norm(f.get('severity')).upper()}] {f.get('title')} — {where}{suffix}")
    else:
        lines.append("No vulnerability-class findings were identified at the selected assessment depth.")

    return "\n".join(lines)


def executive_summary_html(data: dict[str, Any], esc) -> str:
    """Render the executive summary as an HTML section. ``esc`` is the report's
    HTML-escaping function."""
    facts = summary_facts(data)
    sev = facts["severity"]

    chips = "".join(
        f'<span class="exec-chip exec-{s}">{sev[s]} {s.capitalize()}</span>'
        for s in _SEV_ORDER if sev.get(s)
    ) or '<span class="exec-chip">No notable findings</span>'

    drivers: list[str] = []
    if facts["exploitable"]:
        drivers.append(f"<strong>{facts['exploitable']}</strong> with a known public exploit")
    if facts["kev"]:
        drivers.append(f"<strong>{facts['kev']}</strong> on CISA KEV")
    if facts["cleartext"]:
        drivers.append(f"<strong>{facts['cleartext']}</strong> cleartext exposure(s)")
    drivers_html = ("<p class=\"exec-drivers\">Priority drivers: " + "; ".join(drivers) + ".</p>") if drivers else ""

    top_html = ""
    if facts["top"]:
        items = []
        for f in facts["top"]:
            badges = ""
            if f.get("exploit_available"):
                badges += '<span class="kev-badge" style="background:#fef2f2">EXPLOIT</span>'
            if f.get("kev"):
                badges += '<span class="kev-badge">KEV</span>'
            asset = esc(str(f.get("asset", "")))
            port = esc(str(f.get("port", "")))
            where = f"{asset}:{port}" if f.get("port") else asset
            sevn = _norm(f.get("severity")).replace("ational", "")
            items.append(
                f'<li><span class="badge badge-{esc(sevn)}">{esc(sevn.upper()[:4])}</span> '
                f'{esc(f.get("title", ""))} <span class="text-muted">— {where}</span> {badges}</li>'
            )
        top_html = '<ol class="exec-top">' + "".join(items) + "</ol>"

    narrative = esc(executive_summary_text(data)).replace("\n", "<br>")

    return (
        '<section class="exec-section">'
        '<div class="exec-card">'
        '<div class="exec-title">Executive Summary</div>'
        f'<div class="exec-chips">{chips}</div>'
        f'{drivers_html}'
        f'<p class="exec-narrative">{narrative}</p>'
        + (f'<div class="exec-toplabel">Remediate first</div>{top_html}' if top_html else "")
        + '</div></section>'
    )
