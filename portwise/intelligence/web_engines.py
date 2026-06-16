"""Optional web-engine orchestration: nuclei + ffuf.

PortWise stays the brain. When the binaries are on PATH it runs them against
discovered web targets, parses their JSON output into PortWise ``Finding``
objects, and lets the normal dedup/confidence pipeline fold them in. When a
binary is absent it skips cleanly and emits the equivalent handoff command.

Both engines are gated to ``full`` assessment depth by the caller. Parsing is
pure (fixture-testable); execution goes through :class:`ExternalTool`.
"""
from __future__ import annotations

import os
import tempfile
from typing import Any

from portwise.core.external_tool import ExternalTool, ExternalToolResult
from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.utils.net import bracket_host

_NUCLEI_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
}

# ffuf statuses worth surfacing as content-discovery findings.
_FFUF_INTERESTING = {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500}


# ---------------------------------------------------------------------------
# Parsing (pure)
# ---------------------------------------------------------------------------

def _first(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def parse_nuclei_records(records: list[dict[str, Any]], *, module: str = "nuclei") -> list[Finding]:
    """Convert nuclei -jsonl records into Findings."""
    findings: list[Finding] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        info = record.get("info", {}) if isinstance(record.get("info"), dict) else {}
        template_id = str(record.get("template-id") or record.get("templateID") or "")
        name = str(info.get("name") or template_id or "nuclei finding")
        sev_key = str(info.get("severity", "info")).lower()
        severity = _NUCLEI_SEVERITY.get(sev_key, Severity.INFO)
        host = str(record.get("host") or record.get("ip") or "")
        # nuclei 'host' can be host:port or a URL authority; keep the bare host.
        asset = host.split("//")[-1].split("/")[0].split(":")[0]
        try:
            port = int(record.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        matched = str(record.get("matched-at") or record.get("matched") or record.get("url") or "")

        classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
        cve_id = _first(classification.get("cve-id")) or None
        cvss = None
        try:
            score = classification.get("cvss-score")
            cvss = float(score) if score is not None else None
        except (TypeError, ValueError):
            cvss = None
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        references = [str(r) for r in references if r]

        extracted = record.get("extracted-results") or []
        desc_parts = [str(info.get("description") or "").strip()]
        if matched:
            desc_parts.append(f"Matched at: {matched}.")
        if extracted:
            desc_parts.append(f"Extracted: {', '.join(str(e) for e in extracted)[:200]}.")
        description = " ".join(p for p in desc_parts if p) or f"nuclei template {template_id} matched."

        is_info = severity == Severity.INFO
        category = FindingCategory.INFORMATION if is_info else FindingCategory.VULNERABILITY
        evidence = Evidence(
            source=f"engine:{module}",
            description=f"nuclei template '{template_id}' matched at {matched or asset}.",
            strength=4,
            data={
                "engine": "nuclei",
                "template_id": template_id,
                "template_url": record.get("template-url") or record.get("template-path") or "",
                "matched_at": matched,
                "curl_command": record.get("curl-command") or "",
                "type": record.get("type") or "",
                "extracted": extracted,
            },
        )
        finding = Finding(
            title=name,
            severity=severity,
            asset=asset,
            port=port or None,
            protocol="tcp",
            service=str(record.get("type") or "http"),
            description=description,
            recommendation="Validate the nuclei match against the affected component and remediate per the referenced advisory.",
            confidence=Confidence.LIKELY,
            evidence_strength=4,
            type="nuclei",
            module=module,
            false_positive_risk="low",
            manual_validation=is_info is False,
            cve_id=cve_id,
            cvss=cvss,
            references=references,
            evidence=[evidence],
            tags=["nuclei", "external-engine"] + (["cve"] if cve_id else []),
            category=category,
        )
        findings.append(finding)
    return findings


def parse_ffuf_results(
    document: Any,
    *,
    target: dict[str, Any],
    module: str = "ffuf",
    skip_paths: set[str] | None = None,
) -> list[Finding]:
    """Convert an ffuf JSON document (``{"results": [...]}``) into Findings."""
    skip_paths = skip_paths or set()
    if isinstance(document, list):
        document = document[0] if document else {}
    results = []
    if isinstance(document, dict):
        results = document.get("results", []) or []
    host = str(target.get("host", ""))
    try:
        port = int(target.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0

    findings: list[Finding] = []
    seen: set[str] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        status = int(item.get("status", 0) or 0)
        if status not in _FFUF_INTERESTING:
            continue
        url = str(item.get("url", ""))
        path = "/" + url.split("//", 1)[-1].split("/", 1)[-1] if "//" in url else url
        if path in skip_paths or path in seen:
            continue
        seen.add(path)
        length = item.get("length", 0)
        words = item.get("words", 0)
        ctype = item.get("content-type", "")
        severity = Severity.LOW if status in {200, 401, 403} else Severity.INFO
        category = FindingCategory.INFORMATION
        evidence = Evidence(
            source=f"engine:{module}",
            description=f"ffuf discovered {url} (HTTP {status}, {length} bytes).",
            strength=3,
            data={
                "engine": "ffuf",
                "url": url,
                "status": status,
                "length": length,
                "words": words,
                "content_type": ctype,
            },
        )
        finding = Finding(
            title=f"Content Discovered — {path}",
            severity=severity,
            asset=host,
            port=port or None,
            protocol="tcp",
            service="http",
            description=(
                f"ffuf content discovery found {url} returning HTTP {status} "
                f"({length} bytes, {words} words, content-type {ctype or 'unknown'}). "
                f"Review whether this path should be publicly reachable."
            ),
            recommendation="Confirm the path is intended for public access; restrict or remove if not.",
            confidence=Confidence.LIKELY,
            evidence_strength=3,
            type="content-discovery",
            module=module,
            false_positive_risk="contextual",
            manual_validation=True,
            evidence=[evidence],
            tags=["ffuf", "content-discovery", "external-engine"],
            category=category,
        )
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Execution (via ExternalTool)
# ---------------------------------------------------------------------------

def _target_url(target: dict[str, Any]) -> str:
    host = bracket_host(str(target.get("host", "")))
    port = int(target.get("port", 0) or 0)
    routing = str(target.get("routing_reason", "")).lower()
    service = str(target.get("service", "")).lower()
    tls = port in {443, 8443, 9443, 4443, 10443} or "https" in service or "tls" in routing or "ssl" in service
    scheme = "https" if tls else "http"
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def run_nuclei(
    target: dict[str, Any],
    config: dict[str, Any],
    *,
    tool: ExternalTool | None = None,
) -> tuple[list[Finding], str]:
    """Run nuclei against one web target. Returns (findings, status_note)."""
    cfg = _engine_cfg(config, "nuclei")
    if not bool(cfg.get("enabled", True)):
        return [], "nuclei: disabled by config"
    url = _target_url(target)
    handoff = f"nuclei -u {url} -jsonl"
    tool = tool or ExternalTool("nuclei", timeout=float(cfg.get("timeout", 600)))
    args = ["-u", url, "-jsonl", "-silent", "-no-color"]
    severity = str(cfg.get("severity", "")).strip()
    if severity:
        args += ["-severity", severity]
    extra = cfg.get("extra_args")
    if isinstance(extra, list):
        args += [str(a) for a in extra]
    result = tool.run_json(args, jsonl=True, handoff_command=handoff)
    if not result.ok:
        return [], result.note()
    findings = parse_nuclei_records(result.records)
    return findings, f"nuclei: {len(findings)} finding(s) from {url}"


def run_ffuf(
    target: dict[str, Any],
    config: dict[str, Any],
    *,
    skip_paths: set[str] | None = None,
    tool: ExternalTool | None = None,
) -> tuple[list[Finding], str]:
    """Run ffuf content discovery against one web target. Returns (findings, note)."""
    cfg = _engine_cfg(config, "ffuf")
    if not bool(cfg.get("enabled", True)):
        return [], "ffuf: disabled by config"
    url = _target_url(target)
    wordlist = str(cfg.get("wordlist", "") or "")
    handoff = (
        f"ffuf -u {url}/FUZZ -w {wordlist or '/usr/share/seclists/Discovery/Web-Content/common.txt'} "
        f"-of json -o ffuf.json -ac"
    )
    if not wordlist or not os.path.isfile(wordlist):
        return [], (
            f"ffuf: wordlist not configured or missing "
            f"({wordlist or 'web_engines.ffuf.wordlist'}); skipped — handoff: {handoff}"
        )
    tool = tool or ExternalTool("ffuf", timeout=float(cfg.get("timeout", 600)))
    out_handle = tempfile.NamedTemporaryFile(prefix="portwise-ffuf-", suffix=".json", delete=False)
    out_path = out_handle.name
    out_handle.close()
    try:
        args = [
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-of", "json",
            "-o", out_path,
            "-ac",
            "-s",
        ]
        match_codes = str(cfg.get("match_codes", "")).strip()
        if match_codes:
            args += ["-mc", match_codes]
        extra = cfg.get("extra_args")
        if isinstance(extra, list):
            args += [str(a) for a in extra]
        result = tool.run_json(args, jsonl=False, handoff_command=handoff, stdout_path=out_path)
        if not result.ok:
            return [], result.note()
        document = result.records[0] if result.records else {}
        findings = parse_ffuf_results(document, target=target, skip_paths=skip_paths)
        return findings, f"ffuf: {len(findings)} path(s) from {url}"
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def run_web_engines(
    http_targets: list[Any],
    config: dict[str, Any],
    *,
    existing_findings: list[Finding] | None = None,
    nuclei_tool: ExternalTool | None = None,
    ffuf_tool: ExternalTool | None = None,
) -> tuple[list[Finding], list[str]]:
    """Orchestrate nuclei + ffuf across discovered web targets.

    De-duplicates targets to one URL per host:port:scheme and feeds ffuf the set
    of paths already reported by native content discovery so it does not re-report
    them. Returns (findings, notes). Absent binaries yield a note + handoff, never
    an exception.
    """
    web_cfg = config.get("web_engines", {}) if isinstance(config.get("web_engines"), dict) else {}
    if not bool(web_cfg.get("enabled", True)):
        return [], ["web_engines: disabled by config"]

    findings: list[Finding] = []
    notes: list[str] = []
    seen_urls: set[str] = set()
    skip_by_host = _existing_paths_by_host(existing_findings or [])

    for raw in http_targets:
        target = raw if isinstance(raw, dict) else _target_to_dict(raw)
        url = _target_url(target)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        host = str(target.get("host", ""))

        n_findings, n_note = run_nuclei(target, config, tool=nuclei_tool)
        findings.extend(n_findings)
        notes.append(n_note)

        f_findings, f_note = run_ffuf(
            target, config,
            skip_paths=skip_by_host.get(host, set()),
            tool=ffuf_tool,
        )
        findings.extend(f_findings)
        notes.append(f_note)

    return findings, notes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine_cfg(config: dict[str, Any], name: str) -> dict[str, Any]:
    web_cfg = config.get("web_engines", {}) if isinstance(config.get("web_engines"), dict) else {}
    section = web_cfg.get(name, {})
    return section if isinstance(section, dict) else {}


def _existing_paths_by_host(findings: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for finding in findings:
        for ev in finding.evidence:
            data = ev.data if isinstance(ev.data, dict) else {}
            url = str(data.get("url", ""))
            if "//" in url:
                path = "/" + url.split("//", 1)[-1].split("/", 1)[-1]
                out.setdefault(str(finding.asset), set()).add(path)
    return out


def _target_to_dict(target: Any) -> dict[str, Any]:
    from dataclasses import asdict, is_dataclass
    if is_dataclass(target):
        return asdict(target)
    return {
        "host": getattr(target, "host", ""),
        "port": getattr(target, "port", 0),
        "protocol": getattr(target, "protocol", "tcp"),
        "service": getattr(target, "service", ""),
        "routing_reason": getattr(target, "routing_reason", ""),
    }
