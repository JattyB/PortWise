from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from portwise.core.models import Confidence, Evidence, Finding, Service, Severity
from portwise.intelligence.risk_scoring import assign_priority


@dataclass(slots=True)
class CveEnrichment:
    cves: list[dict[str, Any]] = field(default_factory=list)
    provider_notes: list[str] = field(default_factory=list)


class CveProvider(Protocol):
    name: str

    def enrich(self, service: Service) -> CveEnrichment:
        ...


class CachedHttpProvider:
    name = "base"

    def __init__(self, cache_dir: Path, timeout: float = 10.0) -> None:
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def fetch_json(self, url: str, headers: dict[str, str] | None = None, cache_key: str | None = None) -> tuple[dict[str, Any] | list[Any] | None, str | None]:
        key = cache_key or str(abs(hash(url)))
        path = self.cache_dir / f"{self.name}_{key}.json"
        if path.exists() and time.time() - path.stat().st_mtime < 86_400:
            return json.loads(path.read_text(encoding="utf-8")), None
        try:
            try:
                import requests  # type: ignore

                response = requests.get(url, headers=headers or {}, timeout=self.timeout)
                response.raise_for_status()
                data = response.json()
            except ModuleNotFoundError:
                request = urllib.request.Request(url, headers=headers or {})
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
            path.write_text(json.dumps(data), encoding="utf-8")
            return data, None
        except Exception as exc:
            return None, str(exc)


class NvdProvider(CachedHttpProvider):
    name = "nvd"

    def enrich(self, service: Service) -> CveEnrichment:
        query, exact = _service_query(service)
        if not query:
            return CveEnrichment(provider_notes=["No product/version/CPE available for NVD query."])
        params = {"cpeName" if exact else "keywordSearch": query}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
        headers = {}
        if os.getenv("PORTWISE_NVD_API_KEY"):
            headers["apiKey"] = os.environ["PORTWISE_NVD_API_KEY"]
        data, error = self.fetch_json(url, headers=headers, cache_key=_safe_key(query))
        if error:
            return CveEnrichment(provider_notes=[f"NVD skipped: {error}"])
        cves: list[dict[str, Any]] = []
        for item in (data or {}).get("vulnerabilities", [])[:25]:  # type: ignore[union-attr]
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = _cvss(metrics)
            cves.append({
                "id": cve.get("id"),
                "cvss": cvss,
                "severity": _severity_from_cvss(cvss),
                "references": [ref.get("url") for ref in cve.get("references", {}).get("referenceData", []) if ref.get("url")][:5],
                "matched_cpe": query if exact else None,
                "match_confidence": "Likely" if exact else "Possible",
                "affected_product": service.product,
                "detected_version": service.version,
            })
        return CveEnrichment(cves=cves)


class KevProvider(CachedHttpProvider):
    name = "kev"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def enrich(self, service: Service) -> CveEnrichment:
        data, error = self.fetch_json(self.url, cache_key="catalog")
        if error:
            return CveEnrichment(provider_notes=[f"CISA KEV skipped: {error}"])
        vulns = (data or {}).get("vulnerabilities", []) if isinstance(data, dict) else []
        cves = [{"id": item.get("cveID"), "kev": True, "references": [item.get("notes")] if item.get("notes") else []} for item in vulns if item.get("cveID")]
        return CveEnrichment(cves=cves)


class EpssProvider(CachedHttpProvider):
    name = "epss"

    def enrich_cves(self, cve_ids: list[str]) -> CveEnrichment:
        if not cve_ids:
            return CveEnrichment()
        url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": ",".join(cve_ids[:100])})
        data, error = self.fetch_json(url, cache_key=_safe_key(",".join(cve_ids[:100])))
        if error:
            return CveEnrichment(provider_notes=[f"EPSS skipped: {error}"])
        return CveEnrichment(cves=[{"id": item.get("cve"), "epss": float(item.get("epss", 0) or 0)} for item in (data or {}).get("data", [])])  # type: ignore[union-attr]

    def enrich(self, service: Service) -> CveEnrichment:
        return CveEnrichment(provider_notes=["EPSS requires CVE IDs from another provider."])


def enrich_services_with_cves(services: list[Service], cache_dir: Path, enabled: bool = True) -> tuple[list[Finding], list[str]]:
    if not enabled:
        return [], ["CVE enrichment disabled."]
    nvd = NvdProvider(cache_dir)
    kev = KevProvider(cache_dir)
    epss = EpssProvider(cache_dir)
    kev_data = kev.enrich(services[0] if services else Service("", 0, "", "")).cves if services else []
    kev_ids = {item["id"] for item in kev_data if item.get("id")}
    findings: list[Finding] = []
    notes: list[str] = []
    for service in services:
        enrichment = nvd.enrich(service)
        notes.extend(enrichment.provider_notes)
        epss_map = {item["id"]: item for item in epss.enrich_cves([str(cve["id"]) for cve in enrichment.cves if cve.get("id")]).cves}
        for cve in enrichment.cves:
            cve_id = str(cve.get("id"))
            cve["kev"] = cve_id in kev_ids
            if cve_id in epss_map:
                cve["epss"] = epss_map[cve_id].get("epss")
            findings.append(_cve_finding(service, cve))
    return findings, notes


def _cve_finding(service: Service, cve: dict[str, Any]) -> Finding:
    exact = bool(cve.get("matched_cpe"))
    kev = bool(cve.get("kev"))
    backport_sensitive = any(name in f"{service.product} {' '.join(service.cpes)}".lower() for name in ("openssh", "apache", "nginx", "openssl", "php", "linux", "samba"))
    severity = Severity.HIGH if kev else _severity_from_cvss_value(cve.get("cvss"))
    evidence = Evidence("cve-enrichment", "CVE matched using CPE or product/version search.", 3 if exact else 2, cve)
    title = "Known Exploited Vulnerability Indicator" if kev else "Known Vulnerable Component Detected"
    finding = Finding(
        title=title if exact else "CVE Match Requires Manual Validation",
        severity=severity,
        asset=service.host,
        port=service.port,
        protocol=service.protocol,
        service=service.service_name,
        description=f"{cve.get('id')} matched detected component {service.product} {service.version}.",
        recommendation="Validate package provenance/backports and remediate according to vendor guidance.",
        confidence=Confidence.NEEDS_MANUAL_VALIDATION if backport_sensitive else Confidence.LIKELY if exact else Confidence.POSSIBLE,
        evidence_strength=evidence.strength,
        type="CVE",
        module="cve",
        false_positive_risk="high" if backport_sensitive or not exact else "medium",
        manual_validation=True,
        cve_id=str(cve.get("id")),
        cvss=cve.get("cvss"),
        epss=cve.get("epss"),
        kev=kev,
        references=list(cve.get("references", []) or []),
        evidence=[evidence],
    )
    if backport_sensitive:
        finding.tags.append("backport-sensitive")
        finding.description += " Backported distribution packages may not be vulnerable even when the upstream version appears affected."
    return assign_priority(finding)


def _service_query(service: Service) -> tuple[str, bool]:
    if service.cpes:
        return service.cpes[0], True
    if service.product and service.version:
        return f"{service.product} {service.version}", False
    return "", False


def _safe_key(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value)[:120]


def _cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if values:
            return float(values[0].get("cvssData", {}).get("baseScore", 0) or 0)
    return None


def _severity_from_cvss(value: float | None) -> str:
    return _severity_from_cvss_value(value).value


def _severity_from_cvss_value(value: Any) -> Severity:
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW
