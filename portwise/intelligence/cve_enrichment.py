from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from portwise.core.models import Confidence, Evidence, Finding, Service, Severity
from portwise.intelligence.constants import BACKPORT_SENSITIVE
from portwise.intelligence.risk_scoring import assign_priority
from portwise.intelligence.version_match import cpe_product_matches, parse_cpe_version, version_in_range
from portwise.utils.http_client import PoliteHttpClient, PolitenessConfig


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
        self.client = PoliteHttpClient(PolitenessConfig(
            min_delay=0.0,
            jitter_min=0.0,
            jitter_max=0.0,
            max_retries=1,
            max_requests_per_host=100,
        ))

    def fetch_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        cache_key: str | None = None,
    ) -> tuple[dict[str, Any] | list[Any] | None, str | None]:
        key = cache_key or hashlib.sha256(url.encode()).hexdigest()[:32]
        path = self.cache_dir / f"{self.name}_{key}.json"
        if path.exists() and time.time() - path.stat().st_mtime < 86_400:
            return json.loads(path.read_text(encoding="utf-8")), None
        try:
            response = self.client.request_url(url, headers=headers or {}, timeout=self.timeout)
            if response.status >= 400:
                return None, f"HTTP {response.status}"
            data = json.loads(response.read().decode("utf-8"))
            path.write_text(json.dumps(data), encoding="utf-8")
            return data, None
        except Exception as exc:
            return None, str(exc)


class NvdProvider(CachedHttpProvider):
    name = "nvd"

    def enrich(self, service: Service) -> CveEnrichment:
        query, is_cpe_query = _service_query(service)
        if not query:
            return CveEnrichment(provider_notes=["No product/version/CPE available for NVD query."])

        params = {"cpeName" if is_cpe_query else "keywordSearch": query}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
        headers: dict[str, str] = {}
        if os.getenv("PORTWISE_NVD_API_KEY"):
            headers["apiKey"] = os.environ["PORTWISE_NVD_API_KEY"]

        data, error = self.fetch_json(url, headers=headers, cache_key=_sha_key(query))
        if error:
            return CveEnrichment(provider_notes=[f"NVD skipped: {error}"])

        cves: list[dict[str, Any]] = []
        for item in (data or {}).get("vulnerabilities", [])[:50]:  # type: ignore[union-attr]
            cve_obj = item.get("cve", {})
            match_status, matched_criteria = _extract_match_status(
                item,
                service.product,
                service.cpes,
                service.version,
                is_keyword=not is_cpe_query,
            )
            if match_status == "drop":
                continue

            metrics = cve_obj.get("metrics", {})
            cvss = _cvss(metrics)
            cvss_vector = _cvss_vector(metrics)
            # NVD 2.0: references is a list, not a dict
            refs = [
                ref.get("url")
                for ref in cve_obj.get("references", [])
                if isinstance(ref, dict) and ref.get("url")
            ][:5]

            cves.append({
                "id": cve_obj.get("id"),
                "cvss": cvss,
                "cvss_vector": cvss_vector,
                "severity": _severity_from_cvss(cvss),
                "references": refs,
                "matched_cpe": matched_criteria,
                "match_status": match_status,
                "affected_product": service.product,
                "detected_version": service.version,
            })

        return CveEnrichment(cves=cves)


class LocalCveProvider:
    """Deterministic offline CVE matcher over packaged NVD-2.0-shaped data."""

    name = "local-cve"

    def __init__(self, dataset_path: Path | None = None) -> None:
        self.dataset_path = dataset_path or (
            Path(__file__).resolve().parents[1] / "data" / "cve" / "local_cves.json"
        )
        self._data: dict[str, Any] | None = None

    def enrich(self, service: Service) -> CveEnrichment:
        data = self._load()
        detected_cpes = service_cpe23_candidates(service)
        if not detected_cpes:
            return CveEnrichment(provider_notes=[
                f"Local CVE: no strict CPE mapping for {service.product or service.service_name} {service.version}."
            ])

        cves: list[dict[str, Any]] = []
        detected_version = _clean_detected_version(service.version) or next(
            (value for value in (parse_cpe_version(cpe) for cpe in detected_cpes) if value),
            service.version,
        )
        for item in data.get("vulnerabilities", []):
            status, matched = _extract_match_status(
                item,
                service.product,
                detected_cpes,
                detected_version,
                is_keyword=False,
            )
            if status != "version_matched":
                continue
            cve_obj = item.get("cve", {})
            metrics = cve_obj.get("metrics", {})
            refs = [
                ref.get("url")
                for ref in cve_obj.get("references", [])
                if isinstance(ref, dict) and ref.get("url")
            ][:5]
            cves.append({
                "id": cve_obj.get("id"),
                "cvss": _cvss(metrics),
                "cvss_vector": _cvss_vector(metrics),
                "severity": _severity_from_cvss(_cvss(metrics)),
                "references": refs,
                "matched_cpe": matched,
                "match_status": status,
                "affected_product": service.product,
                "detected_version": detected_version,
                "detected_cpes": detected_cpes,
            })
        return CveEnrichment(cves=cves)

    def _load(self) -> dict[str, Any]:
        if self._data is None:
            self._data = json.loads(self.dataset_path.read_text(encoding="utf-8"))
        return self._data


class KevProvider(CachedHttpProvider):
    name = "kev"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def enrich(self, service: Service) -> CveEnrichment:
        data, error = self.fetch_json(self.url, cache_key="catalog")
        if error:
            return CveEnrichment(provider_notes=[f"CISA KEV skipped: {error}"])
        vulns = (data or {}).get("vulnerabilities", []) if isinstance(data, dict) else []
        cves = [
            {
                "id": item.get("cveID"),
                "kev": True,
                "references": [item.get("notes")] if item.get("notes") else [],
            }
            for item in vulns
            if item.get("cveID")
        ]
        return CveEnrichment(cves=cves)


class EpssProvider(CachedHttpProvider):
    name = "epss"

    def enrich_cves(self, cve_ids: list[str]) -> CveEnrichment:
        if not cve_ids:
            return CveEnrichment()
        url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode(
            {"cve": ",".join(cve_ids[:100])}
        )
        data, error = self.fetch_json(url, cache_key=_sha_key(",".join(cve_ids[:100])))
        if error:
            return CveEnrichment(provider_notes=[f"EPSS skipped: {error}"])
        return CveEnrichment(
            cves=[
                {"id": item.get("cve"), "epss": float(item.get("epss", 0) or 0)}
                for item in (data or {}).get("data", [])  # type: ignore[union-attr]
            ]
        )

    def enrich(self, service: Service) -> CveEnrichment:
        return CveEnrichment(provider_notes=["EPSS requires CVE IDs from another provider."])


def enrich_services_with_cves(
    services: list[Service],
    cache_dir: Path,
    enabled: bool = True,
    *,
    include_keyword_only: bool = False,
    collapse_version_unknown: bool = True,
) -> tuple[list[Finding], list[str]]:
    """Enrich services with CVE findings.

    False-positive controls (the main reason real scans were noisy):

    * ``keyword_only`` matches (NVD keyword search hits where no CPE
      configuration actually matched the detected product) are **dropped by
      default**. These were the single largest source of bogus findings —
      one service could emit dozens of unrelated CVEs. Set
      ``include_keyword_only=True`` to restore the old behaviour.
    * ``version_unknown`` matches (product matched but the version range
      could not be confirmed) are **collapsed into one finding per service**
      that lists the CVE IDs, instead of one finding per CVE.
    * ``version_matched`` matches are always kept as individual findings —
      that is the high-signal case.
    """
    if not enabled:
        return [], ["CVE enrichment disabled."]

    local = LocalCveProvider()

    findings: list[Finding] = []
    notes: list[str] = []
    suppressed_keyword = 0

    for service in services:
        enrichment = local.enrich(service)
        notes.extend(enrichment.provider_notes)

        unknown_bucket: list[dict[str, Any]] = []

        for cve in enrichment.cves:
            cve_id = str(cve.get("id", ""))
            match_status = cve.get("match_status", "keyword_only")

            # KEV annotation: only applied when the CVE legitimately matched this service
            cve["kev"] = False

            if match_status == "keyword_only" and not include_keyword_only:
                suppressed_keyword += 1
                continue

            if match_status == "version_unknown" and collapse_version_unknown:
                unknown_bucket.append(cve)
                continue

            findings.append(_cve_finding(service, cve))

        if unknown_bucket:
            findings.append(_collapsed_version_unknown_finding(service, unknown_bucket))

    if suppressed_keyword:
        notes.append(
            f"Suppressed {suppressed_keyword} keyword-only CVE match(es) with no CPE/version "
            f"confirmation (use include_keyword_only=True to show them)."
        )

    return findings, notes


_CPE_PRODUCT_MAP: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("vsftpd",), "vsftpd_project", "vsftpd"),
    (("apache httpd", "apache http server", "httpd"), "apache", "http_server"),
    (("samba", "smbd"), "samba", "samba"),
    (("openssh",), "openbsd", "openssh"),
    (("mysql",), "oracle", "mysql"),
    (("php",), "php", "php"),
)


def service_cpe23_candidates(service: Service) -> list[str]:
    """Return strict CPE 2.3 candidates from nmap CPEs or curated identities."""
    candidates: list[str] = []
    for raw in service.cpes:
        converted = _to_cpe23(raw)
        if converted and converted not in candidates:
            candidates.append(converted)
    text = f"{service.product} {service.service_name}".strip().lower()
    version = _clean_detected_version(service.version)
    if version:
        for aliases, vendor, product in _CPE_PRODUCT_MAP:
            if any(alias in text for alias in aliases):
                candidate = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                if candidate not in candidates:
                    candidates.append(candidate)
                break
    return candidates


def _to_cpe23(raw: str) -> str | None:
    if raw.startswith("cpe:2.3:"):
        return raw
    if not raw.startswith("cpe:/"):
        return None
    parts = raw[5:].split(":")
    if len(parts) < 3:
        return None
    part, vendor, product = parts[:3]
    version = parts[3] if len(parts) > 3 and parts[3] else "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _clean_detected_version(raw: str) -> str:
    value = (raw or "").strip().split()[0] if (raw or "").strip() else ""
    value = re.sub(r"^[^0-9]*", "", value)
    value = re.sub(r"[-_]\d*(?:debian|ubuntu).*$", "", value, flags=re.IGNORECASE)
    return value


def _collapsed_version_unknown_finding(service: Service, cves: list[dict[str, Any]]) -> Finding:
    """One finding per service summarising CVEs that matched the product but
    whose version range could not be confirmed. Keeps the signal without
    emitting dozens of near-duplicate rows."""
    ids = [str(c.get("id")) for c in cves if c.get("id")]
    top = sorted(
        cves,
        key=lambda c: (c.get("cvss") or 0, 1 if c.get("kev") else 0),
        reverse=True,
    )[:10]
    max_cvss = max((c.get("cvss") or 0 for c in cves), default=0)
    kev_any = any(c.get("kev") for c in cves)
    severity = _severity_from_cvss_value(max_cvss)

    evidence = Evidence(
        "cve-enrichment",
        "Product matched CVE configurations but the detected version could not be "
        "confirmed in/out of the vulnerable range.",
        2,
        {"cve_ids": ids, "match_status": "version_unknown", "top": top},
    )
    finding = Finding(
        title=f"{len(ids)} CVE(s) Require Manual Version Validation — {service.product or service.service_name}",
        severity=severity,
        asset=service.host,
        port=service.port,
        protocol=service.protocol,
        service=service.service_name,
        description=(
            f"{len(ids)} CVE(s) matched detected component "
            f"'{service.product} {service.version}' by product, but the exact version "
            f"could not be confirmed against the vulnerable range. "
            f"IDs: {', '.join(ids[:25])}{' …' if len(ids) > 25 else ''}."
        ),
        recommendation=(
            "Confirm the precise build/patch level of the component, then validate each "
            "CVE against vendor advisories. Distribution backports may make some non-exploitable."
        ),
        confidence=Confidence.NEEDS_MANUAL_VALIDATION,
        evidence_strength=2,
        type="CVE",
        module="cve",
        false_positive_risk="medium",
        manual_validation=True,
        kev=kev_any,
        evidence=[evidence],
        tags=["version-range-unknown", "cve-summary"],
    )
    return assign_priority(finding)


def _cve_finding(service: Service, cve: dict[str, Any]) -> Finding:
    match_status = cve.get("match_status", "keyword_only")
    kev = bool(cve.get("kev"))
    product_text = f"{service.product} {' '.join(service.cpes)}".lower()
    backport_sensitive = any(name in product_text for name in BACKPORT_SENSITIVE)

    # Confidence mapping (never CONFIRMED for CVEs)
    if backport_sensitive:
        confidence = Confidence.NEEDS_MANUAL_VALIDATION
        fp_risk = "high"
    elif match_status == "version_matched":
        confidence = Confidence.LIKELY
        fp_risk = "low"
    elif match_status == "version_unknown":
        confidence = Confidence.NEEDS_MANUAL_VALIDATION
        fp_risk = "medium"
    else:  # keyword_only
        confidence = Confidence.POSSIBLE
        fp_risk = "high"

    # Severity: KEV escalates to HIGH only on confirmed version matches
    if kev and match_status == "version_matched":
        severity = Severity.HIGH
    else:
        severity = _severity_from_cvss_value(cve.get("cvss"))

    manual_validation = match_status in ("keyword_only", "version_unknown") or backport_sensitive

    if match_status == "version_matched" and not backport_sensitive:
        title = "Known Exploited Vulnerability Indicator" if kev else "Known Vulnerable Component Detected"
    else:
        title = "CVE Match Requires Manual Validation"

    evidence = Evidence(
        "cve-enrichment",
        "CVE matched using CPE or product/version search.",
        3 if match_status == "version_matched" else 2,
        cve,
    )
    finding = Finding(
        title=title,
        severity=severity,
        asset=service.host,
        port=service.port,
        protocol=service.protocol,
        service=service.service_name,
        description=f"{cve.get('id')} matched detected component {service.product} {service.version}.",
        recommendation="Validate package provenance/backports and remediate according to vendor guidance.",
        confidence=confidence,
        evidence_strength=evidence.strength,
        type="CVE",
        module="cve",
        false_positive_risk=fp_risk,
        manual_validation=manual_validation,
        cve_id=str(cve.get("id")),
        cvss=cve.get("cvss"),
        cvss_vector=cve.get("cvss_vector"),
        epss=cve.get("epss"),
        kev=kev,
        references=list(cve.get("references", []) or []),
        evidence=[evidence],
    )

    if backport_sensitive:
        finding.tags.append("backport-sensitive")
        finding.description += (
            " Backported distribution packages may not be vulnerable"
            " even when the upstream version appears affected."
        )
    if match_status == "keyword_only":
        finding.tags.append("keyword-match-only")
    if match_status == "version_unknown":
        finding.tags.append("version-range-unknown")

    return assign_priority(finding)


def _extract_match_status(
    vuln_item: dict[str, Any],
    product: str,
    cpes: list[str],
    version: str,
    *,
    is_keyword: bool,
) -> tuple[str, str | None]:
    """
    Returns (match_status, matched_criteria_cpe_or_None).

    match_status values:
      "version_matched"  — detected version falls within the CVE's vulnerable range
      "version_unknown"  — product matched but version range can't be confirmed
      "keyword_only"     — keyword search hit; no CPE configuration matched our product
      "drop"             — product matched but detected version is definitively NOT in range
    """
    cve_obj = vuln_item.get("cve", {})
    configurations = cve_obj.get("configurations", [])

    matching: list[dict[str, Any]] = []
    for conf in configurations:
        for node in conf.get("nodes", []):
            for entry in node.get("cpeMatch", []):
                if not entry.get("vulnerable", False):
                    continue
                criteria = entry.get("criteria", "")
                hit = any(cpe_product_matches(c, criteria) for c in cpes) if cpes else False
                if not hit and product:
                    hit = cpe_product_matches(product, criteria)
                if hit:
                    matching.append(entry)

    if not matching:
        return ("keyword_only" if is_keyword else "version_unknown"), None

    any_in_range = False
    any_unknown = False
    first_criteria: str | None = None

    for entry in matching:
        criteria_version = _criteria_version(entry.get("criteria", ""))
        has_range = any(entry.get(key) for key in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding",
        ))
        if criteria_version and not has_range:
            result = version_in_range(version, criteria_version, None, criteria_version, None)
        else:
            result = version_in_range(
                version,
                entry.get("versionStartIncluding"),
                entry.get("versionStartExcluding"),
                entry.get("versionEndIncluding"),
                entry.get("versionEndExcluding"),
            )
        if result is True:
            any_in_range = True
            first_criteria = entry.get("criteria")
            break
        if result is None:
            any_unknown = True

    if any_in_range:
        return "version_matched", first_criteria
    if any_unknown:
        return "version_unknown", None
    return "drop", None


def _criteria_version(criteria: str) -> str | None:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[5] in {"", "*", "-"}:
        return None
    return parts[5]


def _service_query(service: Service) -> tuple[str, bool]:
    if service.cpes:
        return service.cpes[0], True
    if service.product and service.version:
        return f"{service.product} {service.version}", False
    return "", False


def _sha_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if values:
            return float(values[0].get("cvssData", {}).get("baseScore", 0) or 0)
    return None


def _cvss_vector(metrics: dict[str, Any]) -> str | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key)
        if values:
            vec = values[0].get("cvssData", {}).get("vectorString")
            if vec:
                return str(vec)
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
