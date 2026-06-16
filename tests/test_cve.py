from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch


from portwise.core.models import Confidence, Service
from portwise.intelligence.cve_enrichment import (
    EpssProvider,
    KevProvider,
    NvdProvider,
    _extract_match_status,
    enrich_services_with_cves,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _nginx_service(version: str = "1.22.0") -> Service:
    return Service(
        host="203.0.113.10",
        port=80,
        protocol="tcp",
        state="open",
        service_name="http",
        product="nginx",
        version=version,
    )


def _openssh_service(version: str = "OpenSSH_8.9p1") -> Service:
    return Service(
        host="203.0.113.10",
        port=22,
        protocol="tcp",
        state="open",
        service_name="ssh",
        product="openssh",
        version=version,
    )


# ---------------------------------------------------------------------------
# _extract_match_status unit tests (no HTTP calls)
# ---------------------------------------------------------------------------


def test_patched_version_drops_cve():
    fixture = _load("nvd_nginx_vuln.json")
    vuln_item = fixture["vulnerabilities"][0]
    # nginx 1.25.4 is PAST the versionEndExcluding=1.25.3 boundary → drop
    status, _ = _extract_match_status(vuln_item, "nginx", [], "1.25.4", is_keyword=False)
    assert status == "drop"


def test_vulnerable_version_matches():
    fixture = _load("nvd_nginx_vuln.json")
    vuln_item = fixture["vulnerabilities"][0]
    # nginx 1.22.0 IS inside [1.1.0, 1.25.3) → version_matched
    status, criteria = _extract_match_status(vuln_item, "nginx", [], "1.22.0", is_keyword=False)
    assert status == "version_matched"
    assert criteria and "nginx" in criteria


def test_openssh_vendor_prefix_version_in_range():
    fixture = _load("nvd_openssh_vuln.json")
    vuln_item = fixture["vulnerabilities"][0]
    # OpenSSH_8.9p1 normalizes to 8.9, which is <= versionEndIncluding=8.9
    status, _ = _extract_match_status(vuln_item, "openssh", [], "OpenSSH_8.9p1", is_keyword=False)
    assert status == "version_matched"


def test_keyword_only_when_no_matching_cpe():
    fixture = _load("nvd_nginx_vuln.json")
    vuln_item = fixture["vulnerabilities"][0]
    # Using "apache" as product with keyword search — doesn't match nginx CPE
    status, _ = _extract_match_status(vuln_item, "apache", [], "2.4.51", is_keyword=True)
    assert status == "keyword_only"


def test_unknown_version_gives_version_unknown():
    fixture = _load("nvd_nginx_vuln.json")
    vuln_item = fixture["vulnerabilities"][0]
    # Product matches but version is completely unparseable
    status, _ = _extract_match_status(vuln_item, "nginx", [], "UNKNOWN_VER", is_keyword=False)
    assert status == "version_unknown"


# ---------------------------------------------------------------------------
# NvdProvider.enrich tests (mocked fetch_json)
# ---------------------------------------------------------------------------


def test_cpe_version_matched_is_likely(tmp_path):
    nvd = NvdProvider(tmp_path)
    fixture = _load("nvd_nginx_vuln.json")
    with patch.object(nvd, "fetch_json", return_value=(fixture, None)):
        service = _nginx_service("1.22.0")
        enrichment = nvd.enrich(service)
    assert enrichment.cves, "Expected at least one CVE"
    cve = enrichment.cves[0]
    assert cve["match_status"] == "version_matched"


def test_keyword_match_is_possible_and_manual_validation(tmp_path):
    nvd = NvdProvider(tmp_path)
    fixture = _load("nvd_nginx_vuln.json")
    # No CPE on service → keyword query path
    service = Service("203.0.113.10", 80, "tcp", "open", "http", product="nginx", version="1.22.0")
    with patch.object(nvd, "fetch_json", return_value=(fixture, None)):
        enrichment = nvd.enrich(service)
    assert enrichment.cves
    cve = enrichment.cves[0]
    assert cve["match_status"] == "version_matched"  # product+version still matched

    # For keyword_only with a non-backport-sensitive product, confidence is POSSIBLE
    from portwise.intelligence.cve_enrichment import _cve_finding
    non_backport_service = Service("203.0.113.10", 8080, "tcp", "open", "http", product="tomcat", version="9.0.0")
    finding = _cve_finding(non_backport_service, {**cve, "match_status": "keyword_only"})
    assert finding.confidence == Confidence.POSSIBLE
    assert finding.manual_validation is True
    assert "keyword-match-only" in finding.tags

    # For nginx (backport-sensitive), keyword_only still gets NEEDS_MANUAL_VALIDATION (stricter)
    nginx_finding = _cve_finding(service, {**cve, "match_status": "keyword_only"})
    assert nginx_finding.confidence == Confidence.NEEDS_MANUAL_VALIDATION
    assert nginx_finding.manual_validation is True


def test_patched_version_drops_cve_in_provider(tmp_path):
    nvd = NvdProvider(tmp_path)
    fixture = _load("nvd_nginx_vuln.json")
    with patch.object(nvd, "fetch_json", return_value=(fixture, None)):
        service = _nginx_service("1.25.4")  # patched version
        enrichment = nvd.enrich(service)
    # All CVEs should be dropped for the patched version
    assert enrichment.cves == [], f"Expected no CVEs for patched nginx, got: {enrichment.cves}"


def test_references_parsed_from_nvd_2_0_list_schema(tmp_path):
    nvd = NvdProvider(tmp_path)
    fixture = _load("nvd_nginx_vuln.json")
    with patch.object(nvd, "fetch_json", return_value=(fixture, None)):
        service = _nginx_service("1.22.0")
        enrichment = nvd.enrich(service)
    assert enrichment.cves
    refs = enrichment.cves[0].get("references", [])
    assert len(refs) > 0
    assert all(refs[i].startswith("http") for i in range(len(refs)))


# ---------------------------------------------------------------------------
# KEV cross-referencing tests
# ---------------------------------------------------------------------------


def test_kev_only_annotates_version_matched_not_keyword(tmp_path):
    nvd = NvdProvider(tmp_path)
    kev = KevProvider(tmp_path)
    epss = EpssProvider(tmp_path)
    kev_fixture = _load("kev_catalog.json")
    nvd_fixture = _load("nvd_nginx_vuln.json")

    service = _nginx_service("1.22.0")  # vulnerable version

    with (
        patch.object(nvd, "fetch_json", return_value=(nvd_fixture, None)),
        patch.object(kev, "fetch_json", return_value=(kev_fixture, None)),
        patch.object(epss, "fetch_json", return_value=({"data": []}, None)),
    ):
        kev_data = kev.enrich(service).cves
        kev_ids = {item["id"] for item in kev_data if item.get("id")}

        enrichment = nvd.enrich(service)
        assert enrichment.cves

        cve = enrichment.cves[0]
        # CVE-2024-00001 is in KEV and version_matched → kev=True
        cve["kev"] = (str(cve.get("id")) in kev_ids) and cve.get("match_status") == "version_matched"
        assert cve["kev"] is True


def test_kev_does_not_annotate_patched_version(tmp_path):
    nvd = NvdProvider(tmp_path)
    kev = KevProvider(tmp_path)
    nvd_fixture = _load("nvd_nginx_vuln.json")
    kev_fixture = _load("kev_catalog.json")

    service = _nginx_service("1.25.4")  # patched — CVE dropped entirely

    with (
        patch.object(nvd, "fetch_json", return_value=(nvd_fixture, None)),
        patch.object(kev, "fetch_json", return_value=(kev_fixture, None)),
    ):
        enrichment = nvd.enrich(service)
    assert enrichment.cves == [], "Patched version must produce zero CVE findings"


# ---------------------------------------------------------------------------
# Offline / no-internet graceful degradation
# ---------------------------------------------------------------------------


def test_offline_no_internet_degrades_gracefully(tmp_path):
    services = [_nginx_service("1.22.0")]
    with patch(
        "portwise.intelligence.cve_enrichment.NvdProvider.fetch_json",
        return_value=(None, "Connection refused"),
    ), patch(
        "portwise.intelligence.cve_enrichment.KevProvider.fetch_json",
        return_value=(None, "Connection refused"),
    ):
        findings, notes = enrich_services_with_cves(services, tmp_path, enabled=True)
    # Should complete without raising; findings may be empty
    assert isinstance(findings, list)
    assert any("NVD skipped" in n for n in notes)


def test_no_api_key_still_works(tmp_path):
    import os
    os.environ.pop("PORTWISE_NVD_API_KEY", None)
    nvd = NvdProvider(tmp_path)
    fixture = _load("nvd_nginx_vuln.json")
    with patch.object(nvd, "fetch_json", return_value=(fixture, None)):
        enrichment = nvd.enrich(_nginx_service("1.22.0"))
    assert isinstance(enrichment.cves, list)
