import zipfile
from pathlib import Path

from portwise.cli import main
from portwise.core.models import Asset, Service, Severity
from portwise.core.module_runner import execute_safe_modules
from portwise.core.routing import route_assets
from portwise.intelligence.cve_enrichment import LocalCveProvider, NvdProvider, enrich_services_with_cves
from portwise.intelligence.false_positive import apply_false_positive_rules
from portwise.intelligence.risk_scoring import assign_priority
from portwise.modules.registry import ExposureModule, SshSafeModule
from portwise.modules.tls.tls_engine import TlsEngine
from portwise.reporting.excel_report import write_excel_report
from portwise.reporting.html_report import write_html_report
from portwise.reporting.retest import compare_runs


def test_module_base_execution_and_exposure_scoring() -> None:
    target = {"host": "203.0.113.10", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH"}
    result = ExposureModule().execute(target, {"context": "external", "internet_facing": True})
    assert not result.errors
    assert result.findings
    assert result.findings[0].severity in {Severity.MEDIUM, Severity.HIGH}


def test_safe_module_runner_dry_run() -> None:
    asset = Asset(ip="203.0.113.10", services=[Service(host="203.0.113.10", port=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH")])
    routes = route_assets([asset])
    module_results, findings = execute_safe_modules(routes, config={"context": "external"}, enabled_modules={"ssh": True}, dry_run=True)
    assert findings == []
    assert any(result.module_name == "ssh" and result.skipped_reason for result in module_results)


def test_ssh_safe_module_version_disclosure() -> None:
    target = {"host": "203.0.113.10", "port": 2222, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.2"}
    result = SshSafeModule().execute(target, {})
    assert any(f.title == "SSH Version Disclosure" for f in result.findings)


def test_tls_hsts_policy_parser() -> None:
    assert TlsEngine._hsts_max_age("max-age=31536000; includeSubDomains") == 31536000
    assert TlsEngine._hsts_max_age("includeSubDomains") is None


def test_cve_provider_parsing_with_mocked_json(tmp_path: Path, monkeypatch) -> None:
    def fake_fetch(self, url, headers=None, cache_key=None):
        return {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-0001",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    "references": {"referenceData": [{"url": "https://example.com/cve"}]},
                }
            }]
        }, None

    monkeypatch.setattr(NvdProvider, "fetch_json", fake_fetch)
    service = Service(host="203.0.113.10", port=443, protocol="tcp", state="open", service_name="https", product="nginx", version="1.24.0", cpes=["cpe:/a:nginx:nginx:1.24.0"])
    enrichment = NvdProvider(tmp_path).enrich(service)
    assert enrichment.cves[0]["id"] == "CVE-2099-0001"
    assert enrichment.cves[0]["cvss"] == 9.8


def test_cve_enrichment_findings_with_mocked_providers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(LocalCveProvider, "enrich", lambda self, service: type("E", (), {"cves": [{"id": "CVE-2099-0002", "cvss": 7.5, "matched_cpe": "cpe:/a:test:test:1", "match_status": "version_matched", "references": []}], "provider_notes": []})())
    service = Service(host="203.0.113.10", port=80, protocol="tcp", state="open", service_name="http", product="test", version="1", cpes=["cpe:/a:test:test:1"])
    findings, notes = enrich_services_with_cves([service], tmp_path)
    assert notes == [] or isinstance(notes, list)
    assert findings[0].cve_id == "CVE-2099-0002"


def test_false_positive_and_priority_integration() -> None:
    from portwise.core.models import Finding

    finding = Finding(title="nginx version CVE", severity=Severity.HIGH, asset="203.0.113.10", description="version banner", tags=["banner-only"])
    apply_false_positive_rules(finding, context="external")
    assign_priority(finding, context="external", internet_facing=True)
    assert finding.manual_validation is False
    assert finding.priority in {"P2", "P3"}


def test_excel_and_html_report_creation(tmp_path: Path) -> None:
    data = {"project": "PortWise", "profile": "test", "findings": [{"title": "Test", "severity": "high", "confidence": "Likely", "priority": "P2"}], "metadata": {"state": {}}}
    xlsx = write_excel_report(data, tmp_path / "PortWise_Report.xlsx")
    html = write_html_report(data, tmp_path / "PortWise_Report.html")
    assert xlsx.exists()
    assert zipfile.is_zipfile(xlsx)
    assert "<html" in html.read_text(encoding="utf-8")


def test_excel_report_sanitizes_binary_evidence(tmp_path: Path) -> None:
    data = {
        "findings": [{
            "title": "DNS Version Disclosure",
            "description": "version.bind response: \x07version\x04bind",
            "evidence": [],
        }],
        "assets": [],
        "metadata": {"state": {}},
    }
    xlsx = write_excel_report(data, tmp_path / "binary-evidence.xlsx")
    assert xlsx.exists()


def test_retest_comparison() -> None:
    old = {"assets": [{"services": [{"host": "203.0.113.10", "port": 80, "protocol": "tcp", "service_name": "http"}]}], "findings": [{"title": "A", "asset": "203.0.113.10", "port": 80}]}
    new = {"assets": [{"services": [{"host": "203.0.113.10", "port": 443, "protocol": "tcp", "service_name": "https"}]}], "findings": [{"title": "B", "asset": "203.0.113.10", "port": 443}]}
    result = compare_runs(old, new)
    assert result["findings"]["Fixed"]
    assert result["findings"]["New"]


def test_cli_help_and_modules(capsys) -> None:
    assert main(["modules"]) == 0
    output = capsys.readouterr().out
    assert "http" in output
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
