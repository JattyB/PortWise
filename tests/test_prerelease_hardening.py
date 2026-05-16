from pathlib import Path

from portwise.intelligence.importers import import_nessus_csv, import_testssl_json
from portwise.modules import registry
from portwise.modules.registry import (
    DatabaseSafeModule,
    DevOpsAdminModule,
    DnsSafeModule,
    KubernetesContainerModule,
    MailSafeModule,
    NtpSafeModule,
    SnmpSafeModule,
    VpnApplianceModule,
)
from portwise.reporting.retest import write_retest_report


def target(service: str, port: int, product: str = "") -> dict:
    return {"host": "192.0.2.10", "port": port, "protocol": "tcp", "service": service, "product": product, "version": "1.0", "cpe": [], "routing_reason": "test"}


def test_dns_module_recursion_and_zone_transfer(monkeypatch) -> None:
    monkeypatch.setattr(registry, "_dns_query", lambda *a, **k: {"ra": True, "ancount": 1})
    monkeypatch.setattr(registry, "_dns_chaos_version", lambda *a, **k: "BIND 9")
    monkeypatch.setattr(registry, "_dns_axfr_check", lambda *a, **k: True)
    result = DnsSafeModule().execute(target("domain", 53), {"dns": {"zones": ["example.com"]}})
    titles = {finding.title for finding in result.findings}
    assert "DNS Recursion Enabled" in titles
    assert "DNS Version Disclosure" in titles
    assert "DNS Zone Transfer Allowed" in titles


def test_snmp_module_default_community(monkeypatch) -> None:
    monkeypatch.setattr(registry, "_snmp_get", lambda *a, **k: "sysDescr test")
    result = SnmpSafeModule().execute(target("snmp", 161), {"snmp": {"communities": ["public", "private"]}})
    assert any(f.title == "Default SNMP Community Accepted" for f in result.findings)


def test_ntp_module_response(monkeypatch) -> None:
    monkeypatch.setattr(registry, "_ntp_request", lambda *a, **k: {"stratum": 2, "version": 4})
    result = NtpSafeModule().execute(target("ntp", 123), {})
    assert any(f.title == "NTP Information Disclosure" for f in result.findings)


def test_database_module_redis_probe(monkeypatch) -> None:
    monkeypatch.setattr(registry, "_tcp_send_recv", lambda *a, **k: b"+PONG\r\n")
    result = DatabaseSafeModule().execute(target("redis", 6379, "Redis"), {"database": {"unauthenticated_checks": True}})
    assert any(f.title == "Unauthenticated Redis Access" for f in result.findings)


def test_devops_and_kubernetes_http_fingerprint(monkeypatch) -> None:
    monkeypatch.setattr(registry, "_safe_http_fingerprint", lambda *a, **k: (200, "Jenkins", "anonymous ready", "http://192.0.2.10:8080/"))
    devops = DevOpsAdminModule().execute(target("http", 8080, "Jenkins"), {})
    k8s = KubernetesContainerModule().execute(target("https", 6443, "Kubernetes"), {})
    assert any(f.title == "Anonymous Access Possible" for f in devops.findings)
    assert any(f.title == "Kubernetes API Exposed" for f in k8s.findings)


def test_mail_module_smtp_checks(monkeypatch) -> None:
    monkeypatch.setattr(registry, "_smtp_safe_check", lambda *a, **k: ("Postfix", {"starttls": False, "vrfy": True, "expn": True}))
    result = MailSafeModule().execute(target("smtp", 25, "Postfix"), {})
    titles = {finding.title for finding in result.findings}
    assert "SMTP STARTTLS Missing" in titles
    assert "VRFY Enabled" in titles
    assert "EXPN Enabled" in titles


def test_vpn_module_fingerprint() -> None:
    result = VpnApplianceModule().execute(target("https", 443, "Fortinet FortiGate VPN"), {})
    assert any(f.title == "VPN Interface Exposed" for f in result.findings)
    assert any(f.title == "Needs Owner Validation" for f in result.findings)


def test_importers_parse_basic_files(tmp_path: Path) -> None:
    testssl_dir = tmp_path / "testssl"
    testssl_dir.mkdir()
    (testssl_dir / "result.json").write_text('[{"id":"TLS_1_0","severity":"HIGH","host":"192.0.2.10","port":443,"finding":"TLS 1.0 supported"}]', encoding="utf-8")
    nessus = tmp_path / "nessus.csv"
    nessus.write_text("Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also\n1,CVE-2099-0001,7.5,High,192.0.2.10,tcp,443,Test Finding,Syn,Desc,Fix,https://example.com\n", encoding="utf-8")
    testssl_findings, testssl_notes = import_testssl_json(testssl_dir)
    nessus_findings, nessus_notes = import_nessus_csv(nessus)
    assert not testssl_notes
    assert not nessus_notes
    assert testssl_findings[0].module == "testssl-import"
    assert nessus_findings[0].cve_id == "CVE-2099-0001"


def test_retest_excel_has_status_sheets(tmp_path: Path) -> None:
    previous = tmp_path / "old.json"
    current = tmp_path / "new.json"
    previous.write_text('{"assets":[],"findings":[{"title":"Old","asset":"192.0.2.10","port":80}]}', encoding="utf-8")
    current.write_text('{"assets":[],"findings":[{"title":"New","asset":"192.0.2.10","port":443}]}', encoding="utf-8")
    written = write_retest_report(previous, current, tmp_path, "all")
    assert any(path.name == "PortWise_Retest.json" for path in written)
    assert any(path.name == "PortWise_Retest.xlsx" for path in written)
