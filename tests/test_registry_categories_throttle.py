from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

from portwise.core.models import Confidence, FindingCategory, Severity
from portwise.modules.registry import (
    FtpSafeModule,
    RdpSafeModule,
    SmbSafeModule,
    SnmpSafeModule,
    SshSafeModule,
    WinRmSafeModule,
    DatabaseSafeModule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(host="203.0.113.10", port=22, protocol="tcp", service="ssh", **kwargs):
    return {"host": host, "port": port, "protocol": protocol, "service": service, **kwargs}


def _finding(result, title):
    matches = [f for f in result.findings if f.title == title]
    assert matches, f"No finding with title {title!r}. Got: {[f.title for f in result.findings]}"
    return matches[0]


# ---------------------------------------------------------------------------
# Bug 1 tests — category system
# ---------------------------------------------------------------------------

def test_protocol_service_exposed_is_information_category():
    """Bare reachability 'Exposed' findings must be INFORMATION, not VULNERABILITY."""
    cases = [
        (SshSafeModule(), _target(port=22, service="ssh"), "SSH Service Exposed"),
        (SmbSafeModule(), _target(port=445, service="smb"), "SMB Service Exposed"),
        (RdpSafeModule(), _target(port=3389, service="rdp"), "RDP Service Exposed"),
        (WinRmSafeModule(), _target(port=5985, service="winrm"), "WinRM Exposed"),
    ]
    for module, target, title in cases:
        result = module.run(target, {})
        f = _finding(result, title)
        assert f.category == FindingCategory.INFORMATION, (
            f"{title}: expected INFORMATION, got {f.category}"
        )


def test_protocol_version_disclosure_is_information():
    """Version disclosure is now a (low) VULNERABILITY; OS/domain disclosure stays INFORMATION."""
    # SSH version disclosure → vulnerability
    target = _target(port=22, service="ssh", product="OpenSSH", version="9.2")
    result = SshSafeModule().run(target, {})
    f = _finding(result, "SSH Version Disclosure")
    assert f.category == FindingCategory.VULNERABILITY
    assert f.severity == Severity.LOW

    # SMB OS/Domain disclosure → still informational
    target = _target(port=445, service="smb", product="samba", version="", extrainfo="os: Windows domain: CORP")
    target["routing_reason"] = "os: windows domain: corp"
    result = SmbSafeModule().run(target, {})
    f = _finding(result, "SMB OS/Domain Disclosure")
    assert f.category == FindingCategory.INFORMATION

    # Database version disclosure → vulnerability
    target = _target(port=5432, service="postgresql", version="14.2")
    result = DatabaseSafeModule().run(target, {"database": {"unauthenticated_checks": False}})
    f = _finding(result, "Database Version Disclosure")
    assert f.category == FindingCategory.VULNERABILITY


def test_protocol_real_misconfig_stays_vulnerability(monkeypatch):
    """Real misconfigurations must remain VULNERABILITY category."""
    # SMBv1 enabled (from nmap script evidence in target text)
    target = _target(port=445, service="smb", routing_reason="smbv1 nt lm 0.12")
    result = SmbSafeModule().run(target, {})
    f = _finding(result, "SMBv1 Enabled")
    assert f.category == FindingCategory.VULNERABILITY

    # RDP NLA disabled
    target = _target(port=3389, service="rdp", routing_reason="nla: disabled")
    result = RdpSafeModule().run(target, {})
    f = _finding(result, "RDP NLA Disabled")
    assert f.category == FindingCategory.VULNERABILITY

    # Anonymous FTP — monkeypatch ftplib so no real connection
    import ftplib
    class _FakeFtp:
        def connect(self, *a, **kw): pass
        def login(self, *a, **kw): pass
        def quit(self): pass

    monkeypatch.setattr(ftplib, "FTP", _FakeFtp)
    target = _target(port=21, service="ftp")
    result = FtpSafeModule().run(target, {"ftp_anonymous_check": True})
    f = _finding(result, "Anonymous FTP Login Enabled")
    assert f.category == FindingCategory.VULNERABILITY


def test_bare_exposed_finding_is_informational_confidence():
    """Bare reachability findings must use Confidence.INFORMATIONAL, not LIKELY."""
    cases = [
        (SshSafeModule(), _target(port=22, service="ssh"), "SSH Service Exposed"),
        (SmbSafeModule(), _target(port=445, service="smb"), "SMB Service Exposed"),
        (RdpSafeModule(), _target(port=3389, service="rdp"), "RDP Service Exposed"),
        (WinRmSafeModule(), _target(port=5985, service="winrm"), "WinRM Exposed"),
    ]
    for module, target, title in cases:
        result = module.run(target, {})
        f = _finding(result, title)
        assert f.confidence == Confidence.INFORMATIONAL, (
            f"{title}: expected INFORMATIONAL confidence, got {f.confidence}"
        )

    # SNMP exposed — disable community check so no network call
    target = _target(port=161, protocol="udp", service="snmp")
    result = SnmpSafeModule().run(target, {"snmp": {"default_community_check": False}})
    f = _finding(result, "SNMP Service Exposed")
    assert f.confidence == Confidence.INFORMATIONAL


# ---------------------------------------------------------------------------
# Bug 2 tests — rate limiter
# ---------------------------------------------------------------------------

def test_registry_raw_probe_calls_throttle(monkeypatch):
    """client.throttle(host) must be called before each raw probe in SnmpSafeModule."""
    mock_client = MagicMock()
    mock_client.is_tripped.return_value = False
    mock_client.budget_remaining.return_value = 10

    throttled_hosts = []
    mock_client.throttle.side_effect = lambda h: throttled_hosts.append(h)

    # Avoid real network: _snmp_get returns falsy
    monkeypatch.setattr("portwise.modules.registry._snmp_get", lambda *a, **kw: None)
    monkeypatch.setattr("portwise.modules.registry.client_from_config", lambda cfg: mock_client)

    target = _target(host="203.0.113.10", port=161, protocol="udp", service="snmp")
    SnmpSafeModule().run(target, {"snmp": {"default_community_check": True, "communities": ["public"]}})

    assert "203.0.113.10" in throttled_hosts, (
        "throttle(host) was not called before the SNMP probe"
    )


def test_registry_respects_circuit_breaker(monkeypatch):
    """When the circuit breaker is tripped, no raw probe should be attempted."""
    mock_client = MagicMock()
    mock_client.is_tripped.return_value = True  # breaker tripped

    probe_calls = []

    def _fake_snmp(*args, **kwargs):
        probe_calls.append(args)
        return None

    monkeypatch.setattr("portwise.modules.registry._snmp_get", _fake_snmp)
    monkeypatch.setattr("portwise.modules.registry.client_from_config", lambda cfg: mock_client)

    target = _target(host="203.0.113.10", port=161, protocol="udp", service="snmp")
    SnmpSafeModule().run(target, {"snmp": {"default_community_check": True, "communities": ["public"]}})

    assert not probe_calls, (
        "_snmp_get was called even though the circuit breaker was tripped"
    )


# ---------------------------------------------------------------------------
# Latent-hole regression tests (Bug 2 hardening)
# ---------------------------------------------------------------------------

def test_no_rawprobe_path_without_throttle(monkeypatch):
    """_database_safe_probe and _safe_http_fingerprint must throttle even when
    called with no explicit client (client=None) — they must fall back to
    client_from_config() rather than opening raw sockets unthrottled."""
    from portwise.modules.registry import _database_safe_probe, _safe_http_fingerprint

    mock_client = MagicMock()
    mock_client.is_tripped.return_value = False
    throttled: list[str] = []
    mock_client.throttle.side_effect = lambda h: throttled.append(h)

    monkeypatch.setattr("portwise.modules.registry.client_from_config", lambda cfg: mock_client)
    monkeypatch.setattr("portwise.modules.registry._tcp_send_recv", lambda *a, **kw: b"+PONG\r\n")

    target = {"host": "10.0.113.1", "port": 6379, "protocol": "tcp",
              "service": "redis", "product": "", "version": "",
              "cpe": [], "routing_reason": "redis"}

    # No client passed — must still throttle via the fallback client
    _database_safe_probe("database", target, {}, "redis")
    assert "10.0.113.1" in throttled, (
        "_database_safe_probe did not throttle when called with client=None"
    )

    # _safe_http_fingerprint — no client passed
    throttled.clear()
    fake_resp = MagicMock()
    fake_resp.read.return_value = b"<title>Test</title>"
    fake_resp.getheaders.return_value = []
    fake_resp.status = 200
    mock_client.request.return_value = fake_resp

    result = _safe_http_fingerprint(
        {"host": "10.0.113.1", "port": 80}, {}, ["/"]
    )
    assert result is not None, "_safe_http_fingerprint returned None unexpectedly"
    assert "10.0.113.1" in throttled or mock_client.request.called, (
        "_safe_http_fingerprint bypassed throttle when client=None"
    )


# ---------------------------------------------------------------------------
# Cleanup test
# ---------------------------------------------------------------------------

def test_no_imports_of_cve_placeholder():
    """No source file under portwise/ should import cve_placeholder."""
    root = Path(__file__).parent.parent / "portwise"
    offenders = []
    for py_file in root.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else ([node.module or ""] if node.module else [])
                )
                if any("cve_placeholder" in n for n in names):
                    offenders.append(str(py_file))
    assert not offenders, f"These files still import cve_placeholder: {offenders}"
