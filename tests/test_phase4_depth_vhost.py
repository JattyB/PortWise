from __future__ import annotations

from unittest.mock import patch

from portwise.core.models import Confidence, FindingCategory, Severity
from portwise.modules import registry
from portwise.modules.registry import (
    HttpModule,
    NtpSafeModule,
    SnmpSafeModule,
    TlsModule,
    VpnApplianceModule,
    WinRmSafeModule,
    _ber_int,
    _ber_len,
    _snmp_extract_value,
    _snmp_response_error_status,
    _target_hostname,
)
from portwise.utils.http_client import PoliteHttpClient, PolitenessConfig

# Fast, no-delay client config for module tests.
_FAST = {"http_politeness": {"min_delay_seconds": 0, "jitter_seconds": [0, 0]}}


def _ntp_target():
    return {"host": "10.0.0.1", "port": 123, "protocol": "udp", "service": "ntp", "scripts": {}}


# ---------------------------------------------------------------------------
# NTP mode-6 + monlist
# ---------------------------------------------------------------------------

def test_ntp_mode6_enabled():
    with patch.object(registry, "_ntp_request", return_value=None), \
         patch.object(registry, "_ntp_mode6_readvar", return_value="version=ntpd 4.2.8"), \
         patch.object(registry, "_ntp_monlist", return_value=None):
        result = NtpSafeModule().run(_ntp_target(), _FAST)
    f = [x for x in result.findings if "Mode 6" in x.title]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].category == FindingCategory.VULNERABILITY


def test_ntp_monlist_cve():
    with patch.object(registry, "_ntp_request", return_value=None), \
         patch.object(registry, "_ntp_mode6_readvar", return_value=None), \
         patch.object(registry, "_ntp_monlist", return_value=468):
        result = NtpSafeModule().run(_ntp_target(), _FAST)
    f = [x for x in result.findings if "monlist" in x.title.lower()]
    assert f and f[0].severity == Severity.HIGH
    assert f[0].cve_id == "CVE-2013-5211"


# ---------------------------------------------------------------------------
# WinRM auth-method enumeration
# ---------------------------------------------------------------------------

def test_winrm_basic_over_cleartext_high():
    target = {"host": "10.0.0.1", "port": 5985, "protocol": "tcp", "service": "winrm"}
    with patch.object(registry, "_winrm_auth_methods", return_value=["Negotiate", "Kerberos", "Basic"]):
        result = WinRmSafeModule().run(target, _FAST)
    titles = [f.title for f in result.findings]
    assert any("Authentication Methods Disclosed" in t for t in titles)
    basic = [f for f in result.findings if "Cleartext" in f.title]
    assert basic and basic[0].severity == Severity.HIGH


def test_winrm_basic_over_tls_medium():
    target = {"host": "10.0.0.1", "port": 5986, "protocol": "tcp", "service": "winrm"}
    with patch.object(registry, "_winrm_auth_methods", return_value=["Negotiate", "Basic"]):
        result = WinRmSafeModule().run(target, _FAST)
    basic = [f for f in result.findings if f.title == "WinRM Basic Authentication Enabled"]
    assert basic and basic[0].severity == Severity.MEDIUM


def test_winrm_no_basic_only_methods():
    target = {"host": "10.0.0.1", "port": 5985, "protocol": "tcp", "service": "winrm"}
    with patch.object(registry, "_winrm_auth_methods", return_value=["Negotiate", "Kerberos"]):
        result = WinRmSafeModule().run(target, _FAST)
    assert not any("Basic" in f.title for f in result.findings)


# ---------------------------------------------------------------------------
# VPN portal exposure
# ---------------------------------------------------------------------------

def test_vpn_fortinet_portal_exposed():
    target = {"host": "10.0.0.1", "port": 443, "protocol": "tcp", "service": "https",
              "product": "FortiGate", "version": "", "cpe": [], "routing_reason": "fortinet", "scripts": {}}
    with patch.object(registry, "_safe_http_fingerprint", return_value=(200, "", "FortiGate SSL VPN", "https://10.0.0.1:443/remote/login")):
        result = VpnApplianceModule().run(target, {**_FAST, "context": "external"})
    portals = [f for f in result.findings if "SSL-VPN Login Portal" in f.title]
    assert portals
    assert "Fortinet" in portals[0].title
    assert portals[0].severity == Severity.HIGH  # external context


# ---------------------------------------------------------------------------
# SNMP write community (gated)
# ---------------------------------------------------------------------------

def _snmp_target():
    return {"host": "10.0.0.1", "port": 161, "protocol": "udp", "service": "snmp",
            "product": "", "version": "", "cpe": [], "routing_reason": "", "scripts": {}}


def test_snmp_write_community_critical_when_enabled_full():
    config = {**_FAST, "validation_level": "full", "snmp_default_community_check": False,
              "snmp": {"default_community_check": False, "write_check": True, "communities": ["private"]}}
    with patch.object(registry, "_snmp_write_community_check", return_value=True):
        result = SnmpSafeModule().run(_snmp_target(), config)
    write = [f for f in result.findings if "Write Community" in f.title]
    assert write and write[0].severity == Severity.CRITICAL


def test_snmp_write_check_gated_off_at_recon():
    config = {**_FAST, "validation_level": "recon", "snmp_default_community_check": False,
              "snmp": {"default_community_check": False, "write_check": True, "communities": ["private"]}}
    with patch.object(registry, "_snmp_write_community_check", return_value=True) as probe:
        result = SnmpSafeModule().run(_snmp_target(), config)
    assert not any("Write Community" in f.title for f in result.findings)
    probe.assert_not_called()


# ---------------------------------------------------------------------------
# SNMP BER encoder/decoder helpers
# ---------------------------------------------------------------------------

def test_ber_len_short_and_long():
    assert _ber_len(5) == b"\x05"
    assert _ber_len(200) == b"\x81\xc8"
    assert _ber_len(300) == b"\x82\x01\x2c"


def test_ber_int():
    assert _ber_int(0) == b"\x02\x01\x00"
    assert _ber_int(127) == b"\x02\x01\x7f"
    assert _ber_int(128) == b"\x02\x02\x00\x80"  # high bit -> pad


def test_snmp_extract_value_finds_octet_string():
    oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00"
    value = b"\x04\x06router"  # OCTET STRING "router"
    data = b"\x30\x10" + oid + value
    extracted = _snmp_extract_value(data, oid)
    assert extracted == value


def test_snmp_response_error_status():
    # Response PDU 0xA2: request-id=1, error-status=0, error-index=0, empty varbinds
    pdu = b"\xa2\x0b" + b"\x02\x01\x01" + b"\x02\x01\x00" + b"\x02\x01\x00" + b"\x30\x00"
    assert _snmp_response_error_status(pdu) == 0
    pdu_err = b"\xa2\x0b" + b"\x02\x01\x01" + b"\x02\x01\x05" + b"\x02\x01\x00" + b"\x30\x00"
    assert _snmp_response_error_status(pdu_err) == 5


# ---------------------------------------------------------------------------
# vhost / SNI
# ---------------------------------------------------------------------------

def test_target_hostname_only_when_different_from_ip():
    assert _target_hostname({"host": "10.0.0.1", "hostname": "site.example.com"}) == "site.example.com"
    assert _target_hostname({"host": "10.0.0.1", "hostname": "10.0.0.1"}) is None
    assert _target_hostname({"host": "10.0.0.1", "hostname": ""}) is None
    assert _target_hostname({"host": "10.0.0.1"}) is None


def test_http_client_sends_vhost_host_header_and_sni(monkeypatch):
    client = PoliteHttpClient(PolitenessConfig(min_delay=0, jitter_min=0, jitter_max=0))
    client.vhost = "vhost.example.com"
    client.sni = "vhost.example.com"
    captured: dict = {}

    def fake_do(host, port, method, path, tls, headers, timeout, sni=None, body=None):
        captured["headers"] = headers
        captured["sni"] = sni
        captured["connect_host"] = host
        return 200, [("Content-Type", "text/html")], b"ok"

    monkeypatch.setattr(client, "_do_request", fake_do)
    client.request("203.0.113.5", 443, "GET", "/", True)
    assert captured["headers"]["Host"] == "vhost.example.com"
    assert captured["sni"] == "vhost.example.com"
    assert captured["connect_host"] == "203.0.113.5"  # still connects to the IP


def test_do_request_routes_to_sni_path(monkeypatch):
    client = PoliteHttpClient(PolitenessConfig(min_delay=0, jitter_min=0, jitter_max=0))
    called: dict = {}
    monkeypatch.setattr(client, "_do_request_sni", lambda *a, **k: called.setdefault("hit", True) or (200, [], b""))
    client._do_request("203.0.113.5", 443, "GET", "/", True, {}, 5.0, sni="x.example.com")
    assert called.get("hit") is True


def test_tls_module_threads_hostname_into_sni(monkeypatch):
    captured: dict = {}

    class _FakeEngine:
        def __init__(self, *a, **k):
            captured["client"] = k.get("http_client")

        def run(self, service):
            captured["service"] = service
            return []

    monkeypatch.setattr(registry, "TlsEngine", _FakeEngine)
    target = {"host": "10.0.0.1", "port": 443, "protocol": "tcp", "service": "https", "hostname": "site.example.com"}
    TlsModule().run(target, _FAST)
    assert captured["client"].sni == "site.example.com"
    assert captured["service"].hostname == "site.example.com"


def test_http_module_threads_hostname_into_vhost(monkeypatch):
    captured: dict = {}

    class _FakeEngine:
        def __init__(self, *a, **k):
            captured["client"] = k.get("client")

        def run(self, service, config=None):
            captured["service"] = service
            return []

    monkeypatch.setattr(registry, "HttpEngine", _FakeEngine)
    target = {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "service": "http", "hostname": "site.example.com"}
    HttpModule().run(target, _FAST)
    assert captured["client"].vhost == "site.example.com"
