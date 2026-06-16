from __future__ import annotations

from pathlib import Path


from portwise.scanners.nmap_parser import parse_nmap_xml
from portwise.scanners.nse import (
    nse_dns_recursion,
    nse_ftp_anon,
    nse_http_methods,
    nse_rdp_ntlm,
    nse_smb_os,
    nse_smb_security,
    nse_snmp_info,
    nse_ssh_algos,
    nse_ssl_cert,
    nse_ssl_ciphers,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _service(fixture: str, port: int = 443):
    assets = parse_nmap_xml(FIXTURES / fixture)
    assert assets, f"No assets parsed from {fixture}"
    for asset in assets:
        for svc in asset.services:
            if svc.port == port:
                return svc
    raise AssertionError(f"Port {port} not found in {fixture}")


# ---------------------------------------------------------------------------
# test_parse_nested_script_tables
# ---------------------------------------------------------------------------

def test_parse_nested_script_tables():
    svc = _service("nmap_nse_ssl.xml", 443)
    # scripts dict must use new format
    assert "ssl-cert" in svc.scripts
    entry = svc.scripts["ssl-cert"]
    assert isinstance(entry, dict)
    assert "output" in entry
    assert "data" in entry
    data = entry["data"]
    assert isinstance(data, dict)
    assert "subject" in data or "issuer" in data


def test_service_scripts_backward_compat_str_access():
    svc = _service("nmap_nse_ssl.xml", 443)
    # script_text() must return a string regardless of internal structure
    text = svc.script_text("ssl-cert")
    assert isinstance(text, str)
    assert len(text) > 0
    # script_data() must return structured data
    data = svc.script_data("ssl-cert")
    assert data is not None
    # Missing script returns empty string / None gracefully
    assert svc.script_text("nonexistent-script") == ""
    assert svc.script_data("nonexistent-script") is None


# ---------------------------------------------------------------------------
# test_ssl_ciphers_extracts_weak_suites
# ---------------------------------------------------------------------------

def test_ssl_ciphers_extracts_weak_suites():
    svc = _service("nmap_nse_ssl.xml", 443)
    ciphers = nse_ssl_ciphers(svc)
    assert "TLSv1.2" in ciphers
    suite_names = [c["name"] for c in ciphers["TLSv1.2"]]
    assert "TLS_RSA_WITH_RC4_128_SHA" in suite_names
    # Strength C indicates weak
    rc4 = next(c for c in ciphers["TLSv1.2"] if "RC4" in c["name"])
    assert rc4["strength"] == "C"


# ---------------------------------------------------------------------------
# test_ssl_cert_sha1_signature_detected
# ---------------------------------------------------------------------------

def test_ssl_cert_sha1_signature_detected():
    svc = _service("nmap_nse_ssl.xml", 443)
    cert = nse_ssl_cert(svc)
    assert cert, "ssl-cert data should be present"
    assert "sha1" in cert.get("sig_alg", "").lower(), f"Expected SHA1 signature, got: {cert.get('sig_alg')}"


# ---------------------------------------------------------------------------
# test_ssh_algos_flags_weak_kex
# ---------------------------------------------------------------------------

def test_ssh_algos_flags_weak_kex():
    svc = _service("nmap_nse_ssh.xml", 22)
    algos = nse_ssh_algos(svc)
    assert "kex" in algos
    assert "diffie-hellman-group1-sha1" in algos["kex"]
    assert "encryption" in algos
    assert "aes128-cbc" in algos["encryption"]
    assert "mac" in algos
    assert "hmac-md5" in algos["mac"]
    assert "hostkey" in algos
    assert "ssh-dss" in algos["hostkey"]


# ---------------------------------------------------------------------------
# test_smb_security_structured_beats_substring
# ---------------------------------------------------------------------------

def test_smb_security_structured_beats_substring():
    svc = _service("nmap_nse_smb.xml", 445)
    smb_sec = nse_smb_security(svc)
    # Should detect signing state from structured data
    assert smb_sec.get("signing") in ("not_required", "disabled"), f"Got: {smb_sec}"
    # Should detect SMBv1 from smb-security-mode
    assert smb_sec.get("smbv1") is True

    smb_os = nse_smb_os(svc)
    assert smb_os.get("os") == "Windows Server 2012 R2"
    assert smb_os.get("computer_name") == "DC01"
    assert smb_os.get("domain") == "CORP.LOCAL"


# ---------------------------------------------------------------------------
# test_missing_script_returns_empty_gracefully
# ---------------------------------------------------------------------------

def test_missing_script_returns_empty_gracefully():
    # Service with no scripts at all
    from portwise.core.models import Service
    svc = Service(host="1.2.3.4", port=80, protocol="tcp", state="open")
    assert nse_ssl_ciphers(svc) == {}
    assert nse_ssh_algos(svc) == {}
    assert nse_smb_security(svc) == {}
    assert nse_smb_os(svc) == {}
    assert nse_rdp_ntlm(svc) == {}
    assert nse_ftp_anon(svc) is False
    assert nse_http_methods(svc) == []
    assert nse_dns_recursion(svc) is False
    assert nse_snmp_info(svc) == {}
    assert nse_ssl_cert(svc) == {}

    # Target dict with no scripts key
    target: dict = {"host": "1.2.3.4", "port": 80}
    assert nse_ssl_ciphers(target) == {}
    assert nse_ssh_algos(target) == {}
