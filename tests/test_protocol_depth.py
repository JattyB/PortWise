from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


from portwise.core.models import Confidence, FindingCategory, Severity
from portwise.modules.registry import (
    DatabaseSafeModule,
    RdpSafeModule,
    SmbSafeModule,
    SshSafeModule,
    SnmpSafeModule,
)
from portwise.scanners.nmap_parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"

_CONFIG: dict = {}


def _target_from_fixture(fixture: str, port: int) -> dict:
    assets = parse_nmap_xml(FIXTURES / fixture)
    assert assets, f"No assets from {fixture}"
    for asset in assets:
        for svc in asset.services:
            if svc.port == port:
                return {
                    "host": svc.host,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service": svc.service_name,
                    "product": svc.product,
                    "version": svc.version,
                    "cpe": svc.cpes,
                    "routing_reason": "",
                    "scripts": svc.scripts,
                }
    raise AssertionError(f"Port {port} not found in {fixture}")


# ---------------------------------------------------------------------------
# SMB depth tests
# ---------------------------------------------------------------------------

def test_smbv1_high_confirmed():
    target = _target_from_fixture("nmap_nse_smb.xml", 445)
    result = SmbSafeModule().run(target, _CONFIG)
    titles = [f.title for f in result.findings]
    smb1 = [f for f in result.findings if "SMBv1" in f.title]
    assert smb1, f"Expected SMBv1 finding; got: {titles}"
    assert smb1[0].severity == Severity.HIGH
    assert smb1[0].confidence == Confidence.CONFIRMED


def test_smb_signing_not_required_medium_with_relay_note():
    target = _target_from_fixture("nmap_nse_smb.xml", 445)
    result = SmbSafeModule().run(target, _CONFIG)
    signing = [f for f in result.findings if "Signing" in f.title]
    assert signing, "Expected SMB signing finding"
    assert signing[0].severity == Severity.MEDIUM
    assert "relay" in signing[0].description.lower() or "ntlm" in signing[0].description.lower()


# ---------------------------------------------------------------------------
# SSH depth tests
# ---------------------------------------------------------------------------

def test_ssh_weak_kex_and_cipher_and_mac_reported():
    target = _target_from_fixture("nmap_nse_ssh.xml", 22)
    result = SshSafeModule().run(target, _CONFIG)
    titles = [f.title for f in result.findings]
    assert any("Key Exchange" in t or "KEX" in t for t in titles), f"Expected weak KEX finding; got: {titles}"
    assert any("Cipher" in t for t in titles), f"Expected cipher finding; got: {titles}"
    assert any("MAC" in t for t in titles), f"Expected MAC finding; got: {titles}"


def test_ssh_dss_hostkey_flagged():
    target = _target_from_fixture("nmap_nse_ssh.xml", 22)
    result = SshSafeModule().run(target, _CONFIG)
    dss = [f for f in result.findings if "ssh-dss" in f.description.lower() or "Deprecated" in f.title]
    assert dss, "Expected ssh-dss host key finding"
    assert dss[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# SNMP depth tests
# ---------------------------------------------------------------------------

def test_snmp_sysdescr_parsed_for_asset_info():
    # Build a target with NSE snmp-info data
    target = {
        "host": "10.0.0.1", "port": 161, "protocol": "udp", "service": "snmp",
        "product": "", "version": "", "cpe": [], "routing_reason": "",
        "scripts": {
            "snmp-info": {
                "output": "Linux server01 4.15.0-generic #72-Ubuntu SMP",
                "data": {"raw": "Linux server01 4.15.0-generic"},
            }
        },
    }
    result = SnmpSafeModule().run(target, {"snmp_default_community_check": False})
    info_findings = [f for f in result.findings if "System Information" in f.title]
    assert info_findings, "Expected SNMP system information finding from NSE data"
    assert info_findings[0].confidence == Confidence.CONFIRMED


# ---------------------------------------------------------------------------
# RDP depth tests
# ---------------------------------------------------------------------------

def test_rdp_nla_disabled_high():
    target = _target_from_fixture("nmap_nse_rdp.xml", 3389)
    result = RdpSafeModule().run(target, _CONFIG)
    nla = [f for f in result.findings if "NLA" in f.title]
    assert nla, "Expected NLA disabled finding"
    assert nla[0].severity == Severity.HIGH
    assert nla[0].confidence == Confidence.CONFIRMED


# ---------------------------------------------------------------------------
# DB depth tests
# ---------------------------------------------------------------------------

def test_redis_unauth_indicator_high():
    target = {
        "host": "10.0.0.1", "port": 6379, "protocol": "tcp", "service": "redis",
        "product": "Redis", "version": "6.2", "cpe": [], "routing_reason": "redis",
        "scripts": {},
    }
    with patch("portwise.modules.registry._tcp_send_recv", return_value=b"+PONG\r\n"):
        result = DatabaseSafeModule().run(target, {"database": {"unauthenticated_checks": True}})
    redis_findings = [f for f in result.findings if "Redis" in f.title and "Unauthenticated" in f.title]
    assert redis_findings, "Expected Unauthenticated Redis finding"
    assert redis_findings[0].severity == Severity.HIGH


def test_elasticsearch_unauth_root_high():
    target = {
        "host": "10.0.0.1", "port": 9200, "protocol": "tcp", "service": "elasticsearch",
        "product": "Elasticsearch", "version": "7.9", "cpe": [], "routing_reason": "elasticsearch",
        "scripts": {},
    }
    with patch("portwise.modules.registry._safe_http_fingerprint", return_value=(200, "Elasticsearch", "healthy", "http://10.0.0.1:9200/")):
        result = DatabaseSafeModule().run(target, {"database": {"unauthenticated_checks": True}})
    es_findings = [f for f in result.findings if "Elasticsearch" in f.title]
    assert es_findings, "Expected Unauthenticated Elasticsearch finding"
    assert es_findings[0].severity == Severity.HIGH


def test_db_version_inference_is_possible_manual():
    target = {
        "host": "10.0.0.1", "port": 5432, "protocol": "tcp", "service": "postgresql",
        "product": "PostgreSQL", "version": "13.4", "cpe": [], "routing_reason": "postgres",
        "scripts": {},
    }
    result = DatabaseSafeModule().run(target, {"database": {"unauthenticated_checks": False}})
    version_findings = [f for f in result.findings if "Version" in f.title]
    assert version_findings, "Expected version disclosure finding"
    # Version disclosure from fingerprint is informational
    assert version_findings[0].category in {FindingCategory.INFORMATION, FindingCategory.VULNERABILITY}
