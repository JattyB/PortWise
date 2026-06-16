from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from portwise.core.models import Confidence, Finding, Service, Severity
from portwise.intelligence.aggregation import (
    aggregate_ports,
    filter_ports,
    finding_overview,
    plaintext_summary,
)
from portwise.intelligence.cve_enrichment import NvdProvider, enrich_services_with_cves
from portwise.intelligence.false_positive import dedupe_findings
from portwise.intelligence.version_match import cpe_product_matches
from portwise.modules.registry import PlaintextProtocolModule
from portwise.scanners.smb_native import _parse_smb1_negotiate, _parse_smb2_negotiate
from portwise.scanners.ssh_algos import _parse_kexinit


# --------------------------------------------------------------------------
# CVE keyword-only suppression + version-unknown collapsing
# --------------------------------------------------------------------------

def _enrichment(cves):
    return type("E", (), {"cves": cves, "provider_notes": []})()


def test_keyword_only_cves_suppressed_by_default(tmp_path):
    cves = [
        {"id": "CVE-1", "match_status": "keyword_only", "cvss": 7.0, "references": []},
        {"id": "CVE-2", "match_status": "keyword_only", "cvss": 5.0, "references": []},
    ]
    svc = Service("203.0.113.5", 8080, "tcp", "open", "http", product="tomcat", version="9")
    with patch.object(NvdProvider, "enrich", lambda self, s: _enrichment(cves)), \
         patch.object(NvdProvider, "__init__", lambda self, *a, **k: None):
        findings, notes = enrich_services_with_cves([svc], tmp_path)
    assert findings == []
    assert any("Suppressed" in n for n in notes)


def test_keyword_only_included_when_requested(tmp_path):
    cves = [{"id": "CVE-9", "match_status": "keyword_only", "cvss": 7.0, "references": []}]
    svc = Service("203.0.113.5", 8080, "tcp", "open", "http", product="tomcat", version="9")
    with patch.object(NvdProvider, "enrich", lambda self, s: _enrichment(cves)), \
         patch.object(NvdProvider, "__init__", lambda self, *a, **k: None):
        findings, _ = enrich_services_with_cves([svc], tmp_path, include_keyword_only=True)
    assert len(findings) == 1


def test_version_unknown_collapses_to_single_finding(tmp_path):
    cves = [
        {"id": f"CVE-{i}", "match_status": "version_unknown", "cvss": 6.0, "references": []}
        for i in range(8)
    ]
    svc = Service("203.0.113.5", 80, "tcp", "open", "http", product="nginx", version="weird")
    with patch.object(NvdProvider, "enrich", lambda self, s: _enrichment(cves)), \
         patch.object(NvdProvider, "__init__", lambda self, *a, **k: None):
        findings, _ = enrich_services_with_cves([svc], tmp_path)
    assert len(findings) == 1
    assert "Manual Version Validation" in findings[0].title
    assert findings[0].confidence == Confidence.NEEDS_MANUAL_VALIDATION


# --------------------------------------------------------------------------
# Stricter CPE product matching (no loose substrings)
# --------------------------------------------------------------------------

def test_cpe_no_loose_substring_match():
    criteria = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    # "ssh" must NOT match "openssh" (old substring rule did)
    assert cpe_product_matches("ssh", criteria) is False
    assert cpe_product_matches("openssh", criteria) is True


def test_cpe_alias_apache_httpd():
    criteria = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    assert cpe_product_matches("Apache httpd", criteria) is True
    assert cpe_product_matches("nginx", criteria) is False


# --------------------------------------------------------------------------
# Finding dedup
# --------------------------------------------------------------------------

def test_dedupe_keeps_strongest():
    weak = Finding(title="SMBv1 Enabled", severity=Severity.HIGH, asset="10.0.0.1", port=445,
                   protocol="tcp", confidence=Confidence.LIKELY, evidence_strength=4)
    strong = Finding(title="SMBv1 Enabled", severity=Severity.HIGH, asset="10.0.0.1", port=445,
                     protocol="tcp", confidence=Confidence.CONFIRMED, evidence_strength=5)
    other = Finding(title="SMB Signing Not Required", severity=Severity.MEDIUM, asset="10.0.0.1",
                    port=445, protocol="tcp", confidence=Confidence.CONFIRMED)
    result = dedupe_findings([weak, strong, other])
    assert len(result) == 2
    smbv1 = [f for f in result if f.title == "SMBv1 Enabled"][0]
    assert smbv1.confidence == Confidence.CONFIRMED


# --------------------------------------------------------------------------
# Port aggregation / filtering
# --------------------------------------------------------------------------

def _run_fixture():
    return {
        "metadata": {"state": {
            "services_by_host": {
                "10.0.0.1": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https"},
                ],
                "10.0.0.2": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
                ],
                "10.0.0.3": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service_name": "http"},
                ],
            },
            "tcp_open_ports_by_host": {"10.0.0.1": [22, 443], "10.0.0.2": [22], "10.0.0.3": [22, 80]},
            "udp_open_ports_by_host": {},
        }},
        "findings": [
            {"title": "Cleartext Protocol Exposed — Telnet", "asset": "10.0.0.4", "port": 23,
             "severity": "high", "tags": ["plaintext-protocol"], "confidence": "Confirmed"},
        ],
    }


def test_aggregate_ports_counts_hosts():
    groups = aggregate_ports(_run_fixture())
    ssh = [g for g in groups if g.port == 22][0]
    assert ssh.count == 3
    assert ssh.hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert ssh.label == "ssh"
    # sorted by descending host count → 22 first
    assert groups[0].port == 22


def test_filter_ports_by_port_and_service():
    groups = aggregate_ports(_run_fixture())
    only22 = filter_ports(groups, port=22)
    assert len(only22) == 1 and only22[0].count == 3
    https = filter_ports(groups, service="https")
    assert all("https" in g.label or any("https" in s for s in g.services) for g in https)
    min2 = filter_ports(groups, min_count=2)
    assert all(g.count >= 2 for g in min2)


def test_plaintext_summary_groups_endpoints():
    summary = plaintext_summary(_run_fixture())
    assert summary
    assert summary[0]["protocol"] == "Telnet"
    assert summary[0]["host_count"] == 1


def test_finding_overview_counts():
    ov = finding_overview(_run_fixture())
    assert ov["total"] == 1
    assert ov["by_severity"].get("high") == 1


# --------------------------------------------------------------------------
# Plaintext module classification
# --------------------------------------------------------------------------

def test_plaintext_module_flags_telnet():
    mod = PlaintextProtocolModule()
    result = mod.run({"host": "10.0.0.9", "port": 23, "protocol": "tcp", "service": "telnet"}, {})
    assert result.findings
    f = result.findings[0]
    assert "Telnet" in f.title
    assert f.confidence == Confidence.CONFIRMED
    assert "plaintext-protocol" in f.tags


def test_plaintext_module_softens_opportunistic_tls():
    mod = PlaintextProtocolModule()
    result = mod.run({"host": "10.0.0.9", "port": 25, "protocol": "tcp", "service": "smtp"}, {})
    assert result.findings
    assert result.findings[0].confidence == Confidence.NEEDS_MANUAL_VALIDATION


def test_plaintext_module_ignores_tls_tunnel():
    mod = PlaintextProtocolModule()
    result = mod.run({"host": "10.0.0.9", "port": 443, "protocol": "tcp", "service": "https"}, {})
    assert result.findings == []


def test_plaintext_module_ignores_ssh():
    mod = PlaintextProtocolModule()
    result = mod.run({"host": "10.0.0.9", "port": 22, "protocol": "tcp", "service": "ssh"}, {})
    assert result.findings == []


# --------------------------------------------------------------------------
# Native parser unit tests (no sockets)
# --------------------------------------------------------------------------

def test_parse_kexinit_extracts_namelists():
    import struct
    cookie = b"\x00" * 16

    def namelist(s: str) -> bytes:
        raw = s.encode()
        return struct.pack(">I", len(raw)) + raw

    payload = bytes([20]) + cookie
    payload += namelist("diffie-hellman-group14-sha1,curve25519-sha256")
    payload += namelist("ssh-rsa,ssh-ed25519")
    payload += namelist("aes128-cbc,aes256-gcm@openssh.com")  # enc c2s
    payload += namelist("aes128-cbc")  # enc s2c
    payload += namelist("hmac-md5,hmac-sha2-256")  # mac c2s
    payload += namelist("hmac-sha2-256")  # mac s2c
    payload += namelist("none")  # comp c2s
    payload += namelist("none")  # comp s2c
    payload += namelist("")  # lang c2s
    payload += namelist("")  # lang s2c

    parsed = _parse_kexinit(payload)
    assert parsed is not None
    assert "diffie-hellman-group14-sha1" in parsed["kex"]
    assert "aes128-cbc" in parsed["encryption"]
    assert "hmac-md5" in parsed["mac"]


def test_parse_smb2_signing_required():
    import struct
    body = struct.pack("<HHH", 65, 0x0003, 0x0311)  # StructureSize, SecurityMode(req+enabled), dialect
    response = b"\xfeSMB" + b"\x00" * 60 + body
    parsed = _parse_smb2_negotiate(response)
    assert parsed["smbv1"] is False
    assert parsed["signing"] == "required"


def test_parse_smb1_signing_disabled():
    # 32-byte header, WordCount=17 @32, DialectIndex @33-34, SecurityMode @35
    response = b"\xffSMB" + b"\x00" * 28 + bytes([17]) + b"\x00\x00" + bytes([0x00]) + b"\x00" * 8
    parsed = _parse_smb1_negotiate(response)
    assert parsed["smbv1"] is True
    assert parsed["signing"] == "disabled"


def test_parse_smb1_signing_required():
    # SecurityMode bit 0x08 = signing required
    response = b"\xffSMB" + b"\x00" * 28 + bytes([17]) + b"\x00\x00" + bytes([0x0C]) + b"\x00" * 8
    parsed = _parse_smb1_negotiate(response)
    assert parsed["signing"] == "required"


# --------------------------------------------------------------------------
# Handoff / export
# --------------------------------------------------------------------------

def test_handoff_generates_smb_and_web_commands():
    from portwise.intelligence.handoff import build_handoff, render_script
    run = {
        "metadata": {"state": {"services_by_host": {
            "10.0.0.1": [{"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service_name": "http"}],
        }}},
        "findings": [
            {"title": "SMB Signing Not Required", "asset": "10.0.0.1", "port": 445, "type": "Exposure", "confidence": "Confirmed"},
            {"title": "Weak SSH Key Exchange Algorithm", "asset": "10.0.0.1", "port": 22,
             "description": "Weak KEX algorithms offered: diffie-hellman-group1-sha1.", "confidence": "Likely"},
        ],
    }
    items = build_handoff(run)
    cats = {it.category for it in items}
    assert "smb-relay" in cats
    assert "ssh-weak-crypto" in cats
    assert "web" in cats
    script = render_script(items)
    assert script.startswith("#!/usr/bin/env bash")
    assert "nxc smb" in script
    assert "ssh-audit" in script
    assert "PortWise did NOT run" in script


def test_handoff_marks_credential_attacks():
    from portwise.intelligence.handoff import build_handoff
    run = {"metadata": {"state": {}}, "findings": [
        {"title": "Default Credentials Should Be Manually Verified — grafana",
         "asset": "10.0.0.2", "port": 3000, "tags": ["default-creds"], "confidence": "Informational"},
    ]}
    items = build_handoff(run)
    cred = [it for it in items if it.category == "default-creds"]
    assert cred and cred[0].requires_auth_note is True
