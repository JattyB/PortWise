from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from portwise.core.models import FindingCategory, Severity
from portwise.modules.tls.cipher_checks import run_cipher_checks
from portwise.scanners.nmap_parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"

_TARGET: dict = {
    "host": "10.0.0.1", "port": 443, "protocol": "tcp", "service": "https",
    "scripts": {},
}


def _svc_from_ssl_fixture():
    assets = parse_nmap_xml(FIXTURES / "nmap_nse_ssl.xml")
    assert assets
    for a in assets:
        for s in a.services:
            if s.port == 443:
                return s
    raise AssertionError("443 not found in nmap_nse_ssl.xml")


# ---------------------------------------------------------------------------
# NSE path tests
# ---------------------------------------------------------------------------

def test_nse_cipher_data_parsed_to_findings():
    svc = _svc_from_ssl_fixture()
    target = {
        "host": svc.host, "port": svc.port,
        "protocol": svc.protocol, "service": svc.service_name,
        "scripts": svc.scripts,
    }
    findings = run_cipher_checks(svc, target, {})
    titles = [f.title for f in findings]
    assert any("Weak" in t or "Cipher" in t for t in titles), f"Expected cipher finding, got: {titles}"


def test_weak_cipher_family_categorized_medium():
    svc = _svc_from_ssl_fixture()
    target = {
        "host": svc.host, "port": svc.port,
        "protocol": svc.protocol, "service": svc.service_name,
        "scripts": svc.scripts,
    }
    findings = run_cipher_checks(svc, target, {})
    weak = [f for f in findings if "Weak" in f.title and "Cipher" in f.title]
    assert weak, "Expected at least one weak cipher finding"
    assert all(f.severity == Severity.MEDIUM for f in weak), f"Expected MEDIUM: {[f.severity for f in weak]}"
    assert all(f.category == FindingCategory.VULNERABILITY for f in weak)


def test_sha1_cert_signature_medium():
    svc = _svc_from_ssl_fixture()
    target = {
        "host": svc.host, "port": svc.port,
        "protocol": svc.protocol, "service": svc.service_name,
        "scripts": svc.scripts,
    }
    findings = run_cipher_checks(svc, target, {})
    sha1 = [f for f in findings if "SHA-1" in f.title or "sha1" in f.title.lower() or "Signature" in f.title]
    assert sha1, "Expected SHA-1 signature finding from nmap_nse_ssl.xml"
    assert sha1[0].severity == Severity.MEDIUM


def test_cipher_enum_confidence_levels():
    svc = _svc_from_ssl_fixture()
    target = {
        "host": svc.host, "port": svc.port,
        "protocol": svc.protocol, "service": svc.service_name,
        "scripts": svc.scripts,
    }
    findings = run_cipher_checks(svc, target, {})
    from portwise.core.models import Confidence
    for f in findings:
        assert f.confidence in {Confidence.CONFIRMED, Confidence.LIKELY}, (
            f"Expected CONFIRMED or LIKELY, got {f.confidence} for {f.title!r}"
        )


def test_no_pfs_detected_best_practice():
    # Build a service with a kRSA cipher in ssl-enum-ciphers
    scripts = {
        "ssl-enum-ciphers": {
            "output": "TLSv1.2: ...",
            "data": {
                "TLSv1.2": [
                    {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "kex_info": "rsa 2048", "strength": "A"},
                ]
            },
        }
    }
    from portwise.core.models import Service
    svc = Service(host="10.0.0.1", port=443, protocol="tcp", state="open", scripts=scripts)
    target = {"host": "10.0.0.1", "port": 443, "protocol": "tcp", "service": "https", "scripts": scripts}
    findings = run_cipher_checks(svc, target, {})
    # Simplified model: no separate no-PFS finding is emitted anymore.
    pfs = [f for f in findings if "Forward Secrecy" in f.title or "PFS" in f.title]
    assert not pfs


def test_insecure_cipher_family_categorized_high():
    # Build a service with a NULL cipher
    scripts = {
        "ssl-enum-ciphers": {
            "output": "TLSv1.2: ...",
            "data": {
                "TLSv1.2": [
                    {"name": "TLS_NULL_WITH_NULL_NULL", "kex_info": "null", "strength": "F"},
                ]
            },
        }
    }
    from portwise.core.models import Service
    svc = Service(host="10.0.0.1", port=443, protocol="tcp", state="open", scripts=scripts)
    target = {"host": "10.0.0.1", "port": 443, "protocol": "tcp", "service": "https", "scripts": scripts}
    findings = run_cipher_checks(svc, target, {})
    weak = [f for f in findings if f.title == "Weak TLS Ciphers In Use"]
    assert weak, "Expected weak-cipher finding for NULL suite"
    assert weak[0].severity == Severity.HIGH


def test_native_probe_handles_unsupported_family_gracefully():
    """Native probe must not emit per-host noise when a cipher family is not testable."""
    from portwise.core.models import Service
    svc = Service(host="127.0.0.1", port=9443, protocol="tcp", state="open")
    target = {"host": "127.0.0.1", "port": 9443, "protocol": "tcp", "service": "https", "scripts": {}}
    config = {"tls": {"native_cipher_probe": True}}

    # Patch ssl.SSLContext to always raise SSLError (cipher not supported by OpenSSL)
    with patch("portwise.modules.tls.cipher_checks.ssl.SSLContext") as mock_ctx_cls:
        instance = MagicMock()
        instance.set_ciphers.side_effect = __import__("ssl").SSLError("no ciphers available")
        mock_ctx_cls.return_value = instance
        findings = run_cipher_checks(svc, target, config)

    # Should produce zero findings; no crash, no noise
    assert findings == [], f"Expected no findings when native probe fails, got: {[f.title for f in findings]}"
