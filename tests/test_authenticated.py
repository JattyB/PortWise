from __future__ import annotations

import base64

from portwise.core.models import Severity
from portwise.intelligence.auth_checks import run_smb_auth, run_web_auth, web_basic_auth, web_form_login
from portwise.intelligence.credentials import (
    Credential,
    authenticated_enabled,
    credentials_for,
    load_credentials,
    parse_cred_arg,
    snmp_communities_from_credentials,
)
from portwise.modules import registry
from portwise.modules.registry import SmbSafeModule, SnmpSafeModule

_FAST = {"http_politeness": {"min_delay_seconds": 0, "jitter_seconds": [0, 0]}}


# --- credentials framework ---------------------------------------------------

def test_parse_cred_arg_web():
    c = parse_cred_arg("web:admin:s3cret")
    assert c.service == "web" and c.username == "admin" and c.password == "s3cret"


def test_parse_cred_arg_domain():
    c = parse_cred_arg("smb:CORP/svc:pw")
    assert c.service == "smb" and c.domain == "CORP" and c.username == "svc" and c.password == "pw"


def test_parse_cred_arg_snmp():
    c = parse_cred_arg("snmp::secret")
    assert c.service == "snmp" and c.community == "secret"


def test_parse_cred_arg_invalid():
    import pytest
    with pytest.raises(ValueError):
        parse_cred_arg("nope")


def test_authenticated_gate_and_credentials_for():
    config = {"authenticated": False, "credentials": [{"service": "web", "username": "a", "password": "b"}]}
    assert authenticated_enabled(config) is False
    assert credentials_for(config, "web") == []  # gated off
    config["authenticated"] = True
    creds = credentials_for(config, "web", "http")
    assert len(creds) == 1 and creds[0].username == "a"


def test_redacted_never_leaks_password():
    c = Credential(service="smb", username="svc", password="TopSecret", domain="CORP")
    assert "TopSecret" not in c.redacted()
    assert "svc" in c.redacted()


def test_snmp_communities_from_credentials():
    config = {"authenticated": True, "credentials": [{"service": "snmp", "community": "private2"}]}
    assert snmp_communities_from_credentials(config) == ["private2"]


# --- web auth (fake client) --------------------------------------------------

class _Resp:
    def __init__(self, status, headers=None):
        self.status = status
        self._h = headers or {}

    def getheader(self, name, default=""):
        return self._h.get(name, default)


class _Client:
    """Returns 401 unless an Authorization header is present; records form POSTs."""
    def __init__(self, *, form_status=302, form_cookie="session=abc"):
        self.form_status = form_status
        self.form_cookie = form_cookie
        self.posts: list = []

    def request(self, host, port, method, path, tls, timeout=6.0, extra_headers=None, body=None, **kw):
        if method == "POST":
            self.posts.append((path, body))
            return _Resp(self.form_status, {"Set-Cookie": self.form_cookie})
        if extra_headers and "Authorization" in extra_headers:
            return _Resp(200)
        return _Resp(401)


def test_web_basic_auth_success():
    cred = Credential(service="web", username="admin", password="admin")
    assert web_basic_auth(_Client(), "h", 443, True, cred) is True


def test_web_form_login_success():
    cred = Credential(service="web", username="u", password="p", login_url="/signin")
    client = _Client(form_status=302, form_cookie="sessionid=xyz")
    assert web_form_login(client, "h", 80, False, cred) is True
    assert client.posts and client.posts[0][0] == "/signin"


def test_run_web_auth_emits_finding():
    creds = [Credential(service="web", username="admin", password="admin")]
    findings = run_web_auth(_Client(), "10.0.0.1", 443, True, creds)
    assert findings and "Basic" in findings[0].title
    assert findings[0].severity == Severity.HIGH


# --- smb auth (fake impacket SMBConnection) ----------------------------------

class _FakeSmbConn:
    def __init__(self, host, remote, sess_port=445, timeout=6.0, *, accept=True, admin=False):
        self.accept = accept
        self.admin = admin

    def login(self, username, password, domain=""):
        if not self.accept:
            raise RuntimeError("STATUS_LOGON_FAILURE")

    def listShares(self):
        shares = [{"shi1_netname": "IPC$"}]
        if self.admin:
            shares.append({"shi1_netname": "C$"})
        return shares

    def logoff(self):
        pass


def _smb_factory(*, accept=True, admin=False):
    def factory(host, remote, sess_port=445, timeout=6.0):
        return _FakeSmbConn(host, remote, sess_port=sess_port, timeout=timeout, accept=accept, admin=admin)
    return factory


def test_run_smb_auth_pwned_critical():
    creds = [Credential(service="smb", username="admin", password="pw", domain="CORP")]
    findings, notes = run_smb_auth("10.0.0.1", creds, conn_factory=_smb_factory(admin=True))
    assert findings and findings[0].severity == Severity.CRITICAL
    assert "pw" not in str(findings[0].evidence[0].data)


def test_run_smb_auth_not_accepted():
    creds = [Credential(service="smb", username="x", password="y")]
    findings, notes = run_smb_auth("10.0.0.1", creds, conn_factory=_smb_factory(accept=False))
    assert findings == []
    assert any("not accepted" in n for n in notes)


def test_run_smb_auth_connection_error_note():
    creds = [Credential(service="smb", username="x", password="y")]
    def broken(*args, **kwargs):
        raise OSError("unreachable")
    findings, notes = run_smb_auth("10.0.0.1", creds, conn_factory=broken)
    assert findings == []
    assert any("unreachable" in n for n in notes)


# --- module gating -----------------------------------------------------------

def test_smb_module_no_auth_without_optin():
    target = {"host": "10.0.0.1", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "scripts": {}}
    config = {**_FAST, "validation_level": "full", "authenticated": False,
              "credentials": [{"service": "smb", "username": "a", "password": "b"}],
              "smb_native_probe": False}
    result = SmbSafeModule().run(target, config)
    assert not any(f.module == "smb" and "Authenticated Access" in f.title for f in result.findings)


def test_smb_module_runs_auth_when_optin(monkeypatch):
    target = {"host": "10.0.0.1", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "scripts": {}}
    config = {**_FAST, "validation_level": "full", "authenticated": True,
              "credentials": [{"service": "smb", "username": "a", "password": "b"}],
              "smb_native_probe": False}

    def _fake_auth(host, creds, **kw):
        from portwise.intelligence.auth_checks import _auth_finding
        return [_auth_finding("Authenticated Access — SMB Login Succeeded", Severity.HIGH, host, 445, "ok")], []

    monkeypatch.setattr("portwise.intelligence.auth_checks.run_smb_auth", _fake_auth)
    result = SmbSafeModule().run(target, config)
    assert any("Authenticated Access" in f.title for f in result.findings)


def test_snmp_module_adds_credential_community_when_optin(monkeypatch):
    target = {"host": "10.0.0.1", "port": 161, "protocol": "udp", "service": "snmp",
              "product": "", "version": "", "cpe": [], "routing_reason": "", "scripts": {}}
    seen: list[str] = []

    def _fake_get(host, port, community, timeout):
        seen.append(community)
        return None

    monkeypatch.setattr(registry, "_snmp_get", _fake_get)
    config = {**_FAST, "validation_level": "full", "authenticated": True,
              "snmp_default_community_check": True,
              "snmp": {"default_community_check": True, "communities": ["public"]},
              "credentials": [{"service": "snmp", "community": "custom-comm"}]}
    SnmpSafeModule().run(target, config)
    assert "custom-comm" in seen
