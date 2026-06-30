from __future__ import annotations

from portwise.core.models import Severity
from portwise.intelligence.auth_checks import run_smb_auth
from portwise.intelligence.credentials import Credential
from portwise.modules.registry import LdapSafeModule, SmbSafeModule
from portwise.scanners.ad_impacket import (
    LdapObject,
    construct_asrep_roast_requests,
    construct_kerberoast_requests,
    enumerate_ldap_anonymous,
    enumerate_smb,
)


class _FakeSmb:
    def __init__(self, host, remote, sess_port=445, timeout=5.0, *, null=True, auth=True):
        self.host = host
        self.null = null
        self.auth = auth

    def login(self, username, password, domain=""):
        if username == "" and not self.null:
            raise RuntimeError("STATUS_ACCESS_DENIED")
        if username and not self.auth:
            raise RuntimeError("STATUS_LOGON_FAILURE")

    def listShares(self):
        return [
            {"shi1_netname": "IPC$", "shi1_remark": "Remote IPC"},
            {"shi1_netname": "NETLOGON", "shi1_remark": "Logon server share"},
            {"shi1_netname": "C$", "shi1_remark": "Default admin"},
        ]

    def isSigningRequired(self):
        return False

    def getDialect(self):
        return "0x0311"

    def getServerOS(self):
        return "Windows Server 2019"

    def getServerDomain(self):
        return "CORP"

    def getServerName(self):
        return "DC01"

    def logoff(self):
        pass


def _smb_factory(*, null=True, auth=True):
    def factory(host, remote, sess_port=445, timeout=5.0):
        return _FakeSmb(host, remote, sess_port=sess_port, timeout=timeout, null=null, auth=auth)
    return factory


class _FakeLdap:
    def __init__(self, url, base_dn):
        self.url = url
        self.base_dn = base_dn

    def login(self, user, password, domain="", authenticationChoice="simple"):
        pass

    def search(self, base_dn, searchFilter, attributes):
        if base_dn == "":
            return [{"dn": "", "attributes": {"defaultNamingContext": "DC=corp,DC=local"}}]
        if searchFilter == "(objectClass=domainDNS)":
            return [{"dn": "DC=corp,DC=local", "attributes": {"dnsRoot": "corp.local", "name": "corp"}}]
        if "objectCategory=person" in searchFilter:
            return [
                {"dn": "CN=svc-sql,DC=corp,DC=local", "attributes": {"sAMAccountName": "svc-sql", "servicePrincipalName": ["MSSQLSvc/sql.corp.local:1433"], "userAccountControl": 512}},
                {"dn": "CN=legacy,DC=corp,DC=local", "attributes": {"sAMAccountName": "legacy", "userAccountControl": 0x00400000}},
            ]
        if searchFilter == "(objectClass=group)":
            return [{"dn": "CN=Domain Admins,DC=corp,DC=local", "attributes": {"cn": "Domain Admins"}}]
        if searchFilter == "(objectClass=computer)":
            return [{"dn": "CN=DC01,DC=corp,DC=local", "attributes": {"dNSHostName": "dc01.corp.local", "operatingSystem": "Windows Server 2019"}}]
        return []


class _DenyLdap(_FakeLdap):
    def login(self, user, password, domain="", authenticationChoice="simple"):
        raise RuntimeError("invalidCredentials")


def test_impacket_smb_fixture_parses_null_session_shares_signing_os_domain():
    result = enumerate_smb("dc01.corp.local", conn_factory=_smb_factory())
    assert result.null_session is True
    assert result.signing == "not_required"
    assert result.os == "Windows Server 2019"
    assert result.domain == "CORP"
    assert [share.name for share in result.shares] == ["IPC$", "NETLOGON", "C$"]


def test_smb_module_emits_impacket_findings_and_control_does_not_emit(monkeypatch):
    target = {"host": "dc01.corp.local", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "scripts": {}}
    monkeypatch.setattr("portwise.scanners.ad_impacket.enumerate_smb", lambda *a, **k: enumerate_smb("dc01.corp.local", conn_factory=_smb_factory()))
    result = SmbSafeModule().run(target, {"smb": {"impacket_enum": True}, "smb_native_probe": False})
    titles = {f.title for f in result.findings}
    assert "SMB Null Session Accepted" in titles
    assert "SMB Share Enumeration" in titles
    assert "SMB Impacket OS/Domain Enumeration" in titles
    assert "SMB Signing Not Required" in titles
    signing = next(f for f in result.findings if f.title == "SMB Signing Not Required")
    assert signing.evidence[0].data["os"] == "Windows Server 2019"
    assert signing.evidence[0].data["domain"] == "CORP"
    assert signing.evidence[0].data["dialect"] == "0x0311"
    metadata = next(f for f in result.findings if f.title == "SMB Impacket OS/Domain Enumeration")
    assert "domain_or_workgroup=CORP" in metadata.description

    monkeypatch.setattr("portwise.scanners.ad_impacket.enumerate_smb", lambda *a, **k: enumerate_smb("dc01.corp.local", conn_factory=_smb_factory(null=False)))
    control = SmbSafeModule().run(target, {"smb": {"impacket_enum": True}, "smb_native_probe": False})
    assert not any(f.title == "SMB Null Session Accepted" for f in control.findings)


def test_impacket_ldap_fixture_parses_objects_and_roastable_accounts():
    result = enumerate_ldap_anonymous("dc01.corp.local", conn_factory=_FakeLdap)
    assert result.anonymous_bind is True
    assert result.base_dn == "DC=corp,DC=local"
    assert len(result.users) == 2
    assert len(result.groups) == 1
    assert len(result.computers) == 1
    assert result.spn_accounts[0].attributes["sAMAccountName"] == "svc-sql"
    assert result.asrep_roastable[0].attributes["sAMAccountName"] == "legacy"


def test_ldap_module_emits_anonymous_enum_and_control_does_not_emit(monkeypatch):
    target = {"host": "dc01.corp.local", "port": 389, "protocol": "tcp", "service": "ldap", "scripts": {}}
    monkeypatch.setattr("portwise.scanners.ad_impacket.enumerate_ldap_anonymous", lambda *a, **k: enumerate_ldap_anonymous("dc01.corp.local", conn_factory=_FakeLdap))
    result = LdapSafeModule().run(target, {"ldap": {"anonymous_enum": True}})
    assert any(f.title == "LDAP Anonymous Bind Enumeration" for f in result.findings)

    monkeypatch.setattr("portwise.scanners.ad_impacket.enumerate_ldap_anonymous", lambda *a, **k: enumerate_ldap_anonymous("dc01.corp.local", conn_factory=_DenyLdap))
    control = LdapSafeModule().run(target, {"ldap": {"anonymous_enum": True}})
    assert not any(f.title == "LDAP Anonymous Bind Enumeration" for f in control.findings)


def test_impacket_load_failure_surfaces_clear_note(monkeypatch):
    target = {"host": "dc01.corp.local", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "scripts": {}}
    monkeypatch.setattr("portwise.scanners.ad_impacket.impacket_load_error", lambda: "blocked by defender")
    result = SmbSafeModule().run(target, {"smb": {"impacket_enum": True}, "smb_native_probe": False})
    assert any(
        finding.title == "AD/SMB checks unavailable: impacket could not load (blocked or not importable)"
        for finding in result.findings
    )
    assert result.findings


def test_kerberoast_and_asrep_request_construction_redacts_secret():
    cred = Credential(service="smb", username="auditor", password="SuperSecret!", domain="CORP")
    spn = [LdapObject("CN=svc-sql", "user", {"sAMAccountName": "svc-sql", "servicePrincipalName": ["MSSQLSvc/sql.corp.local:1433"]})]
    asrep = [LdapObject("CN=legacy", "user", {"sAMAccountName": "legacy", "userAccountControl": 0x00400000})]
    calls = []

    def requester(request, supplied):
        calls.append((request.roast_type, request.target, supplied.username))

    krb = construct_kerberoast_requests(cred, spn, kdc_host="dc01.corp.local", requester=requester)
    np = construct_asrep_roast_requests(cred, asrep, kdc_host="dc01.corp.local", requester=requester)
    assert [(r.roast_type, r.target) for r in krb.requests] == [("kerberoast", "MSSQLSvc/sql.corp.local:1433")]
    assert [(r.roast_type, r.username) for r in np.requests] == [("asrep-roast", "legacy")]
    assert calls == [
        ("kerberoast", "MSSQLSvc/sql.corp.local:1433", "auditor"),
        ("asrep-roast", "legacy", "auditor"),
    ]

    findings, _notes = run_smb_auth(
        "dc01.corp.local",
        [cred],
        conn_factory=_smb_factory(auth=True),
        spn_accounts=spn,
        asrep_accounts=asrep,
        kdc_host="dc01.corp.local",
        tgs_requester=requester,
        asrep_requester=requester,
    )
    assert any(f.title == "Kerberoast Request Constructed - SPN Accounts" for f in findings)
    assert any(f.title == "AS-REP Roast Request Constructed - Preauth Disabled" for f in findings)
    assert all("SuperSecret!" not in str(f.evidence[0].data) for f in findings)


def test_phase_j_fixture_precision_recall():
    expected = {
        "SMB Null Session Accepted",
        "SMB Share Enumeration",
        "SMB Impacket OS/Domain Enumeration",
        "LDAP Anonymous Bind Enumeration",
        "Kerberoast Request Constructed - SPN Accounts",
        "AS-REP Roast Request Constructed - Preauth Disabled",
    }
    observed = set()
    target_smb = {"host": "dc01.corp.local", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "scripts": {}}
    smb_enum = enumerate_smb("dc01.corp.local", conn_factory=_smb_factory())
    if smb_enum.null_session:
        observed.add("SMB Null Session Accepted")
    if smb_enum.shares:
        observed.add("SMB Share Enumeration")
    if smb_enum.os and smb_enum.domain:
        observed.add("SMB Impacket OS/Domain Enumeration")
    if enumerate_ldap_anonymous("dc01.corp.local", conn_factory=_FakeLdap).anonymous_bind:
        observed.add("LDAP Anonymous Bind Enumeration")
    cred = Credential(service="smb", username="auditor", password="redacted", domain="CORP")
    if construct_kerberoast_requests(cred, [LdapObject("CN=svc", "user", {"sAMAccountName": "svc", "servicePrincipalName": ["HTTP/web"]})]).requests:
        observed.add("Kerberoast Request Constructed - SPN Accounts")
    if construct_asrep_roast_requests(cred, [LdapObject("CN=legacy", "user", {"sAMAccountName": "legacy"})]).requests:
        observed.add("AS-REP Roast Request Constructed - Preauth Disabled")
    false_positives = observed - expected
    false_negatives = expected - observed
    assert not false_positives
    assert not false_negatives
    assert len(observed) == 6
