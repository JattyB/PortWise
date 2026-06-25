"""Authenticated checks (operator opt-in, full depth only).

Only operator-supplied credentials are used. PortWise does not brute force or
guess credentials; these checks validate explicitly provided access and construct
read-only Kerberos requests through impacket.
"""
from __future__ import annotations

import base64
from urllib.parse import urlencode

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.intelligence.credentials import Credential
from portwise.scanners.ad_impacket import (
    IMPACKET_UNAVAILABLE_NOTE,
    KerberosRequester,
    LdapObject,
    SmbConnectionFactory,
    authenticated_smb_access,
    construct_asrep_roast_requests,
    construct_kerberoast_requests,
    impacket_available,
    impacket_load_error,
    request_asrep_with_impacket,
    request_tgs_with_impacket,
)
from portwise.utils.http_client import PoliteHttpClient


def _auth_finding(title, severity, asset, port, description, *, category=FindingCategory.VULNERABILITY,
                  confidence=Confidence.CONFIRMED, strength=5, evidence_data=None) -> Finding:
    ev = Evidence("module:authenticated", description, strength, evidence_data or {})
    return Finding(
        title=title, severity=severity, asset=str(asset), port=int(port or 0) or None,
        protocol="tcp", service="", description=description,
        recommendation="Confirm this account is authorized for the service; enforce least privilege, rotate shared/default credentials, and monitor authenticated access.",
        confidence=confidence, evidence_strength=strength, type="authenticated",
        module="authenticated", false_positive_risk="low", manual_validation=False,
        evidence=[ev], tags=["authenticated", "credentialed"], category=category,
    )


def web_basic_auth(
    client: PoliteHttpClient, host: str, port: int, tls: bool, cred: Credential,
    *, path: str = "/", timeout: float = 6.0,
) -> bool:
    """Return True when supplied Basic credentials are accepted."""
    token = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
    try:
        no_auth = client.request(host, port, "GET", path, tls, timeout)
        with_auth = client.request(host, port, "GET", path, tls, timeout,
                                   extra_headers={"Authorization": f"Basic {token}"})
    except OSError:
        return False
    return no_auth.status == 401 and with_auth.status in (200, 201, 204, 301, 302, 307, 308)


def web_form_login(
    client: PoliteHttpClient, host: str, port: int, tls: bool, cred: Credential,
    *, timeout: float = 6.0,
) -> bool:
    """Attempt a single form login and return True when a session appears active."""
    login_url = cred.login_url or "/login"
    payload = urlencode({
        cred.username_field: cred.username,
        cred.password_field: cred.password,
    })
    try:
        resp = client.request(
            host, port, "POST", login_url, tls, timeout,
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
    except OSError:
        return False
    set_cookie = resp.getheader("Set-Cookie", "")
    session_cookie = any(k in set_cookie.lower() for k in ("session", "sid", "auth", "token"))
    location = resp.getheader("Location", "").lower()
    redirected_in = resp.status in (301, 302, 303, 307, 308) and "login" not in location
    return bool(session_cookie or redirected_in)


def run_web_auth(
    client: PoliteHttpClient, host: str, port: int, tls: bool,
    creds: list[Credential], *, timeout: float = 6.0,
) -> list[Finding]:
    findings: list[Finding] = []
    for cred in creds:
        if web_basic_auth(client, host, port, tls, cred, timeout=timeout):
            findings.append(_auth_finding(
                "Authenticated Access - HTTP Basic Credentials Accepted", Severity.HIGH,
                host, port,
                f"Supplied HTTP Basic credentials ({cred.redacted()}) were accepted by the web service.",
                evidence_data={"method": "basic", "user": cred.username},
            ))
            continue
        if cred.password and web_form_login(client, host, port, tls, cred, timeout=timeout):
            findings.append(_auth_finding(
                "Authenticated Access - Web Form Login Succeeded", Severity.MEDIUM,
                host, port,
                f"Supplied credentials ({cred.redacted()}) appear to establish an authenticated session via form login at {cred.login_url or '/login'}.",
                confidence=Confidence.LIKELY, strength=4,
                evidence_data={"method": "form", "user": cred.username, "login_url": cred.login_url or "/login"},
            ))
    return findings


def run_smb_auth(
    host: str,
    creds: list[Credential],
    *,
    conn_factory: SmbConnectionFactory | None = None,
    spn_accounts: list[LdapObject] | None = None,
    asrep_accounts: list[LdapObject] | None = None,
    kdc_host: str = "",
    tgs_requester: KerberosRequester | None = None,
    asrep_requester: KerberosRequester | None = None,
) -> tuple[list[Finding], list[str]]:
    """Authenticated SMB/AD checks through impacket. Returns (findings, notes)."""
    findings: list[Finding] = []
    notes: list[str] = []
    if conn_factory is None and not impacket_available():
        detail = impacket_load_error()
        notes.append(IMPACKET_UNAVAILABLE_NOTE if not detail else f"{IMPACKET_UNAVAILABLE_NOTE}: {detail}")
        return findings, notes
    tgs_requester = tgs_requester or request_tgs_with_impacket
    asrep_requester = asrep_requester or request_asrep_with_impacket
    for cred in creds:
        result = authenticated_smb_access(host, cred, conn_factory=conn_factory)
        if result.accepted:
            share_names = sorted(share.name for share in result.shares if share.name)
            sev = Severity.CRITICAL if result.admin else Severity.HIGH
            findings.append(_auth_finding(
                "Authenticated Access - SMB Login Succeeded", sev, host, 445,
                f"Supplied SMB credentials ({cred.redacted()}) authenticated successfully"
                + (" and exposed administrative shares." if result.admin else "."),
                evidence_data={"method": "smb", "user": cred.username, "domain": cred.domain, "admin": result.admin, "shares": share_names},
            ))
            notes.append(f"smb-auth: impacket session established for {cred.redacted()}")
        else:
            notes.append(f"smb-auth: credentials not accepted for {cred.redacted()}" + (f" ({result.error})" if result.error else ""))

        if spn_accounts:
            roast = construct_kerberoast_requests(cred, spn_accounts, kdc_host=kdc_host, requester=tgs_requester)
            if roast.requests:
                findings.append(_auth_finding(
                    "Kerberoast Request Constructed - SPN Accounts", Severity.MEDIUM, host, 88,
                    f"Constructed {len(roast.requests)} Kerberoast TGS request(s) through impacket for SPN-bearing account(s) using {cred.redacted()}.",
                    confidence=Confidence.LIKELY,
                    strength=4,
                    evidence_data={
                        "method": "kerberoast",
                        "request_count": len(roast.requests),
                        "targets": [{"account": r.username, "spn": r.target, "domain": r.domain, "kdc_host": r.kdc_host} for r in roast.requests],
                        "errors": roast.errors,
                    },
                ))
        if asrep_accounts:
            roast = construct_asrep_roast_requests(cred, asrep_accounts, kdc_host=kdc_host, requester=asrep_requester)
            if roast.requests:
                findings.append(_auth_finding(
                    "AS-REP Roast Request Constructed - Preauth Disabled", Severity.MEDIUM, host, 88,
                    f"Constructed {len(roast.requests)} AS-REP request(s) through impacket for account(s) without Kerberos pre-authentication using {cred.redacted()}.",
                    confidence=Confidence.LIKELY,
                    strength=4,
                    evidence_data={
                        "method": "asrep-roast",
                        "request_count": len(roast.requests),
                        "targets": [{"account": r.username, "domain": r.domain, "kdc_host": r.kdc_host} for r in roast.requests],
                        "errors": roast.errors,
                    },
                ))
    return findings, notes
