"""Authenticated checks (operator opt-in, full depth only).

* **Web**: HTTP Basic auth and form login with operator-supplied credentials.
* **SMB**: orchestrate netexec/smbclient with supplied credentials (ExternalTool),
  graceful skip + handoff when neither binary is present.

These never brute force: a single operator-supplied credential per service is
tried, to confirm whether that credential grants access (e.g. validating known /
default creds the operator chose to test under authorization).
"""
from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlencode

from portwise.core.external_tool import ExternalTool
from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.intelligence.credentials import Credential
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
    """Return True when supplied Basic credentials are accepted (was 401 without,
    is 2xx/3xx with)."""
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
    """Attempt a single form login; heuristically return True when a session
    appears to be established (auth cookie set, or redirect away from the form)."""
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
                "Authenticated Access — HTTP Basic Credentials Accepted", Severity.HIGH,
                host, port,
                f"Supplied HTTP Basic credentials ({cred.redacted()}) were accepted by the web service.",
                evidence_data={"method": "basic", "user": cred.username},
            ))
            continue
        if cred.password and web_form_login(client, host, port, tls, cred, timeout=timeout):
            findings.append(_auth_finding(
                "Authenticated Access — Web Form Login Succeeded", Severity.MEDIUM,
                host, port,
                f"Supplied credentials ({cred.redacted()}) appear to establish an authenticated session via form login at {cred.login_url or '/login'}.",
                confidence=Confidence.LIKELY, strength=4,
                evidence_data={"method": "form", "user": cred.username, "login_url": cred.login_url or "/login"},
            ))
    return findings


def run_smb_auth(
    host: str, creds: list[Credential], *, tool: ExternalTool | None = None,
) -> tuple[list[Finding], list[str]]:
    """Authenticated SMB via netexec (preferred) or smbclient, orchestrated through
    ExternalTool. Returns (findings, notes)."""
    findings: list[Finding] = []
    notes: list[str] = []
    for cred in creds:
        nxc = tool or ExternalTool("nxc", binary="nxc", timeout=60)
        user = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
        handoff = f"nxc smb {host} -u '{cred.username}' -p '<redacted>' --shares"
        if not nxc.available:
            # Try classic netexec/crackmapexec name, then fall back to handoff.
            alt = ExternalTool("netexec", binary="netexec", timeout=60)
            if alt.available:
                nxc = alt
            else:
                notes.append(f"smb-auth: nxc/netexec not installed; skipped — handoff: {handoff}")
                continue
        args = ["smb", host, "-u", cred.username, "-p", cred.password, "--shares"]
        if cred.domain:
            args += ["-d", cred.domain]
        result = nxc.run(args, handoff_command=handoff)
        if not result.ran:
            notes.append(result.note())
            continue
        out = (result.stdout + " " + result.stderr)
        if "Pwn3d!" in out or "[+]" in out:
            sev = Severity.CRITICAL if "Pwn3d!" in out else Severity.HIGH
            findings.append(_auth_finding(
                "Authenticated Access — SMB Login Succeeded", sev, host, 445,
                f"Supplied SMB credentials ({cred.redacted()}) authenticated successfully"
                + (" with administrative access (Pwn3d!)." if "Pwn3d!" in out else "."),
                evidence_data={"method": "smb", "user": cred.username, "admin": "Pwn3d!" in out},
            ))
            notes.append(f"smb-auth: session established for {cred.redacted()}")
        else:
            notes.append(f"smb-auth: credentials not accepted for {cred.redacted()}")
    return findings, notes
