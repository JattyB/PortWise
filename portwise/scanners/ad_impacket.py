"""SMB/LDAP/AD helpers backed by impacket.

All imports are lazy so PortWise can report a clear dependency problem if a
packaging issue removes impacket, while normal installs ship the capability.
The public functions accept factories/requesters for fixture validation without
opening real SMB/LDAP/Kerberos sessions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable

from portwise.intelligence.credentials import Credential

IMPACKET_UNAVAILABLE_NOTE = "AD/SMB checks unavailable: impacket could not load (blocked or not importable)"


@dataclass(slots=True)
class SmbShare:
    name: str
    remark: str = ""
    share_type: str = ""
    read_access: bool | None = None


@dataclass(slots=True)
class SmbEnumeration:
    host: str
    port: int = 445
    null_session: bool = False
    shares: list[SmbShare] = field(default_factory=list)
    signing: str = "unknown"
    dialect: str = ""
    os: str = ""
    domain: str = ""
    server_name: str = ""
    error: str = ""


@dataclass(slots=True)
class LdapObject:
    dn: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LdapEnumeration:
    host: str
    port: int = 389
    anonymous_bind: bool = False
    base_dn: str = ""
    domain_info: dict[str, Any] = field(default_factory=dict)
    users: list[LdapObject] = field(default_factory=list)
    groups: list[LdapObject] = field(default_factory=list)
    computers: list[LdapObject] = field(default_factory=list)
    spn_accounts: list[LdapObject] = field(default_factory=list)
    asrep_roastable: list[LdapObject] = field(default_factory=list)
    error: str = ""


@dataclass(slots=True)
class SmbAuthResult:
    accepted: bool
    admin: bool = False
    shares: list[SmbShare] = field(default_factory=list)
    error: str = ""


@dataclass(slots=True)
class KerberosRequest:
    roast_type: str
    domain: str
    username: str
    target: str
    kdc_host: str = ""


@dataclass(slots=True)
class RoastConstructionResult:
    requests: list[KerberosRequest] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


SmbConnectionFactory = Callable[..., Any]
LdapConnectionFactory = Callable[..., Any]
KerberosRequester = Callable[[KerberosRequest, Credential], Any]


@lru_cache(maxsize=1)
def impacket_load_error() -> str | None:
    try:
        from impacket.smbconnection import SMBConnection  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment-specific
        return _safe_error(exc)
    return None


def impacket_available() -> bool:
    return impacket_load_error() is None


def impacket_unavailable_note() -> str:
    detail = impacket_load_error()
    return IMPACKET_UNAVAILABLE_NOTE if not detail else f"{IMPACKET_UNAVAILABLE_NOTE}: {detail}"


def enumerate_smb(
    host: str,
    *,
    port: int = 445,
    timeout: float = 5.0,
    conn_factory: SmbConnectionFactory | None = None,
) -> SmbEnumeration:
    result = SmbEnumeration(host=host, port=port)
    load_error = impacket_load_error() if conn_factory is None else None
    if load_error is not None:
        result.error = f"{IMPACKET_UNAVAILABLE_NOTE}: {load_error}"
        return result
    try:
        conn = _new_smb_connection(host, port, timeout, conn_factory)
    except Exception as exc:
        result.error = _safe_error(exc)
        return result
    try:
        result.signing = _smb_signing(conn)
        result.dialect = _maybe_call_str(conn, "getDialect")
        result.os = _maybe_call_str(conn, "getServerOS")
        result.domain = _maybe_call_str(conn, "getServerDomain")
        result.server_name = _maybe_call_str(conn, "getServerName")
        try:
            conn.login("", "", "")
            result.null_session = True
        except Exception as exc:
            result.error = _safe_error(exc)
            return result
        result.shares = [_parse_share(item) for item in _maybe_call(conn, "listShares", default=[]) or []]
        return result
    finally:
        _close_smb(conn)


def authenticated_smb_access(
    host: str,
    cred: Credential,
    *,
    port: int = 445,
    timeout: float = 6.0,
    conn_factory: SmbConnectionFactory | None = None,
) -> SmbAuthResult:
    load_error = impacket_load_error() if conn_factory is None else None
    if load_error is not None:
        return SmbAuthResult(False, error=f"{IMPACKET_UNAVAILABLE_NOTE}: {load_error}")
    try:
        conn = _new_smb_connection(host, port, timeout, conn_factory)
    except Exception as exc:
        return SmbAuthResult(False, error=_safe_error(exc))
    try:
        conn.login(cred.username, cred.password, cred.domain)
        shares = [_parse_share(item) for item in _maybe_call(conn, "listShares", default=[]) or []]
        admin = any(share.name.upper() in {"ADMIN$", "C$"} for share in shares)
        return SmbAuthResult(True, admin=admin, shares=shares)
    except Exception as exc:
        return SmbAuthResult(False, error=_safe_error(exc))
    finally:
        _close_smb(conn)


def enumerate_ldap_anonymous(
    host: str,
    *,
    port: int = 389,
    use_ssl: bool = False,
    base_dn: str = "",
    timeout: float = 5.0,
    conn_factory: LdapConnectionFactory | None = None,
) -> LdapEnumeration:
    result = LdapEnumeration(host=host, port=port, base_dn=base_dn)
    load_error = impacket_load_error() if conn_factory is None else None
    if load_error is not None:
        result.error = f"{IMPACKET_UNAVAILABLE_NOTE}: {load_error}"
        return result
    url = ("ldaps" if use_ssl else "ldap") + f"://{host}:{port}"
    try:
        conn = _new_ldap_connection(url, base_dn, timeout, conn_factory)
        _ldap_login_anonymous(conn)
        result.anonymous_bind = True
        result.base_dn = base_dn or _discover_base_dn(conn)
        result.domain_info = _ldap_first_attrs(_ldap_search(conn, result.base_dn, "(objectClass=domainDNS)", ["defaultNamingContext", "dnsRoot", "name"]))
        result.users = _ldap_objects(conn, result.base_dn, "user", "(&(objectCategory=person)(objectClass=user))", ["sAMAccountName", "userPrincipalName", "servicePrincipalName", "userAccountControl"])
        result.groups = _ldap_objects(conn, result.base_dn, "group", "(objectClass=group)", ["cn", "sAMAccountName"])
        result.computers = _ldap_objects(conn, result.base_dn, "computer", "(objectClass=computer)", ["dNSHostName", "sAMAccountName", "operatingSystem"])
        result.spn_accounts = [obj for obj in result.users if obj.attributes.get("servicePrincipalName")]
        result.asrep_roastable = [obj for obj in result.users if _uac_no_preauth(obj.attributes.get("userAccountControl"))]
        return result
    except Exception as exc:
        result.error = _safe_error(exc)
        return result


def construct_kerberoast_requests(
    cred: Credential,
    spn_accounts: list[LdapObject],
    *,
    kdc_host: str = "",
    requester: KerberosRequester | None = None,
) -> RoastConstructionResult:
    result = RoastConstructionResult()
    domain = cred.domain or str(cred.extra.get("domain", ""))
    for obj in spn_accounts:
        spns = obj.attributes.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        account = str(obj.attributes.get("sAMAccountName") or obj.attributes.get("userPrincipalName") or obj.dn)
        for spn in [str(item) for item in spns if item]:
            request = KerberosRequest("kerberoast", domain, account, spn, kdc_host)
            result.requests.append(request)
            if requester is not None:
                try:
                    requester(request, cred)
                except Exception as exc:
                    result.errors.append(_safe_error(exc))
    return result


def construct_asrep_roast_requests(
    cred: Credential,
    accounts: list[LdapObject],
    *,
    kdc_host: str = "",
    requester: KerberosRequester | None = None,
) -> RoastConstructionResult:
    result = RoastConstructionResult()
    domain = cred.domain or str(cred.extra.get("domain", ""))
    for obj in accounts:
        username = str(obj.attributes.get("sAMAccountName") or obj.attributes.get("userPrincipalName") or obj.dn)
        request = KerberosRequest("asrep-roast", domain, username, username, kdc_host)
        result.requests.append(request)
        if requester is not None:
            try:
                requester(request, cred)
            except Exception as exc:
                result.errors.append(_safe_error(exc))
    return result


def request_tgs_with_impacket(request: KerberosRequest, cred: Credential) -> Any:
    """Construct and issue a TGS request through impacket for Kerberoast checks."""
    load_error = impacket_load_error()
    if load_error is not None:
        raise RuntimeError(f"{IMPACKET_UNAVAILABLE_NOTE}: {load_error}")
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import Principal

    user = Principal(cred.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    server = Principal(request.target, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgt, cipher, old_session_key, session_key = getKerberosTGT(
        user,
        cred.password,
        request.domain,
        "",
        "",
        "",
        kdcHost=request.kdc_host or None,
    )
    return getKerberosTGS(server, request.domain, request.kdc_host or None, tgt, cipher, session_key)


def request_asrep_with_impacket(request: KerberosRequest, cred: Credential) -> Any:
    """Construct an AS-REP roast request through impacket for a no-preauth user."""
    load_error = impacket_load_error()
    if load_error is not None:
        raise RuntimeError(f"{IMPACKET_UNAVAILABLE_NOTE}: {load_error}")
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal

    user = Principal(request.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    return getKerberosTGT(
        user,
        "",
        request.domain or cred.domain,
        "",
        "",
        "",
        kdcHost=request.kdc_host or None,
    )


def _new_smb_connection(host: str, port: int, timeout: float, factory: SmbConnectionFactory | None) -> Any:
    if factory is None:
        from impacket.smbconnection import SMBConnection
        factory = SMBConnection
    return factory(host, host, sess_port=int(port), timeout=timeout)


def _new_ldap_connection(url: str, base_dn: str, timeout: float, factory: LdapConnectionFactory | None) -> Any:
    del timeout
    if factory is None:
        from impacket.ldap.ldap import LDAPConnection
        factory = LDAPConnection
    return factory(url, base_dn)


def _smb_signing(conn: Any) -> str:
    for name in ("isSigningRequired", "is_signing_required"):
        attr = getattr(conn, name, None)
        if callable(attr):
            return "required" if attr() else "not_required"
    return "unknown"


def _parse_share(item: Any) -> SmbShare:
    name = _field(item, "shi1_netname", "shi0_netname", "NetName", "name")
    remark = _field(item, "shi1_remark", "remark", "Remark")
    share_type = str(_field(item, "shi1_type", "type", "Type"))
    return SmbShare(name=_clean_share_name(name), remark=str(remark or ""), share_type=share_type)


def _field(item: Any, *names: str) -> Any:
    for name in names:
        if isinstance(item, dict) and name in item:
            return item[name]
        try:
            return item[name]
        except Exception:
            pass
        value = getattr(item, name, None)
        if value is not None:
            return value
    return ""


def _clean_share_name(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-16-le", errors="ignore") if b"\x00" in value else value.decode(errors="ignore")
    return str(value).replace("\x00", "").strip()


def _maybe_call(conn: Any, name: str, default: Any = None) -> Any:
    attr = getattr(conn, name, None)
    if not callable(attr):
        return default
    try:
        return attr()
    except Exception:
        return default


def _maybe_call_str(conn: Any, name: str) -> str:
    value = _maybe_call(conn, name, "")
    return str(value or "")


def _close_smb(conn: Any) -> None:
    for name in ("logoff", "close"):
        attr = getattr(conn, name, None)
        if callable(attr):
            try:
                attr()
            except Exception:
                pass


def _ldap_login_anonymous(conn: Any) -> None:
    login = getattr(conn, "login", None)
    if not callable(login):
        return
    try:
        login("", "", "", authenticationChoice="simple")
    except TypeError:
        login("", "", "")


def _discover_base_dn(conn: Any) -> str:
    rows = _ldap_search(conn, "", "(objectClass=*)", ["defaultNamingContext", "namingContexts"])
    attrs = _ldap_first_attrs(rows)
    value = attrs.get("defaultNamingContext") or attrs.get("namingContexts")
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _ldap_objects(conn: Any, base_dn: str, kind: str, search_filter: str, attributes: list[str]) -> list[LdapObject]:
    objects: list[LdapObject] = []
    for row in _ldap_search(conn, base_dn, search_filter, attributes):
        dn, attrs = _ldap_row(row)
        if dn or attrs:
            objects.append(LdapObject(dn=dn, kind=kind, attributes=attrs))
    return objects


def _ldap_search(conn: Any, base_dn: str, search_filter: str, attributes: list[str]) -> list[Any]:
    search = getattr(conn, "search", None)
    if not callable(search):
        return []
    try:
        rows = search(base_dn, searchFilter=search_filter, attributes=attributes)
    except TypeError:
        rows = search(base_dn, search_filter, attributes)
    return list(rows or [])


def _ldap_first_attrs(rows: list[Any]) -> dict[str, Any]:
    if not rows:
        return {}
    return _ldap_row(rows[0])[1]


def _ldap_row(row: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(row, LdapObject):
        return row.dn, dict(row.attributes)
    if isinstance(row, dict):
        dn = str(row.get("dn") or row.get("distinguishedName") or "")
        attrs = row.get("attributes") if isinstance(row.get("attributes"), dict) else {k: v for k, v in row.items() if k not in {"dn"}}
        return dn, dict(attrs)
    dn = str(getattr(row, "dn", "") or getattr(row, "distinguishedName", "") or "")
    attrs = getattr(row, "attributes", None)
    if isinstance(attrs, dict):
        return dn, dict(attrs)
    return dn, {}


def _uac_no_preauth(value: Any) -> bool:
    try:
        raw = value[0] if isinstance(value, list) else value
        return bool(int(raw) & 0x00400000)
    except (TypeError, ValueError):
        return False


def _safe_error(exc: Exception) -> str:
    return str(exc).replace("\r", " ").replace("\n", " ")[:200]
