from __future__ import annotations

import re
from typing import Any


def _get_scripts(source: Any) -> dict[str, Any]:
    if hasattr(source, "scripts"):
        return source.scripts or {}
    if isinstance(source, dict):
        return source.get("scripts") or {}
    return {}


def _script_entry(source: Any, script_id: str) -> dict[str, Any] | None:
    entry = _get_scripts(source).get(script_id)
    return entry if isinstance(entry, dict) else None


def _script_text(source: Any, script_id: str) -> str:
    entry = _script_entry(source, script_id)
    return entry.get("output", "") if entry else ""


def _script_data(source: Any, script_id: str) -> Any:
    entry = _script_entry(source, script_id)
    return entry.get("data") if entry else None


def _iter_items(container: Any) -> list[Any]:
    """Return list items from a parsed NSE container (list or mixed dict)."""
    if isinstance(container, list):
        return container
    if isinstance(container, dict):
        return container.get("_items", [])
    return []


def nse_ssl_ciphers(source: Any) -> dict[str, list[dict[str, str]]]:
    """Returns {tls_version: [{name, kex_info, strength}, ...]}"""
    data = _script_data(source, "ssl-enum-ciphers")
    if not isinstance(data, dict):
        return {}
    result: dict[str, list[dict[str, str]]] = {}
    for version, version_data in data.items():
        if version.startswith("_"):
            continue
        ciphers: list[dict[str, str]] = []
        for item in _iter_items(version_data):
            if isinstance(item, dict) and "name" in item:
                ciphers.append({
                    "name": str(item.get("name", "")),
                    "kex_info": str(item.get("kex_info", "")),
                    "strength": str(item.get("strength", "")),
                })
        if ciphers:
            result[version] = ciphers
    return result


def nse_ssh_algos(source: Any) -> dict[str, list[str]]:
    """Returns {kex, encryption, mac, hostkey} each a list of algorithm names."""
    data = _script_data(source, "ssh2-enum-algos")
    if not isinstance(data, dict):
        return {}
    mapping = {
        "kex": "kex_algorithms",
        "encryption": "encryption_algorithms",
        "mac": "mac_algorithms",
        "hostkey": "server_host_key_algorithms",
    }
    result: dict[str, list[str]] = {}
    for out_key, nse_key in mapping.items():
        raw = data.get(nse_key, [])
        items = raw if isinstance(raw, list) else _iter_items(raw)
        algos = [str(a) for a in items if a]
        if algos:
            result[out_key] = algos
    return result


def nse_smb_security(source: Any) -> dict[str, Any]:
    """Returns {signing, smbv1, raw} from smb-security-mode / smb2-security-mode."""
    result: dict[str, Any] = {}

    # smb2-security-mode (SMBv2/3 signing state — most reliable)
    smb2_text = _script_text(source, "smb2-security-mode")
    if smb2_text:
        result["smb2_raw"] = smb2_text
        tl = smb2_text.lower()
        if "signing enabled and required" in tl:
            result["signing"] = "required"
        elif "signing enabled but not required" in tl or "signing not required" in tl:
            result["signing"] = "not_required"
        elif "signing disabled" in tl:
            result["signing"] = "disabled"

    # smb-security-mode (SMBv1)
    smb1_text = _script_text(source, "smb-security-mode")
    if smb1_text:
        result["smbv1"] = True
        result["smb1_raw"] = smb1_text
        tl = smb1_text.lower()
        if "signing" not in result:
            if "message signing disabled" in tl or "signing: disabled" in tl:
                result["signing"] = "disabled"
            elif "message signing enabled" in tl:
                result["signing"] = "not_required"

    # Structured data from either script
    for sid in ("smb2-security-mode", "smb-security-mode"):
        data = _script_data(source, sid)
        if isinstance(data, dict):
            result.setdefault("structured", data)
            break

    return result


def nse_smb_os(source: Any) -> dict[str, str]:
    """Returns {os, computer_name, domain, workgroup, fqdn} from smb-os-discovery."""
    result: dict[str, str] = {}
    data = _script_data(source, "smb-os-discovery")
    if isinstance(data, dict):
        key_map = {
            "OS": "os",
            "Computer name": "computer_name",
            "Domain": "domain",
            "Workgroup": "workgroup",
            "FQDN": "fqdn",
            "NetBIOS computer name": "netbios_name",
        }
        for src, dst in key_map.items():
            if src in data:
                result[dst] = str(data[src])
    raw = _script_text(source, "smb-os-discovery")
    if raw and not result:
        result["raw"] = raw
    return result


def nse_rdp_ntlm(source: Any) -> dict[str, str]:
    """Returns parsed rdp-enum-encryption / rdp-ntlm-info dict."""
    result: dict[str, str] = {}
    for sid in ("rdp-ntlm-info", "rdp-enum-encryption"):
        data = _script_data(source, sid)
        items = _iter_items(data) if not isinstance(data, dict) else [data]
        for item in items:
            if isinstance(item, dict):
                for k, v in item.items():
                    result[k.lower().replace(" ", "_")] = str(v)
        if isinstance(data, dict) and not items:
            for k, v in data.items():
                result[k.lower().replace(" ", "_")] = str(v)
        raw = _script_text(source, sid)
        if raw:
            result.setdefault("raw", raw)
            tl = raw.lower()
            if "nla: disabled" in tl or "nla:disabled" in tl:
                result["nla"] = "disabled"
            elif "nla: enabled" in tl or "nla:enabled" in tl:
                result["nla"] = "enabled"
    return result


def nse_ftp_anon(source: Any) -> bool:
    """Returns True if ftp-anon indicates anonymous login is allowed."""
    text = _script_text(source, "ftp-anon")
    if not text:
        return False
    tl = text.lower()
    return "anonymous ftp login allowed" in tl or ("anonymous" in tl and "denied" not in tl)


def nse_http_methods(source: Any) -> list[str]:
    """Returns list of HTTP methods from http-methods script output."""
    text = _script_text(source, "http-methods")
    if not text:
        return []
    methods: list[str] = []
    for line in text.splitlines():
        ll = line.lower()
        if "supported methods:" in ll or "potentially risky methods:" in ll:
            parts = line.split(":", 1)
            if len(parts) > 1:
                methods.extend(m.strip() for m in parts[1].split() if m.strip())
    if not methods:
        methods = re.findall(
            r"\b(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT|MOVE|COPY|MKCOL|PROPFIND|PROPPATCH|LOCK|UNLOCK)\b",
            text,
        )
    return list(dict.fromkeys(methods))


def nse_dns_recursion(source: Any) -> bool:
    """Returns True if dns-recursion script indicates recursion is enabled."""
    text = _script_text(source, "dns-recursion")
    if not text:
        return False
    return "enabled" in text.lower()


def nse_snmp_info(source: Any) -> dict[str, str]:
    """Returns combined SNMP info from snmp-info / snmp-sysdescr scripts."""
    result: dict[str, str] = {}
    for sid in ("snmp-info", "snmp-sysdescr"):
        data = _script_data(source, sid)
        if isinstance(data, dict):
            result.update({k: str(v) for k, v in data.items()})
        raw = _script_text(source, sid)
        if raw:
            result.setdefault("raw", raw)
    return result


def nse_ssl_cert(source: Any) -> dict[str, Any]:
    """Returns {subject, issuer, sig_alg, pubkey_bits, not_before, not_after, sans}."""
    result: dict[str, Any] = {}
    data = _script_data(source, "ssl-cert")
    if isinstance(data, dict):
        result["subject"] = data.get("subject", {})
        result["issuer"] = data.get("issuer", {})
        result["sig_alg"] = str(data.get("signature algorithm", data.get("sig_alg", "")))
        result["pubkey_bits"] = str(data.get("Public Key type", data.get("pubkey_bits", "")))
        result["not_before"] = str(data.get("Not valid before", data.get("not_before", "")))
        result["not_after"] = str(data.get("Not valid after", data.get("not_after", "")))
        result["sans"] = str(data.get("Subject Alternative Name", data.get("sans", "")))
    raw = _script_text(source, "ssl-cert")
    if raw and not result:
        result["raw"] = raw
    return result
