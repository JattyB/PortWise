"""Handoff / export layer.

PortWise stays read-only and never runs attacks. This module turns a completed
run into *suggested* command templates for the operator's own toolkit (NetExec,
ssh-audit, nuclei, ffuf, testssl, snmpwalk, dig, searchsploit, …), grouped by
the finding that motivates them. The operator reviews and runs them manually,
under their own authorization.

Nothing here executes; it only emits text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HandoffItem:
    category: str
    rationale: str
    target: str
    commands: list[str] = field(default_factory=list)
    requires_auth_note: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rationale": self.rationale,
            "target": self.target,
            "commands": self.commands,
            "credential_attack": self.requires_auth_note,
        }


def _findings(run: dict[str, Any]) -> list[dict[str, Any]]:
    return run.get("findings", []) or []


def _services(run: dict[str, Any]) -> list[dict[str, Any]]:
    state = (run.get("metadata", {}) or {}).get("state", {}) or {}
    out: list[dict[str, Any]] = []
    for host, svcs in (state.get("services_by_host", {}) or {}).items():
        for s in svcs:
            if str(s.get("state", "open")) in ("open", "open|filtered"):
                out.append(s)
    return out


def _title_has(f: dict[str, Any], *needles: str) -> bool:
    tl = str(f.get("title", "")).lower()
    return any(n in tl for n in needles)


def build_handoff(run: dict[str, Any]) -> list[HandoffItem]:
    items: list[HandoffItem] = []
    findings = _findings(run)
    services = _services(run)

    # ----- SMB: signing off / SMBv1 → relay + enumeration -----
    smb_hosts_signing = sorted({f["asset"] for f in findings if _title_has(f, "smb signing")})
    smb_hosts_v1 = sorted({f["asset"] for f in findings if _title_has(f, "smbv1")})
    for host in smb_hosts_signing:
        items.append(HandoffItem(
            "smb-relay",
            "SMB signing not required — candidate for NTLM relay.",
            host,
            [
                f"nxc smb {host} --gen-relay-list relay_targets.txt",
                f"nxc smb {host} -u '' -p '' --shares    # null-session share enum",
                f"enum4linux-ng -A {host}",
            ],
        ))
    for host in smb_hosts_v1:
        items.append(HandoffItem(
            "smb-legacy",
            "SMBv1 negotiable — check for MS17-010 / EternalBlue class exposure.",
            host,
            [
                f"nmap -p445 --script smb-vuln-ms17-010 {host}",
                f"nxc smb {host} -u '' -p '' --shares",
            ],
        ))

    # ----- SSH weak algorithms → reproduce + audit -----
    for f in findings:
        if not _title_has(f, "weak ssh", "deprecated ssh host key"):
            continue
        host, port = f.get("asset"), f.get("port") or 22
        cmds = [f"ssh-audit {host} -p {port}"]
        algos = _extract_listed_algos(f.get("description", ""))
        if "kex" in f.get("title", "").lower() and algos:
            cmds.append(f"ssh -oKexAlgorithms=+{algos[0]} -p {port} user@{host}    # repro negotiation")
        if "host key" in f.get("title", "").lower() and algos:
            cmds.append(f"ssh -oHostKeyAlgorithms=+{algos[0]} -p {port} user@{host}")
        items.append(HandoffItem("ssh-weak-crypto", f["title"] + ".", f"{host}:{port}", cmds))

    # ----- TLS issues → testssl/sslscan -----
    tls_hosts = sorted({(f["asset"], f.get("port") or 443) for f in findings
                        if _title_has(f, "tls", "ssl", "certificate", "heartbleed", "sweet32")
                        or (_title_has(f, "cipher") and not _title_has(f, "ssh"))})
    for host, port in tls_hosts:
        items.append(HandoffItem(
            "tls", "TLS/cert hardening finding — confirm protocols and ciphers.",
            f"{host}:{port}",
            [f"testssl.sh {host}:{port}", f"sslscan {host}:{port}"],
        ))

    # ----- HTTP targets → content + vuln scanning -----
    http_seen: set[tuple[str, int, str]] = set()
    for s in services:
        name = str(s.get("service_name", "")).lower()
        if "http" not in name:
            continue
        host, port = s.get("host"), int(s.get("port") or 0)
        scheme = "https" if ("https" in name or "ssl" in name or port in (443, 8443)) else "http"
        key = (host, port, scheme)
        if key in http_seen:
            continue
        http_seen.add(key)
        url = f"{scheme}://{host}:{port}"
        items.append(HandoffItem(
            "web", "Reachable web service — enumerate and scan.", url,
            [
                f"whatweb {url}",
                f"nuclei -u {url}",
                f"ffuf -u {url}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404",
                f"nikto -h {url}",
            ],
        ))

    # ----- SNMP default community -----
    for f in findings:
        if not _title_has(f, "snmp"):
            continue
        host = f.get("asset")
        if any(it.target == host and it.category == "snmp" for it in items):
            continue
        items.append(HandoffItem(
            "snmp", "SNMP exposed — enumerate via community strings.", host,
            [
                f"onesixtyone {host} public private",
                f"snmpwalk -v2c -c public {host}",
                f"snmp-check {host}",
            ],
        ))

    # ----- DNS zone transfer / recursion -----
    for f in findings:
        if _title_has(f, "zone transfer", "axfr"):
            host = f.get("asset")
            items.append(HandoffItem(
                "dns", "Zone transfer indicated — attempt AXFR.", host,
                [f"dig axfr @{host} <zone>", f"fierce --domain <zone> --dns-servers {host}"],
            ))

    # ----- RDP NLA / exposure -----
    for f in findings:
        if _title_has(f, "rdp nla", "weak rdp"):
            host, port = f.get("asset"), f.get("port") or 3389
            items.append(HandoffItem(
                "rdp", f["title"] + ".", f"{host}:{port}",
                [f"nxc rdp {host}", f"nmap -p{port} --script rdp-enum-encryption {host}"],
            ))

    # ----- Anonymous FTP / cleartext FTP -----
    for f in findings:
        if _title_has(f, "anonymous ftp"):
            host, port = f.get("asset"), f.get("port") or 21
            items.append(HandoffItem(
                "ftp", "Anonymous FTP login accepted — browse contents.", f"{host}:{port}",
                [f"ftp {host} {port}    # login anonymous", f"wget -r ftp://anonymous:anon@{host}:{port}/"],
            ))

    # ----- Default-credential KB hits -----
    for f in findings:
        if "default-creds" in (f.get("tags") or []):
            host, port = f.get("asset"), f.get("port") or 0
            items.append(HandoffItem(
                "default-creds",
                "Product commonly ships default creds — verify under authorization.",
                f"{host}:{port}",
                [
                    f"# {f.get('title','')}",
                    f"hydra -L users.txt -P passwords.txt {host} <service>    # scope/authorization required",
                ],
                requires_auth_note=True,
            ))

    # ----- CVE version-matched → searchsploit -----
    seen_products: set[str] = set()
    for f in findings:
        if str(f.get("type")) != "CVE":
            continue
        if str(f.get("confidence")) not in ("Likely", "Confirmed"):
            continue
        ev = (f.get("evidence") or [{}])[0].get("data", {}) if f.get("evidence") else {}
        product = str(ev.get("affected_product") or "").strip()
        version = str(ev.get("detected_version") or "").strip()
        key = f"{product} {version}".strip()
        if not key or key in seen_products:
            continue
        seen_products.add(key)
        cmds = [f"searchsploit {key}"]
        if f.get("cve_id"):
            cmds.append(f"nuclei -u <target> -id {f['cve_id']}    # if a template exists")
        items.append(HandoffItem(
            "cve", f"Version-matched {f.get('cve_id','CVE')} on {product} {version}.",
            f"{f.get('asset')}:{f.get('port')}", cmds,
        ))

    return items


def _extract_listed_algos(description: str) -> list[str]:
    """Pull the 'algo1, algo2' list out of a weak-algo finding description."""
    if ":" not in description:
        return []
    tail = description.split(":", 1)[1]
    tail = tail.split(".")[0]
    return [a.strip() for a in tail.split(",") if a.strip() and " " not in a.strip()][:4]


def render_script(items: list[HandoffItem]) -> str:
    """Render items as a commented, review-before-run shell script."""
    lines = [
        "#!/usr/bin/env bash",
        "# PortWise handoff — SUGGESTED commands for manual, authorized use.",
        "# PortWise did NOT run any of these. Review every line and confirm scope first.",
        "# Replace placeholders (user, <zone>, <target>, wordlists) as needed.",
        "set -u",
        "",
    ]
    by_cat: dict[str, list[HandoffItem]] = {}
    for it in items:
        by_cat.setdefault(it.category, []).append(it)
    for cat in sorted(by_cat):
        lines.append(f"# ===== {cat.upper()} =====")
        for it in by_cat[cat]:
            note = "  [CREDENTIAL ATTACK — explicit authorization required]" if it.requires_auth_note else ""
            lines.append(f"# {it.target}: {it.rationale}{note}")
            lines.extend(it.commands)
            lines.append("")
    return "\n".join(lines) + "\n"
