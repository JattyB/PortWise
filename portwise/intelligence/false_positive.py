from __future__ import annotations

from portwise.core.models import Confidence, Finding, FindingCategory, Severity
from portwise.intelligence.constants import BACKPORT_SENSITIVE

BACKPORT_HINTS = BACKPORT_SENSITIVE

_ABOVE_LOW = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def apply_category_rules(finding: Finding) -> Finding:
    """Enforce severity caps based on finding category (detection-confidence axis is separate)."""
    if finding.category == FindingCategory.INFORMATION:
        finding.severity = Severity.INFO
    elif finding.category in {FindingCategory.BEST_PRACTICE, FindingCategory.HYGIENE}:
        if finding.severity in _ABOVE_LOW:
            finding.severity = Severity.LOW
    return finding


_CONFIDENCE_RANK = {
    "Confirmed": 0,
    "Likely": 1,
    "Possible": 2,
    "Needs Manual Validation": 3,
    "Informational": 4,
    "False Positive Candidate": 5,
}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse issue families and merge endpoint instances and evidence."""
    preferred_by_endpoint = _preferred_issue_families(findings)
    best: dict[tuple[str, int | str, str], Finding] = {}
    order: list[tuple[str, int | str, str]] = []
    for finding in findings:
        issue = _semantic_issue(finding, preferred_by_endpoint)
        scope: int | str = "*" if issue in _CROSS_INSTANCE_ISSUES else int(finding.port or 0)
        key = (
            str(finding.asset),
            scope,
            issue,
        )
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            order.append(key)
            continue
        # Prefer higher detection confidence, then higher evidence strength.
        new_rank = _CONFIDENCE_RANK.get(str(finding.confidence), 9)
        old_rank = _CONFIDENCE_RANK.get(str(existing.confidence), 9)
        if (new_rank, -finding.evidence_strength) < (old_rank, -existing.evidence_strength):
            _merge_finding(finding, existing)
            best[key] = finding
        else:
            _merge_finding(existing, finding)
    return [best[key] for key in order]


_CROSS_INSTANCE_ISSUES = {
    "smbv1-enabled",
    "smb-anonymous-enumeration",
    "database-version-disclosure",
    "content-fuzzer-additional-paths",
    "missing-http-security-headers",
    "default-credentials-advisory",
}


def _preferred_issue_families(findings: list[Finding]) -> dict[tuple[str, int, str], set[str]]:
    found: dict[tuple[str, int, str], set[str]] = {}
    for finding in findings:
        endpoint = (str(finding.asset), int(finding.port or 0), str(finding.protocol or ""))
        found.setdefault(endpoint, set()).add(str(finding.title).lower())
    return found


def _semantic_issue(
    finding: Finding,
    preferred: dict[tuple[str, int, str], set[str]],
) -> str:
    title = str(finding.title).strip().lower()
    endpoint = (str(finding.asset), int(finding.port or 0), str(finding.protocol or ""))
    titles = preferred.get(endpoint, set())
    service = str(finding.service or "").lower()
    text = f"{title} {service}"

    if finding.cve_id:
        return f"cve:{str(finding.cve_id).upper()}"
    if title in {"smb null session accepted", "smb share enumeration"}:
        return "smb-anonymous-enumeration"
    if title == "smbv1 enabled":
        return "smbv1-enabled"
    if title == "content fuzzer discovered additional paths":
        return "content-fuzzer-additional-paths"
    if title.startswith("default credentials should be manually verified"):
        return "default-credentials-advisory"
    if title.startswith("missing ") and (
        "header" in title or "content security policy" in title or "x-frame-options" in title
        or "x-content-type-options" in title
    ):
        return "missing-http-security-headers"
    if title in {
        "http service metadata", "http technology fingerprint",
        "apache server detected", "apache detection",
    }:
        return "http-server-version-disclosure" if "http server version disclosure" in titles else "http-component-fingerprint"
    if title == "http server version disclosure":
        return "http-server-version-disclosure"
    if title in {"http framework version disclosure", "php detect"}:
        return "http-framework-version-disclosure"
    if "php info page" in title or "phpinfo page" in title:
        return "exposed-phpinfo"
    if title == "exposed phpinfo page":
        return "exposed-phpinfo"

    if "ftp" in text and _generic_exposure_title(title):
        if any("cleartext protocol exposed" in item and "ftp" in item for item in titles):
            return "cleartext:ftp"
        return "service-exposure:ftp"
    if "telnet" in text and _generic_exposure_title(title):
        if any("cleartext protocol exposed" in item and "telnet" in item for item in titles):
            return "cleartext:telnet"
        return "service-exposure:telnet"
    if ("smb" in text or "microsoft-ds" in text or "netbios" in text) and _generic_exposure_title(title):
        if "smbv1 enabled" in titles:
            return "smbv1 enabled"
        return "service-exposure:smb"
    if "ssh" in text and _generic_exposure_title(title):
        if "ssh version disclosure" in titles or "legacy ssh service" in titles:
            return "ssh-legacy-version"
        return "service-exposure:ssh"
    if "tomcat" in text and _generic_exposure_title(title):
        if any("tomcat manager" in item for item in titles):
            return "tomcat-manager-exposure"
        return "service-exposure:tomcat"
    if "tomcat manager" in title or (
        title == "login page detected" and any("tomcat manager" in item for item in titles)
    ):
        return "tomcat-manager-exposure"
    if title == "dns service exposed" and "dns version disclosure" in titles:
        return "dns-version-disclosure"
    if title == "dns version disclosure":
        return "dns-version-disclosure"
    if title == "database service exposed" and "database version disclosure" in titles:
        return "database-version-disclosure"
    if title == "database version disclosure":
        return "database-version-disclosure"
    if title == "smtp service exposed" and "mail server version disclosure" in titles:
        return "mail-version-disclosure"
    if title == "mail server version disclosure":
        return "mail-version-disclosure"
    if title == "ftp cleartext service exposed":
        return "cleartext:ftp"
    if title.startswith("cleartext protocol exposed"):
        return "cleartext:" + title.rsplit("—", 1)[-1].strip().lower()
    if title in {"ssh version disclosure", "legacy ssh service"}:
        return "ssh-legacy-version"
    if title in {
        "weak ssh key exchange algorithm", "weak ssh cipher",
        "weak ssh mac algorithm", "deprecated ssh host key type",
    }:
        return "weak-ssh-cryptography"
    return title


def _generic_exposure_title(title: str) -> bool:
    return (
        title.startswith("exposed ")
        or title.endswith(" service exposed")
        or "needs owner validation" in title
    )


def _merge_finding(target: Finding, source: Finding) -> None:
    ports = {
        int(port)
        for port in [target.port, source.port, *target.affected_ports, *source.affected_ports]
        if port
    }
    target.affected_ports = sorted(ports)
    evidence_ids = {item.id for item in target.evidence}
    for item in source.evidence:
        if item.id not in evidence_ids:
            target.evidence.append(item)
            evidence_ids.add(item.id)
    target.evidence_strength = max(target.evidence_strength, source.evidence_strength)
    for attr in ("tags", "references", "exploit_refs"):
        values = getattr(target, attr)
        for value in getattr(source, attr):
            if value not in values:
                values.append(value)
    target.exploit_available = target.exploit_available or source.exploit_available
    target.kev = target.kev or source.kev
    if target.epss is None or (source.epss is not None and source.epss > target.epss):
        target.epss = source.epss
        target.epss_percentile = source.epss_percentile
    if _semantic_title_group(target.title) == "headers":
        target.title = "Missing HTTP Security Headers"
        target.description = "Multiple recommended HTTP response security headers are absent."
        target.recommendation = "Add the missing headers with values appropriate to the application."
    title_group = _semantic_title_group(target.title)
    if title_group == "phpinfo":
        target.title = "Exposed phpinfo Page"
        target.description = (
            "The exposed phpinfo page discloses PHP, module, filesystem, "
            "environment, and server configuration details."
        )
        target.recommendation = "Remove the phpinfo page from the deployed application."
    elif title_group == "http-component":
        target.title = "HTTP Server Version Disclosure"
    elif title_group == "http-framework":
        target.title = "HTTP Framework Version Disclosure"
    elif title_group == "ssh-legacy":
        target.title = "Legacy SSH Service"
        target.description = "The SSH service discloses an obsolete OpenSSH release."
    elif title_group == "ssh-crypto":
        target.title = "Weak SSH Cryptography"
        target.description = (
            "The SSH service offers deprecated key exchange, cipher, MAC, "
            "or host-key algorithms."
        )
        target.recommendation = "Disable the deprecated algorithms and retain modern SHA-2 and AEAD suites."
    if _semantic_issue(target, {}) == "smb-anonymous-enumeration":
        target.title = "SMB Null Session and Share Enumeration"
        target.description = (
            "An anonymous SMB session enumerated network shares without credentials."
        )
        target.recommendation = "Disable anonymous SMB sessions and restrict share access to required accounts."


def _semantic_title_group(title: str) -> str:
    value = title.lower()
    if value.startswith("missing ") and (
        "header" in value or "content security policy" in value
        or "x-frame-options" in value or "x-content-type-options" in value
    ):
        return "headers"
    if "php info page" in value or "phpinfo page" in value:
        return "phpinfo"
    if value in {
        "http service metadata", "http technology fingerprint",
        "apache server detected", "apache detection", "http server version disclosure",
    }:
        return "http-component"
    if value in {"http framework version disclosure", "php detect"}:
        return "http-framework"
    if value in {"ssh version disclosure", "legacy ssh service"}:
        return "ssh-legacy"
    if value in {
        "weak ssh key exchange algorithm", "weak ssh cipher",
        "weak ssh mac algorithm", "deprecated ssh host key type",
    }:
        return "ssh-crypto"
    return ""


def apply_false_positive_rules(finding: Finding, context: str = "unknown") -> Finding:
    text = " ".join([finding.title, finding.description, " ".join(finding.tags)]).lower()

    if "banner-only" in finding.tags or "version-only" in finding.tags:
        finding.confidence = Confidence.NEEDS_MANUAL_VALIDATION
        if "Needs Manual Validation" not in finding.tags:
            finding.tags.append("Needs Manual Validation")

    if any(hint in text for hint in BACKPORT_HINTS) and ("version" in text or "cpe" in text):
        finding.confidence = Confidence.NEEDS_MANUAL_VALIDATION
        if "backport-sensitive" not in finding.tags:
            finding.tags.append("backport-sensitive")

    if "hsts" in text and context in {"internal", "unknown"}:
        finding.severity = Severity.LOW
        if "contextual" not in finding.tags:
            finding.tags.append("contextual")

    if "udp open|filtered" in text:
        finding.confidence = Confidence.NEEDS_MANUAL_VALIDATION
        if "udp-open-filtered" not in finding.tags:
            finding.tags.append("udp-open-filtered")

    if "nmap-guessed" in finding.tags and finding.confidence == Confidence.LIKELY:
        finding.confidence = Confidence.POSSIBLE

    if "exact-cpe" in finding.tags and finding.evidence_strength < 3:
        finding.evidence_strength = 3
        if finding.confidence == Confidence.NEEDS_MANUAL_VALIDATION:
            finding.confidence = Confidence.POSSIBLE

    # NOTE: The blanket "safe-active → CONFIRMED" rule was removed.
    # safe-active raises *detection* confidence (handled in confidence.py),
    # but category and severity are set independently by the module.

    return finding
