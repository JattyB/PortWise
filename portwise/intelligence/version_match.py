from __future__ import annotations

import re
from typing import Any

try:
    from packaging.version import InvalidVersion, Version as _PkgVersion

    def _parse(v: str) -> Any:
        return _PkgVersion(v)

    def _cmp(a: Any, b: Any) -> int:
        if a < b:
            return -1
        if a > b:
            return 1
        return 0

    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False
    InvalidVersion = Exception  # type: ignore[assignment,misc]

    def _parse(v: str) -> tuple[int, ...]:  # type: ignore[misc]
        return tuple(int(x) for x in v.split(".") if x.isdigit())

    def _cmp(a: Any, b: Any) -> int:  # type: ignore[misc]
        if a < b:
            return -1
        if a > b:
            return 1
        return 0


_VENDOR_PREFIX = re.compile(
    r"^(?:openssh[_/]|nginx[/]|apache[_/]|httpd[_/]|linux[_/]|"
    r"openssl[_/]|php[_/]|samba[_/]|mariadb[_/]|mysql[_/])",
    re.IGNORECASE,
)

# Matches a trailing portable/patch letter suffix on the last numeric component.
# Examples: "9p1" -> strip "p1" -> "9"; "2k" -> strip "k" -> "2"
_PATCH_SUFFIX = re.compile(r"[a-zA-Z]\w*$")


def normalize_version(raw: str) -> str | None:
    """
    Strip vendor prefix and portable/patch-letter suffix, return a clean
    dot-separated numeric string suitable for comparison, or None if the
    version cannot be meaningfully parsed.

    Examples:
      "OpenSSH_8.9p1" -> "8.9"
      "1.0.2k"        -> "1.0.2"
      "1.25.4"        -> "1.25.4"
      ""              -> None
    """
    v = _VENDOR_PREFIX.sub("", (raw or "").strip())
    if not v:
        return None

    if _HAS_PACKAGING:
        try:
            _parse(v)
            return v
        except InvalidVersion:
            pass

    # Strip trailing patch-letter suffix from the last component.
    # Split on last dot so we only alter the final segment.
    dot_idx = v.rfind(".")
    if dot_idx >= 0:
        base, last = v[:dot_idx], v[dot_idx + 1 :]
        clean_last = _PATCH_SUFFIX.sub("", last)
        if clean_last.isdigit():
            candidate = f"{base}.{clean_last}"
            if _HAS_PACKAGING:
                try:
                    _parse(candidate)
                    return candidate
                except InvalidVersion:
                    pass
            if re.match(r"^\d+(\.\d+)*$", candidate):
                return candidate

    # Try stripping from the whole string (no dots, e.g. bare "2k")
    no_suffix = _PATCH_SUFFIX.sub("", v)
    if no_suffix and re.match(r"^\d+(\.\d+)*$", no_suffix):
        return no_suffix

    return None


def parse_cpe_version(cpe: str) -> str | None:
    """Extract the version field from a CPE 2.3 string. Returns None for wildcards."""
    parts = cpe.split(":")
    if len(parts) >= 6:
        ver = parts[5]
        if ver not in ("*", "-", ""):
            return ver
    return None


def version_in_range(
    detected: str | None,
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
) -> bool | None:
    """
    Returns True if *detected* falls within the version range, False if it
    is definitively outside, or None if the version cannot be confidently
    parsed (callers must treat None as needs-manual-validation, not a hit).
    """
    if not detected:
        return None

    det_str = normalize_version(detected)
    if det_str is None:
        return None

    try:
        det = _parse(det_str)
    except Exception:
        return None

    def _bound(raw: str | None) -> Any | None:
        if raw is None:
            return None
        s = normalize_version(raw)
        if s is None:
            return _SENTINEL
        try:
            return _parse(s)
        except Exception:
            return _SENTINEL

    _SENTINEL = object()  # signals unparseable bound

    si = _bound(start_inc)
    if si is _SENTINEL:
        return None
    if si is not None and _cmp(det, si) < 0:
        return False

    se = _bound(start_exc)
    if se is _SENTINEL:
        return None
    if se is not None and _cmp(det, se) <= 0:
        return False

    ei = _bound(end_inc)
    if ei is _SENTINEL:
        return None
    if ei is not None and _cmp(det, ei) > 0:
        return False

    ee = _bound(end_exc)
    if ee is _SENTINEL:
        return None
    if ee is not None and _cmp(det, ee) >= 0:
        return False

    return True


# Maps an nmap-style product token to the CPE product field it corresponds to.
# Nmap reports human names ("Apache httpd"), NVD CPEs use normalized products
# ("http_server"), so without these aliases a real match would be missed.
_PRODUCT_ALIASES: dict[str, str] = {
    "apache": "http_server",
    "httpd": "http_server",
    "iis": "internet_information_services",
    "named": "bind",
    "smbd": "samba",
    "nginx": "nginx",
    "openssh": "openssh",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "pureftpd": "pure-ftpd",
    "exim": "exim",
    "postfix": "postfix",
    "dovecot": "dovecot",
    "mariadb": "mariadb",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def cpe_product_matches(detected: str, criteria_cpe: str) -> bool:
    """
    Returns True if *detected* (a bare product name or a CPE string) refers
    to the same vendor:product as *criteria_cpe*.

    Matching is intentionally strict: exact CPE vendor:product, exact bare
    name, a whole *token* of the detected name, or a curated alias. The old
    loose ``d in vendor or d in product`` substring rule was removed because
    it produced cross-product false matches (e.g. "sql" matching every SQL
    engine, "ssh" matching "openssh"), which was a major false-positive source.
    """
    parts = criteria_cpe.split(":")
    if len(parts) < 5:
        return False
    vendor = parts[3].lower()
    product = parts[4].lower()
    if not product or product in ("*", "-"):
        return False

    d = (detected or "").strip().lower()
    if not d:
        return False

    if d.startswith("cpe:"):
        det_parts = detected.split(":")
        if len(det_parts) >= 5:
            return det_parts[3].lower() == vendor and det_parts[4].lower() == product
        return False

    if d == product or d == vendor:
        return True

    tokens = set(_TOKEN_RE.findall(d.replace("-", "")))
    if product in tokens or vendor in tokens:
        return True
    for token in tokens:
        if _PRODUCT_ALIASES.get(token) == product:
            return True
    return False
