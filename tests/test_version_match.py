from __future__ import annotations


from portwise.intelligence.version_match import (
    cpe_product_matches,
    normalize_version,
    parse_cpe_version,
    version_in_range,
)


def test_version_in_range_basic():
    assert version_in_range("1.5.0", "1.0", None, None, "2.0") is True


def test_version_below_range():
    assert version_in_range("0.9.0", "1.0", None, None, "2.0") is False


def test_version_above_range():
    assert version_in_range("2.1.0", "1.0", None, None, "2.0") is False


def test_version_excludes_patched():
    # nginx 1.25.4 is NOT in the range [1.1.0, 1.25.3) — it's patched
    result = version_in_range("1.25.4", "1.1.0", None, None, "1.25.3")
    assert result is False


def test_version_at_end_exclusive_boundary():
    # 1.25.3 itself is excluded by versionEndExcluding=1.25.3
    assert version_in_range("1.25.3", "1.1.0", None, None, "1.25.3") is False


def test_version_at_end_inclusive_boundary():
    # 8.9 is IN range with versionEndIncluding=8.9
    assert version_in_range("8.9", "8.0", None, "8.9", None) is True


def test_version_start_exclusive():
    # start_exc=1.0 means >1.0 is required; 1.0 itself is excluded
    assert version_in_range("1.0", None, "1.0", None, "2.0") is False
    assert version_in_range("1.0.1", None, "1.0", None, "2.0") is True


def test_vendor_prefix_stripped():
    # OpenSSH_8.9p1 must normalize to a form comparable with "8.9"
    result = normalize_version("OpenSSH_8.9p1")
    assert result == "8.9"


def test_openssl_patch_letter_stripped():
    # 1.0.2k normalizes to 1.0.2 (patch letter stripped)
    result = normalize_version("1.0.2k")
    assert result == "1.0.2"


def test_plain_version_unchanged():
    assert normalize_version("1.25.4") == "1.25.4"


def test_openssh_version_in_range_with_prefix():
    # OpenSSH_8.9p1 should be considered in range 8.0-8.9 (inclusive)
    result = version_in_range("OpenSSH_8.9p1", "8.0", None, "8.9", None)
    assert result is True


def test_unparseable_version_returns_unknown():
    # Completely unparseable version returns None (not a false hit)
    result = version_in_range("NOT_A_VERSION_XYZ", "1.0", None, None, "2.0")
    assert result is None


def test_empty_version_returns_unknown():
    result = version_in_range("", "1.0", None, None, "2.0")
    assert result is None


def test_no_range_constraints_any_version_matches():
    # No version constraints → all versions affected
    assert version_in_range("1.2.3", None, None, None, None) is True


def test_parse_cpe_version_extracts_version():
    cpe = "cpe:2.3:a:nginx:nginx:1.25.4:*:*:*:*:*:*:*"
    assert parse_cpe_version(cpe) == "1.25.4"


def test_parse_cpe_version_wildcard_returns_none():
    cpe = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert parse_cpe_version(cpe) is None


def test_cpe_product_match_nginx_bare_name():
    criteria = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert cpe_product_matches("nginx", criteria) is True


def test_cpe_product_match_rejects_different_product():
    criteria = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert cpe_product_matches("apache", criteria) is False
    assert cpe_product_matches("httpd", criteria) is False


def test_cpe_product_match_full_cpe_vs_cpe():
    detected = "cpe:2.3:a:nginx:nginx:1.25.4:*:*:*:*:*:*:*"
    criteria = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert cpe_product_matches(detected, criteria) is True


def test_cpe_product_match_openssh():
    criteria = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    assert cpe_product_matches("openssh", criteria) is True
    assert cpe_product_matches("OpenSSH", criteria) is True


def test_cpe_product_match_rejects_malformed_criteria():
    assert cpe_product_matches("nginx", "not:a:cpe") is False
