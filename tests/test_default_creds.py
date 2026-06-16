from __future__ import annotations

import inspect


from portwise.intelligence.default_creds import (
    ATTEMPTS_AUTH,
    DEFAULT_CREDS,
    lookup_default_creds,
)
from portwise.modules.registry import _default_cred_note
from portwise.core.models import Confidence, FindingCategory, Severity


# ---------------------------------------------------------------------------
# Guardrail: module NEVER attempts authentication
# ---------------------------------------------------------------------------

def test_module_never_attempts_auth():
    assert ATTEMPTS_AUTH is False

    import portwise.intelligence.default_creds as mod
    src = inspect.getsource(mod)
    # No socket or login calls must exist in the module
    forbidden = ["socket.create_connection", "ftplib", "paramiko", "requests.post", ".login(", "ssh.connect"]
    for token in forbidden:
        assert token not in src, f"Found forbidden auth token in default_creds.py: {token!r}"


# ---------------------------------------------------------------------------
# Knowledge base integrity
# ---------------------------------------------------------------------------

def test_references_present_for_each_kb_entry():
    for key, entry in DEFAULT_CREDS.items():
        refs = entry.get("references", [])
        assert refs, f"No references for {key!r}"
        for ref in refs:
            assert ref.startswith("http"), f"Reference in {key!r} doesn't look like a URL: {ref!r}"


def test_kb_entries_have_required_fields():
    for key, entry in DEFAULT_CREDS.items():
        assert "notes" in entry, f"Missing 'notes' in {key!r}"
        assert "references" in entry, f"Missing 'references' in {key!r}"
        assert "risk" in entry, f"Missing 'risk' in {key!r}"
        assert "severity" in entry, f"Missing 'severity' in {key!r}"
        assert entry["severity"] in {"low", "medium", "high"}, f"Invalid severity in {key!r}"


# ---------------------------------------------------------------------------
# Lookup behaviour
# ---------------------------------------------------------------------------

def test_default_cred_note_attached_when_product_detected():
    target = {"host": "10.0.0.1", "port": 6379, "protocol": "tcp", "service": "redis",
               "product": "Redis", "version": "6.2", "routing_reason": "", "cpe": []}
    note = _default_cred_note("database", target, "redis 6.2")
    assert note is not None
    assert "redis" in note.title.lower()
    assert note.manual_validation is True
    assert note.confidence == Confidence.INFORMATIONAL
    assert note.category == FindingCategory.BEST_PRACTICE


def test_no_note_without_product_detection():
    target = {"host": "10.0.0.1", "port": 9999, "protocol": "tcp", "service": "unknown",
               "product": "", "version": "", "routing_reason": "", "cpe": []}
    note = _default_cred_note("database", target, "unknown")
    assert note is None


def test_note_is_informational_best_practice_not_confirmed_vuln():
    target = {"host": "10.0.0.1", "port": 3000, "protocol": "tcp", "service": "grafana",
               "product": "Grafana", "version": "9.0", "routing_reason": "", "cpe": []}
    note = _default_cred_note("devops", target, "grafana 9.0")
    assert note is not None
    assert note.category == FindingCategory.BEST_PRACTICE
    assert note.confidence == Confidence.INFORMATIONAL
    assert note.confidence != Confidence.CONFIRMED
    assert "PortWise does NOT attempt authentication" in note.description


def test_unauth_sensitive_panel_note_is_medium_or_high():
    # elasticsearch is "high" severity in KB
    target = {"host": "10.0.0.1", "port": 9200, "protocol": "tcp", "service": "elasticsearch",
               "product": "Elasticsearch", "version": "7.9", "routing_reason": "", "cpe": []}
    note = _default_cred_note("database", target, "elasticsearch 7.9")
    assert note is not None
    assert note.severity in {Severity.MEDIUM, Severity.HIGH}


def test_lookup_default_creds_returns_none_for_unknown():
    assert lookup_default_creds("some-obscure-service-xyz") is None


def test_lookup_default_creds_returns_entry_for_known():
    result = lookup_default_creds("jenkins ci automation")
    assert result is not None
    kb_key, entry = result
    assert kb_key == "jenkins"
    assert "pairs" in entry
