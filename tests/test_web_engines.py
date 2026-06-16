from __future__ import annotations

from portwise.core.external_tool import ExternalToolResult
from portwise.core.models import FindingCategory, Severity
from portwise.intelligence.web_engines import (
    parse_ffuf_results,
    parse_nuclei_records,
    run_ffuf,
    run_nuclei,
    run_web_engines,
)


# --- Fixtures modelled on real nuclei -jsonl / ffuf -of json output ----------

NUCLEI_RECORDS = [
    {
        "template-id": "CVE-2021-44228",
        "template-url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "Log4j JNDI RCE",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "classification": {"cve-id": "CVE-2021-44228", "cvss-score": 10.0},
        },
        "type": "http",
        "host": "10.0.0.5:8080",
        "port": "8080",
        "matched-at": "http://10.0.0.5:8080/api",
        "extracted-results": ["jndi"],
        "curl-command": "curl -X GET http://10.0.0.5:8080/api",
    },
    {
        "template-id": "tech-detect",
        "info": {"name": "Nginx Detected", "severity": "info"},
        "type": "http",
        "host": "10.0.0.5",
        "port": "8080",
        "matched-at": "http://10.0.0.5:8080/",
    },
]

FFUF_DOCUMENT = {
    "commandline": "ffuf ...",
    "results": [
        {"input": {"FUZZ": "admin"}, "url": "http://10.0.0.5:8080/admin", "status": 200, "length": 1234, "words": 100, "lines": 50, "content-type": "text/html"},
        {"input": {"FUZZ": "login"}, "url": "http://10.0.0.5:8080/login", "status": 302, "length": 0, "words": 0, "lines": 0, "content-type": ""},
        {"input": {"FUZZ": "missing"}, "url": "http://10.0.0.5:8080/missing", "status": 404, "length": 9, "words": 1, "lines": 1, "content-type": "text/plain"},
        {"input": {"FUZZ": "robots.txt"}, "url": "http://10.0.0.5:8080/robots.txt", "status": 200, "length": 20, "words": 3, "lines": 2, "content-type": "text/plain"},
    ],
}

TARGET = {"host": "10.0.0.5", "port": 8080, "protocol": "tcp", "service": "http"}


class _FakeTool:
    def __init__(self, records, *, ok=True, available=True):
        self._records = records
        self._ok = ok
        self._available = available
        self.calls: list[list[str]] = []

    def run_json(self, args, *, jsonl=False, handoff_command=None, stdout_path=None, timeout=None, input_text=None):
        self.calls.append(list(args))
        result = ExternalToolResult(tool="fake", available=self._available, handoff_command=handoff_command)
        if self._ok:
            result.ran = True
            result.records = self._records
            result.parsed = self._records
        else:
            result.ran = self._available
            result.error = "engine failed" if self._available else None
            result.skipped_reason = None if self._available else "not found"
        return result


# --- nuclei parsing ----------------------------------------------------------

def test_parse_nuclei_records_maps_fields():
    findings = parse_nuclei_records(NUCLEI_RECORDS)
    assert len(findings) == 2
    crit = findings[0]
    assert crit.title == "Apache Log4j RCE"
    assert crit.severity == Severity.CRITICAL
    assert crit.asset == "10.0.0.5"
    assert crit.port == 8080
    assert crit.cve_id == "CVE-2021-44228"
    assert crit.cvss == 10.0
    assert crit.category == FindingCategory.VULNERABILITY
    assert "nuclei" in crit.tags and "external-engine" in crit.tags and "cve" in crit.tags
    assert crit.evidence[0].data["template_id"] == "CVE-2021-44228"
    assert crit.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]

    info = findings[1]
    assert info.severity == Severity.INFO
    assert info.category == FindingCategory.INFORMATION


def test_parse_nuclei_handles_garbage():
    assert parse_nuclei_records([{"info": "not-a-dict"}, "junk", {}]) [0].title  # no crash; first record yields a finding


# --- ffuf parsing ------------------------------------------------------------

def test_parse_ffuf_filters_uninteresting_and_maps():
    findings = parse_ffuf_results(FFUF_DOCUMENT, target=TARGET)
    paths = sorted(f.title for f in findings)
    # 404 dropped; admin/login/robots kept
    assert any("/admin" in p for p in paths)
    assert any("/login" in p for p in paths)
    assert not any("/missing" in p for p in paths)
    admin = next(f for f in findings if "/admin" in f.title)
    assert admin.severity == Severity.LOW
    assert admin.evidence[0].data["status"] == 200
    assert "ffuf" in admin.tags


def test_parse_ffuf_skip_paths():
    findings = parse_ffuf_results(FFUF_DOCUMENT, target=TARGET, skip_paths={"/robots.txt", "/admin"})
    paths = [f.title for f in findings]
    assert not any("/admin" in p for p in paths)
    assert not any("/robots.txt" in p for p in paths)
    assert any("/login" in p for p in paths)


# --- run wrappers ------------------------------------------------------------

def test_run_nuclei_with_fake_tool():
    findings, note = run_nuclei(TARGET, {"web_engines": {"nuclei": {"enabled": True}}}, tool=_FakeTool(NUCLEI_RECORDS))
    assert len(findings) == 2
    assert "2 finding" in note


def test_run_nuclei_disabled():
    findings, note = run_nuclei(TARGET, {"web_engines": {"nuclei": {"enabled": False}}}, tool=_FakeTool([]))
    assert findings == []
    assert "disabled" in note


def test_run_nuclei_missing_binary_real_adapter():
    # No fake tool -> real ExternalTool for a non-existent binary -> graceful skip + handoff.
    findings, note = run_nuclei(
        {"host": "10.0.0.5", "port": 80, "service": "http"},
        {"web_engines": {"nuclei": {"enabled": True}}},
        tool=__import__("portwise.core.external_tool", fromlist=["ExternalTool"]).ExternalTool("nuclei", binary="nuclei-not-real-xyz"),
    )
    assert findings == []
    assert "not installed" in note and "handoff" in note


def test_run_ffuf_without_wordlist_emits_handoff():
    findings, note = run_ffuf(TARGET, {"web_engines": {"ffuf": {"enabled": True}}}, tool=_FakeTool([FFUF_DOCUMENT]))
    assert findings == []
    assert "wordlist" in note and "handoff" in note


def test_run_ffuf_with_wordlist_and_fake_tool(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\n", encoding="utf-8")
    config = {"web_engines": {"ffuf": {"enabled": True, "wordlist": str(wl)}}}
    findings, note = run_ffuf(TARGET, config, tool=_FakeTool([FFUF_DOCUMENT]))
    assert len(findings) >= 2
    assert "path(s)" in note


def test_run_web_engines_dedups_targets_and_aggregates():
    targets = [
        {"host": "10.0.0.5", "port": 8080, "protocol": "tcp", "service": "http"},
        {"host": "10.0.0.5", "port": 8080, "protocol": "tcp", "service": "http"},  # dup URL
    ]
    nuclei_tool = _FakeTool(NUCLEI_RECORDS)
    findings, notes = run_web_engines(
        targets,
        {"web_engines": {"enabled": True, "nuclei": {"enabled": True}, "ffuf": {"enabled": True}}},
        nuclei_tool=nuclei_tool,
        ffuf_tool=_FakeTool([FFUF_DOCUMENT]),
    )
    # Only one unique URL -> nuclei called once.
    assert len(nuclei_tool.calls) == 1
    assert any(f.cve_id == "CVE-2021-44228" for f in findings)


def test_run_web_engines_disabled():
    findings, notes = run_web_engines([TARGET], {"web_engines": {"enabled": False}})
    assert findings == []
    assert notes == ["web_engines: disabled by config"]
