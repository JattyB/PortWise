from __future__ import annotations

import sys
from pathlib import Path

import pytest

from portwise.cli import main
from portwise.core.config import ConfigError, load_config
from portwise.core.doctor import collect_engine_status, render_doctor
from portwise.core.external_tool import ExternalTool, parse_json_output
from portwise.utils.net import bracket_host, endpoint_url, is_ipv6


# --------------------------------------------------------------------------
# ExternalTool adapter
# --------------------------------------------------------------------------

def test_external_tool_detects_present_binary():
    # The Python interpreter is guaranteed to be on PATH under its own name in CI,
    # but to be safe we use the current executable's stem via a known tool.
    tool = ExternalTool("python", binary=Path(sys.executable).name)
    assert tool.available is True
    assert tool.resolve() is not None


def test_external_tool_missing_binary_skips_with_handoff():
    tool = ExternalTool("definitely-not-a-real-engine-xyz")
    result = tool.run(["--version"], handoff_command="run it yourself")
    assert result.available is False
    assert result.ran is False
    assert result.skipped_reason and "not found" in result.skipped_reason
    assert result.handoff_command == "run it yourself"
    assert "handoff: run it yourself" in result.note()


def test_external_tool_run_captures_output():
    tool = ExternalTool("python", binary=Path(sys.executable).name)
    result = tool.run(["-c", "print('hello-portwise')"])
    assert result.ran is True
    assert result.returncode == 0
    assert "hello-portwise" in result.stdout


def test_external_tool_run_json_single_document():
    tool = ExternalTool("python", binary=Path(sys.executable).name)
    result = tool.run_json(["-c", "import json; print(json.dumps({'a': 1}))"])
    assert result.ok is True
    assert result.records == [{"a": 1}]


def test_external_tool_run_json_jsonl():
    tool = ExternalTool("python", binary=Path(sys.executable).name)
    script = "print('{\"id\": 1}'); print('{\"id\": 2}')"
    result = tool.run_json(["-c", script], jsonl=True)
    assert result.ok is True
    assert [r["id"] for r in result.records] == [1, 2]


def test_external_tool_run_json_bad_output_sets_error():
    tool = ExternalTool("python", binary=Path(sys.executable).name)
    result = tool.run_json(["-c", "print('not json at all')"])
    assert result.ran is True
    assert result.ok is False
    assert result.error and "parse" in result.error


def test_parse_json_output_variants():
    assert parse_json_output("") == []
    assert parse_json_output("   \n  ") == []
    assert parse_json_output('[1, 2, 3]') == [1, 2, 3]
    assert parse_json_output('{"x": 1}') == [{"x": 1}]
    assert parse_json_output('{"a":1}\n{"b":2}', jsonl=True) == [{"a": 1}, {"b": 2}]


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def test_doctor_collects_known_engines():
    statuses = collect_engine_status()
    names = {s.name for s in statuses}
    assert {"nmap", "nuclei", "ffuf", "gowitness", "testssl", "masscan", "ssh-audit", "searchsploit"} <= names
    rendered = render_doctor(statuses)
    assert "PortWise doctor" in rendered
    assert "nuclei" in rendered


def test_doctor_cli_runs(capsys):
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "optional engine availability" in out


def test_doctor_cli_json(capsys):
    assert main(["doctor", "--json"]) == 0
    out = capsys.readouterr().out
    assert '"binary"' in out and '"nuclei"' in out


# --------------------------------------------------------------------------
# Config schema validation
# --------------------------------------------------------------------------

_VALID = """
project:
  name: Test
scanner:
  validation_level: recon
profiles:
  full-vapt:
    validation_level: full
    nmap_steps: [discovery, tcp_top_1000]
    modules:
      http: true
    reports: [json, html]
"""


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_valid_config_loads(tmp_path):
    config = load_config(_write(tmp_path, _VALID))
    assert config.scanner["validation_level"] == "recon"
    assert config.get_profile("full-vapt").nmap_steps == ["discovery", "tcp_top_1000"]


def test_invalid_scanner_depth_rejected(tmp_path):
    text = _VALID.replace("validation_level: recon", "validation_level: safe")
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, text))
    assert "validation_level" in str(exc.value)
    assert "recon" in str(exc.value)


def test_invalid_profile_depth_rejected(tmp_path):
    text = _VALID.replace("validation_level: full", "validation_level: controlled")
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, text))
    assert "controlled" in str(exc.value)


def test_unknown_nmap_step_rejected(tmp_path):
    text = _VALID.replace("[discovery, tcp_top_1000]", "[discovery, warp_drive]")
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, text))
    assert "warp_drive" in str(exc.value)


def test_unknown_report_format_rejected(tmp_path):
    text = _VALID.replace("[json, html]", "[json, hologram]")
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, text))
    assert "hologram" in str(exc.value)


def test_no_profiles_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, "project:\n  name: x\n"))


# --------------------------------------------------------------------------
# IPv6 handling
# --------------------------------------------------------------------------

def test_is_ipv6():
    assert is_ipv6("::1") is True
    assert is_ipv6("fe80::1") is True
    assert is_ipv6("[2001:db8::1]") is True
    assert is_ipv6("192.0.2.1") is False
    assert is_ipv6("example.com") is False


def test_bracket_host():
    assert bracket_host("::1") == "[::1]"
    assert bracket_host("[::1]") == "[::1]"
    assert bracket_host("192.0.2.1") == "192.0.2.1"
    assert bracket_host("example.com") == "example.com"


def test_endpoint_url_ipv6():
    assert endpoint_url("2001:db8::1", 8080, tls=False) == "http://[2001:db8::1]:8080/"
    assert endpoint_url("192.0.2.1", 443, tls=True) == "https://192.0.2.1/"
