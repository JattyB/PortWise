from pathlib import Path
from portwise.intelligence.poc import build_poc_items, write_poc_artifacts, _derive_poc


def _run():
    return {"findings": [
        {"title": "Weak TLS Ciphers In Use", "severity": "medium", "asset": "1.1.1.1", "port": 443,
         "description": "weak ciphers", "evidence": [{"data": {"poc_command": "nmap --script ssl-enum-ciphers -p 443 1.1.1.1"}}]},
        {"title": "Weak SSH Cipher", "severity": "medium", "asset": "1.1.1.1", "port": 22, "description": "x", "evidence": []},
        {"title": "HSTS Missing", "severity": "low", "asset": "1.1.1.1", "port": 443, "description": "x",
         "evidence": [{"data": {"poc_command": "curl -sI https://1.1.1.1/"}}]},
        {"title": "Some Info", "severity": "informational", "asset": "1.1.1.1", "port": 80, "description": "x", "evidence": []},
    ]}


def test_build_poc_items_collects_and_filters():
    items = build_poc_items(_run(), min_severity="low")
    titles = {i.title for i in items}
    assert "Weak TLS Ciphers In Use" in titles
    assert "HSTS Missing" in titles
    # informational filtered out at min-severity=low
    assert "Some Info" not in titles


def test_derive_poc_for_ssh():
    f = {"title": "Weak SSH Cipher", "asset": "h", "port": 22}
    assert "ssh-audit" in _derive_poc(f)


def test_write_artifacts(tmp_path: Path):
    items = build_poc_items(_run())
    index = write_poc_artifacts(items, tmp_path / "poc", capture=False)
    assert index.exists()
    files = list((tmp_path / "poc").glob("*.txt"))
    assert len(files) >= 3
    content = (tmp_path / "poc" / "INDEX.txt").read_text()
    assert "ssl-enum-ciphers" in content
    # never executed without --capture
    sample = next(f for f in files if f.name != "INDEX.txt")
    assert "PASTE OUTPUT" in sample.read_text()


def test_every_critical_and_high_finding_gets_poc_entry_and_evidence(tmp_path: Path):
    run = {"findings": [
        {
            "title": "vsftpd 2.3.4 Backdoor", "severity": "critical",
            "asset": "10.0.0.5", "port": 21,
            "evidence": [{"source": "service-exploit-correlation", "description": "exact version matched"}],
        },
        {
            "title": "Unclassified High Finding", "severity": "high",
            "asset": "10.0.0.5", "port": 9999,
            "evidence": [{"source": "module", "description": "probe matched"}],
        },
    ]}

    items = build_poc_items(run, min_severity="high")
    assert len(items) == 2
    assert all(item.command for item in items)
    assert all(item.evidence for item in items)
    write_poc_artifacts(items, tmp_path / "poc")
    text = "\n".join(path.read_text() for path in (tmp_path / "poc").glob("*.txt"))
    assert "Matched detection evidence:" in text
