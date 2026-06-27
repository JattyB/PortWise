from pathlib import Path

from portwise.reporting.customization import apply_report_inputs, finding_fingerprint
from portwise.reporting.pentest_report import write_pentest_report


def test_branding_manual_injection_and_persistent_suppression(tmp_path: Path):
    finding = {"title": "Fixture", "asset": "a.test", "port": 443, "protocol": "tcp", "type": "tls", "severity": "high"}
    manual = tmp_path / "manual.yaml"
    manual.write_text("findings:\n  - title: Operator finding\n    asset: a.test\n    severity: medium\n", encoding="utf-8")
    suppressions = tmp_path / "suppress.yaml"
    suppressions.write_text(f"suppressions:\n  - {finding_fingerprint(finding)}\n", encoding="utf-8")
    report = apply_report_inputs(
        {"project": "P", "findings": [finding]},
        manual_file=manual,
        suppression_file=suppressions,
        client_name="ACME",
        logo="data:image/png;base64,AA==",
    )
    assert report["findings"][0]["status"] == "suppressed"
    assert report["findings"][1]["title"] == "Operator finding"
    html = write_pentest_report(report, tmp_path / "report.html").read_text(encoding="utf-8")
    assert "ACME" in html and "data:image/png;base64,AA==" in html


def test_pdf_renderer_contract_with_fake_playwright(monkeypatch, tmp_path: Path):
    from portwise.reporting import pdf_report

    class Page:
        async def goto(self, *_a, **_k): pass
        async def emulate_media(self, **_k): pass
        async def pdf(self, path, **_k): Path(path).write_bytes(b"%PDF-1.7\nfixture")
    class Browser:
        async def new_page(self): return Page()
        async def close(self): pass
    class Chromium:
        async def launch(self, **_k): return Browser()
    class Manager:
        chromium = Chromium()
    class Context:
        async def __aenter__(self): return Manager()
        async def __aexit__(self, *_a): pass
    monkeypatch.setattr("playwright.async_api.async_playwright", lambda: Context())
    source = tmp_path / "report.html"
    source.write_text("<html>real data</html>", encoding="utf-8")
    output = pdf_report.write_pdf_report(source, tmp_path / "report.pdf")
    assert output.read_bytes().startswith(b"%PDF")
