# CLAUDE.md — PortWise

Operating guide for any AI agent (Claude Code) working in this repository.
Read this fully before making changes. These rules are binding.

## What PortWise is

PortWise is a **penetration-testing orchestration platform** (Python, ~12k LOC).
Its job is to be the **orchestration + correlation + CVE mapping + de-duplication +
evidence/POC + reporting engine** that ties best-in-class scanners and native
protocol checks into one prioritized, evidence-backed report.

It is a real offensive-security tool for authorized assessments. Treat it as a
professional product, not a demo.

## Positioning & language (strict)

- **Never** describe PortWise or its behavior as "safe", "safe-by-default", or
  "controlled" — in code, config, comments, docstrings, README, CHANGELOG, CLI
  help, or report text. That framing is banned.
- The correct concept is **operator-controlled depth and scope**:
  - **Depth** — the operator chooses `recon` (fast enumeration) or `full`
    (complete active assessment).
  - **Scope** — intrusive or credentialed actions are explicit opt-in per
    engagement. That is standard scope control, not a limitation, and is never
    described as "safety".
- Write user-facing text the way a senior pentester would: direct, technical,
  confident. No hedging, no apology.

## Architecture decision (do not violate)

- **Native** for protocol-level checks (SSH KEX, SMB negotiate, TLS handshake,
  HTTP fingerprint, banner grab). These stay dependency-free.
- **Orchestrate** heavy / fast-moving engines (nuclei, ffuf, gowitness, testssl,
  masscan) as **optional** integrations — never hard requirements:
  - Detect the binary on PATH. If present, run it and parse its **JSON** output
    into PortWise `Finding` objects. If absent, skip with a clear note and emit
    the equivalent command through the existing `handoff` system.
  - Always prefer JSON output modes (`nuclei -jsonl`, `ffuf -of json`,
    `gowitness`, `masscan -oJ`, `nmap -oX`). Do not scrape fragile text.
- **Do not reimplement** nuclei/ffuf/nmap engines in Python. PortWise is the
  brain; those are the hands.
- New external integrations go through the shared `ExternalTool` adapter
  (detect → run-with-timeout → parse JSON → graceful fallback).

## Use context7

The `context7` MCP server is available. Use it to fetch **current** documentation
for external-tool JSON schemas and any libraries you integrate, instead of relying
on training memory — these formats and APIs change.

## Working rules

- Keep the test suite green at all times. Run `pytest -q` before every commit.
- Add tests for every new feature or fix.
- One logical change per commit; commit per roadmap phase with a clear message.
- Update `CHANGELOG.md` and `ROADMAP.md` as you go.
- Intrusive / credentialed actions and external active engines run only at depth
  `full` or behind an explicit flag — framed as scope control.
- Preserve de-duplication, confidence scoring, and CVE version-matching behavior;
  do not regress false-positive controls.
- Do not commit engagement output: `runs/`, `scans/`, `reports/`, `evidence/`,
  `cache/`, or `config.yaml` (see `.gitignore`).

## Repository map

```
portwise/
  cli.py              # CLI entrypoint and command handlers
  core/               # runner, routing, models, module_runner, config, progress
  modules/            # 17 service modules (http/, tls/, smb/, registry.py, ...)
  intelligence/       # cve_enrichment, version_match, aggregation, handoff, poc, ...
  scanners/           # nmap_runner, nmap_parser, nse, ssh_algos, smb_native
  reporting/          # html_report, pentest_report, _html_common, remediation
  utils/              # http_client, sanitize, logging
tests/                # pytest suite (keep green)
config.example.yaml   # profiles + scanner config
```

Pipeline: discover → port scan → service fingerprint → route to modules →
module checks (native + orchestrated) → CVE enrichment → dedup/confidence →
findings → report / POC / handoff.

## Commands

```bash
pip install -e ".[dev]"          # dev install
pytest -q                        # run tests

portwise scan --targets t.txt --profile full-vapt --config config.yaml --execute
portwise analyze --nmap scan.xml --profile full-vapt --config config.yaml
portwise report  --run runs/latest.json --format html
portwise summary --run runs/latest.json
portwise ports   --run runs/latest.json --port 22 --hosts
portwise handoff --run runs/latest.json
portwise poc     --run runs/latest.json --capture
```

CLI commands: init, scan, analyze, report, retest, status, ports, summary,
handoff, poc, modules, version (plus `doctor`, added in roadmap Phase 0).

Profiles: `quick-triage` (recon depth), `internal-vapt`, `external-vapt`,
`full-vapt` (full depth — one command, internal or external), `offline-analysis`.

## When unsure

Make the change and report it; only stop to ask when a decision is genuinely
ambiguous or would alter the platform's identity or the rules above.
