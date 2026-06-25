# CLAUDE.md — PortWise

Project orientation for any AI agent working in this repository. Read it fully
before changing anything. The binding engineering rules live in `AGENTS.md` —
follow them.

## What PortWise is

A self-sufficient, professional penetration-testing platform. It is the engine
that ties discovery, native scanning, web crawling and fuzzing, templated vuln
checks, CVE correlation, de-duplication, evidence/POC capture, and reporting into
one prioritized result. Treat it as a product, not a script.

## Voice

Write like a senior operator: direct and technical, no hedging or disclaimer
phrasing. Depth and scope are operator-driven — depth is `recon` (fast
enumeration) or `full` (complete assessment); intrusive and credentialed actions
are explicit opt-in. State capability plainly.

## Architecture

Self-sufficient on `pip install`. Deliver capability via, in order of preference:
native Python logic > bundled pip libraries > shipped/synced data files. External
binaries are optional accelerators only, behind the `ExternalTool` adapter; nmap
is the one assumed scanner, with a native connect-scan fallback for its absence.

- **Transport:** every HTTP request rides one shared, human-like transport built
  on `curl_cffi` (Chrome JA3/TLS + HTTP2 impersonation, realistic headers, cookie
  jar, jitter, UA rotation, optional Burp/SOCKS proxy), with a Playwright path for
  JS challenges. Never add a second HTTP path.
- **Speed:** async-first throughout (`asyncio` + `curl_cffi`/`httpx`, bounded
  concurrency, pooling); CPU-heavy matching uses a process pool.

Full engineering contract, build loop, and acceptance gates: `AGENTS.md`.

## Native engines (owned in-tree)

Capabilities are reimplemented natively rather than shelled out, so the platform
needs no external setup:

- Transport / anti-bot — curl_cffi JA3 transport + Playwright fallback.
- Port/host discovery — nmap (service detection) + native async connect-scan.
- Subdomain/asset discovery — passive sources (crt.sh, archives) + async DNS.
- URL/endpoint discovery — native crawler + archive pulls (Wayback/CommonCrawl)
  + parameter discovery.
- Content/directory fuzzing — async wordlist engine with soft-404 / size / word /
  line filtering and recursion.
- HTTP probe + tech fingerprint — async prober + Wappalyzer fingerprint data.
- Vuln scanning — native template engine consuming synced nuclei-format templates
  (plus custom templates for gaps).
- JS/secrets — endpoint + secret extraction with shipped rule sets.
- TLS — native cert + protocol + cipher assessment.
- AD/SMB/auth — optional `portwise[ad]` impacket extra (SMB/LDAP
  enumeration; opt-in Kerberoast/AS-REP).
- Exploit intel — native ExploitDB lookup for the exploit-available signal.
- Screenshots — Playwright (`portwise[screenshots]` extra).

Status and sequencing live in `ROADMAP.md`.

## Repo map

```
portwise/
  cli.py                 # CLI entrypoint and command handlers
  core/                  # runner, routing, models, module_runner, config,
                         # progress, doctor, external_tool
  modules/               # service modules (http/, tls/, smb/, registry.py, ...)
  intelligence/          # cve_enrichment, version_match, aggregation, handoff,
                         # poc, credentials, auth_checks, exploit_intel,
                         # screenshots, web_engines
  scanners/              # nmap_runner, nmap_parser, nse, ssh_algos, smb_native
  reporting/             # html_report, pentest_report, _html_common,
                         # remediation, csv_report, narrative
  utils/                 # http_client (shared transport), sanitize, net, logging
tests/                   # pytest suite (keep green)
config.example.yaml      # profiles + scanner config
ROADMAP.md               # phased native-rebuild plan + status
```

Pipeline: discover → port scan → service fingerprint → route to modules →
module checks (native + optional accelerators) → CVE + exploit intel →
dedup/confidence → findings → report / POC / handoff.

## Commands

```bash
pip install -e ".[dev]"          # dev install
pytest -q                        # run the suite

portwise doctor                  # show which optional accelerators are present
portwise scan    --targets t.txt --profile full-vapt --config config.yaml --execute
portwise analyze --nmap scan.xml --profile full-vapt --config config.yaml --active-modules
portwise report  --run runs/latest.json --format html
portwise summary --run runs/latest.json
portwise ports   --run runs/latest.json --port 22 --hosts
portwise handoff --run runs/latest.json
portwise poc     --run runs/latest.json --capture
```

CLI commands: init, scan, analyze, report, retest, status, ports, summary,
handoff, poc, doctor, modules, version.

Profiles: `quick-triage` (recon depth), `internal-vapt`, `external-vapt`,
`full-vapt` (full depth — one command, internal or external), `offline-analysis`.
Depth resolves CLI flag > profile > config; `full-vapt` runs everything.

## When unsure

Make the change and report it. Stop only when a decision would change the
platform's identity or break a rule in `AGENTS.md`.
