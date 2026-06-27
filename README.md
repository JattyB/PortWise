# PortWise

Penetration-testing orchestration, correlation, and evidence-backed reporting
for authorized assessments.

PortWise is the brain that ties best-in-class scanners and native protocol
checks into one prioritized report: it discovers services, runs native
protocol-level validation, orchestrates optional engines (nuclei, ffuf,
Playwright screenshots, masscan, testssl), adds optional impacket AD/SMB depth,
correlates and de-duplicates findings, maps
version-matched CVEs, captures evidence/POCs, and generates JSON, HTML, and
Excel reports suitable for client delivery.

## What It Is

PortWise is a Python 3.11+ penetration-testing orchestration platform for
authorized engagements. The operator controls:

- **Depth** — `recon` (fast enumeration) or `full` (complete active assessment).
- **Scope** — intrusive or credentialed actions are explicit opt-in per
  engagement.

It answers, with a visible evidence chain:

- What assets and services are exposed?
- Which findings are confirmed by an active check vs. only a version/banner
  indicator?
- What is the confidence and false-positive risk of each finding?
- Which version-matched CVEs apply, and is an exploit available?
- What changed during retest?

## Architecture

- **Native** protocol-level checks (SSH KEX, SMB negotiate, TLS handshake, HTTP
  fingerprint, banner grab) — dependency-free.
- **Optional** AD/SMB depth through `portwise[ad]`: SMB null-session/share
  metadata, LDAP anonymous enumeration where allowed, and opt-in credentialed
  SMB/Kerberos checks through impacket without requiring nxc/netexec. Without
  the extra, AD/SMB modules degrade with an availability note.
- **Orchestrated** heavy/fast-moving engines (nuclei, ffuf, testssl, masscan,
  nmap) as **optional** integrations: detect the binary on PATH, run it, parse
  its JSON output into PortWise `Finding` objects; if absent, skip with a note
  and fall back to the native async TCP connect discovery path for basic runs.
  Playwright
  screenshots are an optional Python extra: install `portwise[screenshots]` to
  capture browser-rendered web evidence with managed Chromium.

PortWise is the orchestration + correlation engine; it does not reimplement
those engines.

Use PortWise only against systems where you have explicit authorization.

## Why It Exists

VAPT reporting fails when raw scan output is treated as truth. PortWise keeps
the evidence chain visible: service fingerprint, active validation result,
confidence level, false-positive risk, recommendation, and manual-validation
status.

## Workflow

```text
targets.txt
  -> Nmap discovery
  -> live_hosts.txt
  -> TCP/UDP port discovery
  -> grouped service detection by identical host/port sets
  -> service parser and module router
  -> native modules + optional orchestrated engines + CVE enrichment
  -> confidence/risk scoring + de-duplication
  -> JSON, HTML, Excel, retest reports
```

## Installation

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

AD/SMB/LDAP depth uses impacket and is installed only when requested:

```powershell
python -m pip install -e ".[ad]"
```

On Windows, Microsoft Defender and other AV products may quarantine impacket
components because the package is dual-use. Install the `ad` extra in WSL or in
an operator-approved Defender exclusion path when that capability is in scope.

Linux:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

With `uv`:

```powershell
uv venv
.venv\Scripts\Activate.ps1
uv pip install -e ".[dev]"
```

## Quick Start

```powershell
portwise init client-audit
cd client-audit
portwise doctor
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --dry-run
```

Run active phases after scope review:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute
```

Analyze existing Nmap XML:

```powershell
portwise analyze --nmap scans\sample.xml --profile offline-analysis --config config.yaml --workspace .
```

Generate all reports:

```powershell
portwise report --run runs\latest.json --format all
```

Enforce engagement scope and generate a branded PDF:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --scope-file scope.txt --exclude-file exclude.txt
portwise report --run runs\latest.json --format pdf --client-name "Example Client" --logo client-logo.png --manual-findings manual.yaml --suppressions suppressions.yaml
```

Configured scope is fail-closed. Rules accept exact hosts, parent domains
(including their subdomains), and CIDRs. Discovered crawl/archive URLs outside
the allowlist or matching an exclusion are discarded. `--scope-override` is the
explicit operator bypass.

Authenticated reuse checks remain off unless `--authenticated` is supplied.
Only `--cred`/`--cred-file` values are attempted; no guessing is performed.
`credential_reuse.rate_per_second` controls the attempt rate. Successful reuse
is correlated by a non-reversible identifier and secrets remain redacted.

Manual findings files contain a top-level `findings:` list. Suppression files
contain `suppressions:` with stable finding fingerprints. Suppressed findings
remain marked `suppressed` on later reports and on scans configured with
`false_positive_suppression.file`.

Retest:

```powershell
portwise retest --previous runs\old.json --current runs\latest.json --format all
```

## Optional Engines

PortWise orchestrates external engines when they are on PATH and uses their JSON
output. Check what is available:

```powershell
portwise doctor
```

| Engine | Used for | If absent |
| --- | --- | --- |
| nmap | discovery, port + service detection | core scanning unavailable |
| nuclei | templated web/vuln checks (`-jsonl`) | skipped; handoff command emitted |
| ffuf | content discovery (`-of json`) | skipped; handoff command emitted |
| Playwright | browser-rendered web service screenshots | skipped; install `portwise[screenshots]` |
| testssl | deep TLS analysis | native TLS checks still run |
| masscan | fast port sweeps | nmap used instead |
| ssh-audit | SSH algorithm cross-check | native KEXINIT probe still runs |
| searchsploit | exploit-availability lookup | flag omitted |
| impacket (`portwise[ad]`) | AD/SMB/LDAP depth | native SMB negotiate remains; AD checks emit availability note |

## Depth And Scope

Assessment depth is `recon` or `full`, selected by profile or
`--validation-level`. Intrusive and credentialed actions run only at `full`
depth or behind an explicit flag — that is engagement scope control.

## Progress And Status

PortWise writes scan progress continuously to `runs/progress.json`. Check status
while a scan runs or after it completes:

```powershell
portwise status --workspace .
```

Disable live progress output for machine-readable command summaries:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --dry-run --no-progress
```

## Troubleshooting And Stability

Raw command output is written to `logs/commands/`. UDP scanning can be slow on
some networks; skip it with `--skip-udp`. If a provider, module, or report
format fails, PortWise records the failed/skipped phase and continues so a
partial report can still be generated.

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --no-cve
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --no-modules
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --debug
```

Use `--debug` only when troubleshooting; normal mode prints concise errors
instead of tracebacks. If Nmap reports permission issues for SYN scans, PortWise
falls back to TCP connect scan where applicable.

## Profiles

- `quick-triage`: fast discovery and basic routing (recon depth).
- `internal-vapt`: internal defaults, full depth.
- `external-vapt`: perimeter defaults, full depth.
- `full-vapt`: discovery, TCP/UDP scan phases, grouped service detection, all
  module checks, active web crawl, CVE mapping. One command, internal or
  external.
- `offline-analysis`: parse existing Nmap XML and run evidence-based modules
  without active probes unless requested.

## CVE Enrichment

Optional enrichment supports NVD, CISA KEV, and FIRST EPSS with caching. Set
`PORTWISE_NVD_API_KEY` for higher NVD limits. Provider failures, no internet,
and rate limits are recorded as skipped notes and do not fail scans.

CVE confidence is conservative:

- exact CPE match: `Likely`
- product/version keyword match: `Possible`
- backport-sensitive packages (OpenSSH, Apache, nginx, OpenSSL, PHP, distro
  packages, Samba): backport warning and manual validation
- no CVE is marked `Confirmed` without active validation

Version-matched CVEs are annotated with an exploit-availability flag when an
ExploitDB entry or nuclei template is known.

## Confidence And False Positives

Evidence strength:

- `5`: active validation
- `4`: strong protocol evidence
- `3`: exact CPE/version evidence
- `2`: banner/header only
- `1`: heuristic

PortWise downgrades banner-only findings, guessed services, UDP
`open|filtered`, contextual HSTS findings, and backport-sensitive version
matches, and de-duplicates overlapping findings.

## Reports

Generated under `reports/`:

- `PortWise_Report.json`
- `PortWise_Report.html`
- `PortWise_Report.xlsx`
- `PortWise_Report.csv`
- `PortWise_Retest.json` / `PortWise_Retest.xlsx`

The HTML report includes an executive-summary narrative, per-host grouped view,
severity charts, evidence/POC blocks, and retest diffs.

## Handoff

`portwise handoff` turns findings into suggested command templates for the
operator's own tooling (NetExec, ssh-audit, nuclei/ffuf/nikto, testssl,
snmpwalk, dig, searchsploit). It also backs the optional-engine fallback: when
an engine is not installed, its equivalent command is emitted here.

## Imports

`analyze` supports imports:

- `--testssl-json-dir`: imports testssl JSON issues as manual-validation findings.
- `--nessus-csv`: imports common Nessus CSV fields as non-confirmed findings.

Imported issues are not treated as PortWise-confirmed unless later validated by a
module.

## Sample Artifacts

Documentation examples use `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
and `example.com`.

- [sample_nmap.xml](examples/sample_nmap.xml)
- [sample_run.json](examples/sample_run.json)
- [sample_report.json](examples/sample_report.json)
- [sample_targets.txt](examples/sample_targets.txt)

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License.
