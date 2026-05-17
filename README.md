# PortWise

Safe, evidence-first VAPT intelligence and reporting for authorized security
audits.

PortWise turns Nmap evidence into structured service intelligence, runs
conservative read-only validation modules, applies confidence and
false-positive logic, optionally enriches components with CVE context, and
generates JSON, HTML, and Excel reports suitable for auditor review.

## What It Is

PortWise is a Python 3.11+ assessment assistant for authorized VAPT and
security configuration review. It is designed to help an assessor answer:

- What assets and services were discovered?
- Which services need owner validation?
- Which safe checks confirm a finding?
- Which findings are only version/banner/CPE indicators?
- What changed during retest?

## What It Is Not

PortWise is not an exploit framework, brute-force tool, RCE runner, password
spraying tool, destructive scanner, fuzzing suite, or data dumping utility. It
does not submit credentials, test default passwords, write to services,
enumerate sensitive database contents, or run denial-of-service checks.

Use PortWise only against systems where you have explicit authorization.

## Why It Exists

VAPT reporting often fails when raw scan output is treated as truth. PortWise
keeps the evidence chain visible: service fingerprint, safe validation result,
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
  -> safe modules and optional imports/CVE enrichment
  -> confidence/risk scoring
  -> JSON, HTML, Excel, retest reports
```

## Installation

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

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
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --dry-run
```

Run active Nmap phases only after scope review:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --internet-facing
```

Analyze existing Nmap XML:

```powershell
portwise analyze --nmap scans\sample.xml --profile offline-analysis --config config.yaml --workspace .
```

Generate all reports:

```powershell
portwise report --run runs\latest.json --format all
```

Retest:

```powershell
portwise retest --previous runs\old.json --current runs\latest.json --format all
```

## Progress And Status

PortWise writes scan progress continuously to:

```text
runs/progress.json
```

During `scan`, the CLI shows phase, grouped service-detection, module, and CVE
status. Nmap does not always expose reliable percentage completion for every
scan type, so PortWise reports the current phase, command, group count, module
target count, elapsed time, and skip/failure reasons.

Check status while a scan is running, or after it completes:

```powershell
portwise status --workspace .
```

Disable live progress output when you want machine-readable command summaries:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --dry-run --no-progress
```

## Troubleshooting And Stability

Check the current or last run status:

```powershell
portwise status --workspace .
```

Raw command output is written to:

```text
logs/commands/
```

UDP scanning can be slow or noisy on some networks. To skip UDP for a run:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --skip-udp
```

If a provider, module, or report format fails, PortWise records the failed or
skipped phase and continues where it can so a partial report can still be
generated.

Useful stability switches:

```powershell
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --no-cve
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --no-modules
portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute --debug
```

Use `--debug` only when troubleshooting; normal mode prints concise
human-readable errors instead of Python tracebacks. If Nmap reports permission
issues for SYN scans, PortWise falls back to TCP connect scan where applicable.

## Profiles

- `quick-triage`: fast discovery and basic routing.
- `internal-vapt`: internal defaults with moderate exposure severity.
- `external-vapt`: perimeter defaults with higher exposure severity.
- `full-vapt`: discovery, TCP/UDP scan phases, grouped service detection, safe modules, reports, and optional CVE enrichment.
- `offline-analysis`: parse existing Nmap XML and run evidence-based modules without active HTTP/TLS probes unless requested.

## Module Coverage

| Module | Status | Safe behavior |
| --- | --- | --- |
| Exposure | Implemented | Context-aware service exposure findings |
| HTTP | Implemented | GET/HEAD/OPTIONS, headers, cookies, safe paths; no auth, POST, or fuzzing |
| TLS | Implemented | Native Python TLS, certificate, protocol, and HSTS checks |
| SMB | Basic | Exposure and safe Nmap script evidence parsing |
| SSH | Basic | Exposure and version disclosure only |
| RDP/WinRM | Basic | Exposure and Nmap evidence only; no login attempts |
| FTP | Basic | Cleartext exposure and anonymous login check only |
| DNS | Conservative | Exposure, recursion, CHAOS version, configured-zone AXFR only |
| SNMP | Conservative | `public`/`private` minimal sysDescr-style check only |
| NTP | Conservative | Basic NTP time response only |
| Database | Conservative | Minimal Redis/Memcached/HTTP metadata probes; no data dumping |
| DevOps/Admin | Conservative | Landing/status fingerprinting; no forms or credentials |
| Kubernetes/Container | Conservative | `/version`, `/healthz`, `/v2/` style metadata only |
| Mail | Conservative | Banner, STARTTLS capability, VRFY/EXPN command support only |
| VPN/Appliance | Fingerprint | Exposure/version indicators only |

## CVE Enrichment

Optional enrichment supports NVD, CISA KEV, and FIRST EPSS with caching. Set
`PORTWISE_NVD_API_KEY` for higher NVD limits. Provider failures, no internet,
and rate limits are recorded as skipped notes and do not fail scans.

CVE confidence is intentionally conservative:

- exact CPE match: `Likely`
- product/version keyword match: `Possible`
- OpenSSH, Apache, nginx, OpenSSL, PHP, Linux distro packages, and Samba:
  backport warning and manual validation
- no CVE is marked `Confirmed` without safe validation

## Confidence And False Positives

Evidence strength:

- `5`: safe active validation
- `4`: strong protocol evidence
- `3`: exact CPE/version evidence
- `2`: banner/header only
- `1`: heuristic

PortWise downgrades banner-only findings, guessed services, UDP
`open|filtered`, contextual HSTS findings, and backport-sensitive version
matches.

## Reports

Generated under `reports/`:

- `PortWise_Report.json`
- `PortWise_Report.html`
- `PortWise_Report.xlsx`
- `PortWise_Retest.json`
- `PortWise_Retest.xlsx`

The Excel workbook includes 17 sheets: executive summary, inventory, ports,
service view, findings queues, TLS/HTTP/exposure/CVE views, module targets,
commands, skipped checks, and retest baseline.

## Imports

`analyze` supports conservative imports:

- `--testssl-json-dir`: imports recognizable testssl JSON issues as manual-validation findings.
- `--nessus-csv`: imports common Nessus CSV fields as non-confirmed findings.

Imported issues are not treated as PortWise-confirmed unless later validated by safe modules.

## Sample Artifacts

Documentation-safe examples use `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, and `example.com`.

- [sample_nmap.xml](examples/sample_nmap.xml)
- [sample_run.json](examples/sample_run.json)
- [sample_report.json](examples/sample_report.json)
- [sample_targets.txt](examples/sample_targets.txt)
- [PortWise_Report.html](examples/sample_reports/PortWise_Report.html)
- [PortWise_Report.xlsx](examples/sample_reports/PortWise_Report.xlsx)

Screenshots can be added under `docs/screenshots/` before a formal release.

## Limitations

- Several protocol modules are intentionally conservative metadata checks.
- DNS AXFR requires configured zones; PortWise does not brute force subdomains.
- SNMP checks only `public` and `private` by default and query minimal metadata.
- Database modules do not authenticate or enumerate user data.
- CVE enrichment depends on external provider availability and rate limits.
- PortWise supports auditor judgment; it does not replace manual validation.

## Roadmap

- Richer authenticated proof modes with explicit opt-in.
- More importers and normalized evidence mapping.
- Type checking, linting, and release packaging.
- Screenshot-backed reporting examples.
- More protocol-specific parsers for existing Nmap NSE output.

## Contributing

Keep contributions safe-by-default. Do not add exploit payloads, brute force, destructive checks, data dumping, or state-changing validation.

## License

MIT License.
