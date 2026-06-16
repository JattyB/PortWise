# Changelog

## v0.7.0 — orchestration platform foundation

PortWise is a penetration-testing orchestration platform: the orchestration +
correlation + CVE + de-duplication + evidence + reporting engine that ties
best-in-class scanners and native protocol checks into one prioritized,
evidence-backed report. The operator controls **depth** (`recon` = fast
enumeration, `full` = complete active assessment) and **scope** (intrusive or
credentialed actions are explicit opt-in per engagement).

### Phase 3 — screenshot evidence
- Orchestrate **gowitness** (optional) to screenshot each discovered web service
  at full depth. Version-robust: tries multiple gowitness argument forms and
  accepts whichever produces a PNG.
- Image paths are attached to matching web findings' evidence and surfaced via a
  dedicated "Web Service Screenshot Captured" finding; the POC bundle references
  the screenshot per finding.
- New `screenshots:` config section; new "Screenshot capture" scan phase. Absent
  binary skips cleanly with a handoff command.

### Phase 2 — web depth (optional engines)
- Orchestrate **nuclei** (optional): run against discovered web targets at full
  depth, parse `-jsonl` into Findings with severity + CVE/CVSS mapping, tagged
  `external-engine`; folded through the existing dedup/confidence pipeline.
- Orchestrate **ffuf** (optional) with configurable external wordlist
  (`web_engines.ffuf.wordlist`, e.g. SecLists); results fold into content
  discovery and skip paths already reported by the native crawler.
- Both engines run only at `full` depth, only when the binary is on PATH; absent
  binaries skip cleanly and record the equivalent handoff command.
- New `web_engines:` config section; new "Web engine orchestration" scan phase.

### Phase 1 — parallelism
- Module checks now run through a bounded thread pool: work is parallelized
  **across hosts** while all work for a single host stays **serialized**, so
  per-host throttle/politeness and circuit-breaker behavior are preserved.
- Output ordering is deterministic — results are reassembled in module → target
  order regardless of completion order.
- Concurrency is configurable via `scanner.module_concurrency` (default 10) or
  the `--concurrency` flag.

### Phase 0 — foundation + rename
- Renamed the `safe` assessment depth to **`recon`** across config, CLI choices
  (`--validation-level recon|full`), profiles, docstrings, comments, and tests.
- Removed legacy positioning wording (README, CHANGELOG, docstrings, CLI help)
  in favor of operator-controlled depth and scope.
- Added `portwise doctor`: detects installed optional engines (nuclei, ffuf,
  gowitness, testssl, masscan, nmap, ssh-audit, searchsploit) and reports which
  checks are therefore available.
- Added the `ExternalTool` adapter (detect-on-PATH → run-with-timeout → parse
  JSON → graceful skip + handoff fallback) that all engine integrations use.
- Added config schema validation with actionable error messages.
- Verified IPv6 target handling; removed the leftover `_fixpack/` folder.


## v0.6.1 — full PT means full PT

- Collapsed the depth gate to two levels: **full** (run every active check —
  crawl, content discovery, injection indicators, all module probes, CVE) and
  **recon** (fast enumeration, used by quick-triage). (Renamed from the earlier
  `safe` label in v0.7.0.)
- `full-vapt`, `internal-vapt`, and `external-vapt` all run at **full** with the
  full TCP port scan and CVE mapping. One command, no flags, same for internal or
  external:
      portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute
- `--validation-level` choices simplified to two depths (optional; the profile
  decides by default).


## v0.6.0 — one-command full PT, redesigned report

### Same command, internal or external — no restrictions
- `full-vapt` now runs at full assessment depth, so a single command
  performs the full assessment (all modules, active web crawl/content-discovery/
  injection indicators, CVE mapping) with no extra flags:
      portwise scan --targets targets.txt --profile full-vapt --config config.yaml --execute
  `--internet-facing` is now purely a severity-context hint (optional); it imposes
  no restrictions. The same command works for internal and external engagements.
- `--validation-level` is now optional and resolved as CLI > profile > config.
- `full-vapt` emits the HTML report by default.

### Report UI redesign
- Replaced the neon "terminal" theme with a clean, professional light report:
  system fonts, indigo accent, soft cards/shadows, refined severity badges,
  print-friendly stylesheet. Charts, tables, evidence/POC blocks restyled to
  match. Affects both the standard HTML report and the pentest report.


## v0.5.0 — more services, port-based routing, POC capture

### More ports / services checked
- **Port-based routing**: alt web ports (8080/8443/8880, Cloudflare 2052/2053/
  2082/2083/2086/2087/2095/2096, 5000, etc.) now reach the HTTP/TLS engines even
  when nmap labels them with non-web default names. Well-known DB ports
  (6379/9200/27017/11211/...) route to the database module; Docker 2375/2376 to
  the container module.
- HTTP engine now tries the opposite scheme on failure (ambiguous alt ports) and
  recognises many more HTTPS ports.
- Database safe-probe infers the engine from the port when the fingerprint is
  unnamed.
- **Unauthenticated Docker API** now reported as CRITICAL (confirmed via read-only
  /version, /info); exposed Docker registry flagged.

### POC / evidence capture
- New `portwise poc [--capture] [--min-severity] [--out]`: writes a per-finding
  evidence file with a reproduction command (nmap/openssl/curl/ssh-audit/redis-cli)
  and a slot to paste output / reference a screenshot, plus an INDEX. With
  `--capture` it runs the *read-only* commands and embeds their real output as
  attachable evidence. POC commands are sourced from finding evidence
  (TLS/cipher/HSTS already carry nmap POCs) or derived per finding type.


## v0.4.0 — scan accuracy, TLS simplification, web crawl, POC

### Scan correctness (was missing hosts/ports)
- Port scans now use **-Pn** and seed every supplied target as live
  (`scanner.assume_hosts_up`, default on), so ICMP-filtered-but-alive hosts are
  scanned instead of dropped at discovery.
- Removed the aggressive `--host-timeout 20m` from the full `-p-` scan that was
  silently skipping heavily-filtered hosts (the cause of the full-scan
  discrepancy vs a manual `nmap -Pn -p-`). Raised `--min-rate`, `-T4`.

### False positives
- HTTP content discovery now requires a **content signature** (or demotes to
  manual-validation) before confirming `/.git`, `/.env`, `/config.php`, etc., so
  SPA/catch-all servers no longer produce confident-but-wrong "file exposed" hits.

### TLS (simplified per request)
- Single **"Weak TLS Ciphers In Use"** finding (no CBC/PFS sub-findings).
- **Deprecated protocol** vuln for SSLv3 / TLS 1.0 / TLS 1.1.
- Every TLS/cipher/HSTS finding now carries an **nmap POC command** in its
  description/evidence (e.g. `nmap --script ssl-enum-ciphers -p 443 host`).

### Findings
- Version/banner disclosure is now a **LOW vulnerability** (was informational).

### Web
- New same-origin **web crawler**: surfaces interesting endpoints/API paths,
  JS files, and high-signal secrets (keys/tokens/JWT/private keys, redacted).
  Skips off-origin redirects; GET-only.
- HTTP client now sends a **full browser header set** (current Chrome UA, Sec-CH-UA,
  Accept-*, Sec-Fetch-*) to reduce bot blocking.


## v0.3.0 — PT-buddy update

### False-positive reduction
- **CVE keyword-only matches suppressed by default.** A service with a version
  but no CPE used to pull dozens of unrelated CVEs (one finding each). These are
  now dropped unless `cve.include_keyword_only: true`.
- **Version-unconfirmed CVEs collapse** into a single "needs manual validation"
  finding per service (`cve.collapse_version_unknown`, default true).
- **Stricter product matching** in `cpe_product_matches`: exact/token/alias only,
  removing the loose substring rule that caused cross-product matches
  (e.g. "ssh"→"openssh", "sql"→every SQL engine).
- **Finding dedup pass** (`dedupe_findings`) collapses identical endpoint+title
  rows from overlapping code paths, keeping the highest-confidence copy.

### New detection
- **Native SSH algorithm enumeration** (`scanners/ssh_algos.py`): read-only
  KEXINIT handshake (no auth) flags weak KEX/cipher/MAC/host-key. Works without
  nmap; falls back to NSE `ssh2-enum-algos` evidence when present.
- **Native SMB negotiate probe** (`scanners/smb_native.py`): read-only handshake
  detects SMBv1 support and message-signing posture (no auth, no tree connect).
- **Plaintext-protocol module**: flags Telnet/FTP/HTTP/r-services/SNMP/LDAP/VNC/
  TFTP cleartext exposure; ignores TLS tunnels; softens STARTTLS-capable services.
- **Service-detection nmap command now requests the right safe NSE scripts**
  (`ssh2-enum-algos`, `smb-security-mode`, `smb2-security-mode`, `ssl-enum-ciphers`,
  etc.) — previously `-sC` alone never collected SSH-algo or SMB-mode data.

### Handoff / export
- New `portwise handoff [--out plan.sh] [--category C] [--json]`: turns findings
  into SUGGESTED command templates for the operator's own tools (NetExec,
  ssh-audit, nuclei/ffuf/nikto/whatweb, testssl/sslscan, snmpwalk/onesixtyone,
  dig AXFR, searchsploit). PortWise never runs them; credential-attack commands
  are explicitly flagged as requiring authorization.

### New CLI views
- `portwise ports [--port N] [--protocol] [--service] [--min-count] [--hosts] [--json]`
  — open-port rollup across hosts ("port 22 open on N IPs, here are the IPs").
- `portwise summary [--json]` — PT overview: port histogram, cleartext exposure,
  weak-crypto highlights, actionable finding count.
- Scan summary reworked into the same compact PT view (no report spam).

## v0.2.0 — 2026-05-22

### Bug fixes

**Bug 1 — Protocol findings now respect the category system (false-positive reduction)**

Every `_simple_finding()` call in the registry modules previously defaulted to
`FindingCategory.VULNERABILITY`, inflating "Service Exposed" and version-disclosure
noise into the vulnerability bucket. Fixed:

- Added `category: FindingCategory` parameter to `FindingFactory.finding()` and
  `_simple_finding()`.
- Classified every registry call site:
  - Bare reachability ("SSH Exposed", "SMB Service Exposed", etc.) → `INFORMATION`
  - Version/OS/domain disclosures → `INFORMATION`
  - Real misconfigurations (SMBv1, RDP NLA Disabled, Anonymous FTP, Default SNMP
    Community, DNS Recursion Enabled, DNS Zone Transfer Allowed) → `VULNERABILITY`
  - Best-practice advisories (Legacy SSH, SNMP v1/v2c advisory, SMTP STARTTLS
    Missing, VRFY/EXPN Enabled) → `BEST_PRACTICE`
- Bare reachability findings downgraded from `Confidence.LIKELY` to
  `Confidence.INFORMATIONAL` (an open port is not a "likely" finding; nmap already
  confirmed it). `apply_category_rules` now correctly forces INFORMATION → INFO
  severity and caps BEST_PRACTICE at LOW for these findings.

**Bug 2 — Registry raw probes now route through the rate limiter (WAF/IDS risk)**

`registry.py` raw helpers (TCP, DNS, SNMP, NTP, SMTP) opened sockets with no
throttle, backoff, or circuit-breaker, firing back-to-back on multi-port targets
and tripping WAFs. Fixed:

- Each module's `run()` that performs raw probes now calls `client_from_config(config)`
  and gates every probe with `client.is_tripped(host)` / `client.throttle(host)`,
  matching the pattern already used by `TlsEngine`.
- `_safe_http_fingerprint()` now routes through `PoliteHttpClient.request()` when
  a client is provided, gaining throttle + exponential backoff + circuit-breaker +
  shared User-Agent for all DevOps, Kubernetes, and database HTTP fingerprint probes.
- A tripped circuit breaker on a host stops all further raw probes to that host
  in the same module run.
- Removed the duplicated hardcoded User-Agent string from `_http_request()`; uses
  the module-level `_BROWSER_UA` constant instead.

### Housekeeping

- Removed `portwise/intelligence/cve_placeholder.py` (deprecated re-export shim).
- Bumped version `0.1.0` → `0.2.0`.

### Previous fixpack (0.1.x → 0.2.0)

- Confidence/category model: `apply_confidence()`, `apply_category_rules()`,
  `apply_false_positive_rules()` pipeline.
- CVE version-range matching with KEV gating (`cve_enrichment.py`,
  `version_match.py`).
- Rate-limiting HTTP/TLS probes via `PoliteHttpClient` (min-delay, jitter,
  exponential backoff, per-host circuit breaker, request budget).
- Signature-based page detection for HTTP engine (`signatures.py`).
- Dark-theme HTML report with confidence/category badges.
- OCSP stapling check removed (passive-only scope).

---

## v0.1.0 - Initial MVP

Initial pre-release MVP for PortWise, an evidence-first VAPT intelligence and reporting tool.

### Added

- Cross-platform CLI with `init`, `scan`, `analyze`, `report`, `retest`, `modules`, and `version` commands.
- Workspace initialization for targets, scans, evidence, reports, runs, and logs.
- Configurable profiles for quick triage, internal VAPT, external VAPT, full VAPT, and offline analysis.
- Nmap XML parsing for assets, host status, hostnames, TCP/UDP ports, services, products, versions, CPEs, script output, confidence, and reasons.
- Safe Nmap command building with dry-run support, command metadata, timeout handling, and Windows non-admin SYN scan fallback to TCP connect scan.
- Scan phase chaining with live-host extraction, open-port extraction, grouped TCP/UDP service detection, and module target routing.
- Safe module framework and conservative modules for exposure, HTTP, TLS, SMB, SSH, RDP, WinRM, FTP, SNMP, DNS, NTP, databases, DevOps/admin panels, Kubernetes/container interfaces, mail, and VPN/security appliance fingerprints.
- Native Python TLS checks for certificates, expiry, hostname mismatch, protocol support where available, and HSTS.
- Safe HTTP checks for metadata, headers, cookies, methods, and bounded common-path exposure checks.
- Optional CVE enrichment through NVD, CISA KEV, and FIRST EPSS with caching and graceful offline failure handling.
- Confidence scoring, false-positive handling, evidence strength, manual-validation flags, and priority assignment.
- JSON, HTML, and Excel reporting.
- Retest comparison reports in JSON and Excel.
- Documentation-safe sample targets, Nmap XML, run JSON, and sample reports.
- GitHub Actions test workflow for Python 3.11 and 3.12.

### Initial scope notes

- The initial MVP shipped read-only native checks only; active/intrusive engines
  and credentialed checks arrived later as operator-opt-in scope.
- Imported findings and CVE matches are not treated as confirmed without active validation.
