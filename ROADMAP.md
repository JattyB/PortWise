# PortWise Roadmap

PortWise is the orchestration + correlation + CVE-mapping + de-duplication +
evidence/POC + reporting engine that ties best-in-class scanners and native
protocol checks into one prioritized, evidence-backed report.

The operator controls **depth** (`recon` = fast enumeration, `full` = complete
active assessment) and **scope** (intrusive or credentialed actions are explicit
opt-in per engagement). That is standard scope control, not a limitation.

This roadmap drives PortWise to professional-grade PT capability. Phases are
implemented in order, one commit per phase, tests green throughout.

**Status: Phases 0-7 complete; native rebuild Phases A-D complete.** 365 tests passing.

---

## Native rebuild Phase D - crawler and URL discovery

**Goal:** Native async crawler, archive URL discovery, and parameter discovery
through the shared transport.

- Rebuilt web crawling around an async same-origin crawler with bounded
  concurrency, configurable depth/page/JS budgets, robots handling, dedup,
  off-origin redirect skips, and link/form/JS-source extraction.
- Added a shared discovered-surface object for endpoints, forms, JS files,
  archive URLs, and parameters so later content fuzzing and template phases can
  consume one normalized surface.
- Added archive discovery from Wayback CDX (`matchType=host`), Common Crawl,
  OTX, and urlscan.io without contacting the live target.
- Added archive parameter extraction and bounded active parameter probing that
  detects meaningful reflection, status changes, and response-shape changes.
- Windows now installs `WindowsSelectorEventLoopPolicy` before curl_cffi async
  sessions, removing the selector warning in the full suite.
- Live validation: testaspnet crawl TP=30 FP=0 FN=0, precision=1.000,
  recall=1.000 at 5.65 req/s. Active parameter probing ran 48 tests at
  10.17 req/s and found no additional hidden parameters, TP=0 FP=0 FN=0.
  testphp archive discovery found 497 historical URLs independent of live-host
  reachability, including 250 Wayback URLs; archive parameter extraction found
  expected `artist`, TP=1 FP=0 FN=0, precision=1.000, recall=1.000 at
  158.70 URL/sec. Full suite green: 365 passed.

---

## Native rebuild Phase C - HTTP probe and technology fingerprinting

**Goal:** Native async HTTP probing and Wappalyzer-compatible technology
fingerprinting through the shared transport.

- Added `AsyncHttpProber` for status/title/header/body metadata and explicit
  redirect-chain capture through `PoliteHttpClient`.
- Redirect following is configurable in the shared curl_cffi transport, preserving
  the one-transport rule while allowing probe-level redirect evidence.
- Shipped ProjectDiscovery's MIT Wappalyzer fingerprint dataset as pip package
  data and added native detection for headers, cookies, meta tags, body patterns,
  script URLs, versions, categories, and implied technologies.
- HTTP module findings now include a technology inventory finding with matched
  names, versions, confidence, categories, and evidence sources.
- Live validation: scanme HTTP 200 detected `Apache HTTP Server 2.4.7`; testaspnet
  HTTP 200 detected `IIS 8.5` and `Microsoft ASP.NET 2.0.50727`. TP=3 FP=0 FN=0,
  precision=1.000, recall=1.000. Batch benchmark: 14.35 req/s over 20 live
  requests with zero errors. Full suite green: 361 passed.

---

## Native rebuild Phase B - transport and anti-bot foundation

**Goal:** All HTTP traffic routes through one shared async browser-impersonated
transport.

- Rebuilt `portwise.utils.http_client` around `curl_cffi.requests.AsyncSession`
  with Chrome impersonation, pooled connections, bounded concurrency, redirects,
  cookies, proxy/Burp support, configurable browser profiles, and async
  `request_async()` support while preserving the existing sync module API.
- Vhost/SNI scans use libcurl host resolution so the scanned IP is used for the
  TCP connection while the URL host, Host header, and SNI remain the DNS name.
- Circuit breakers now back off only on explicit rate-limit evidence; generic
  blocks, connection errors, and timeouts do not starve other modules.
- Playwright challenge clearing is optional via `portwise[browser]`; absence is
  non-fatal. Hard HTTP blocks emit `WAF / Access Blocked` findings.
- CVE enrichment and registry web probes no longer open separate HTTP stacks.
- Live validation: scanme HTTP HEAD/GET 200; badssl TP=7 FP=0 FN=0,
  precision=1.000, recall=1.000, speed=0.053 checks/sec. Vulnweb block-rate
  drop was not measurable from this network because `testphp.vulnweb.com`
  timed out through both clients and reachable `testaspnet.vulnweb.com` showed
  0/5 blocks on both plain stdlib and JA3 transport. Async transport benchmark:
  17.23 req/s vs 1.76 req/s sequential stdlib. Full suite green: 354 passed.
- B-VERIFY: one-off `tls.peet.ws/api/all` validation proves the shared transport
  is current Chrome, not stdlib/OpenSSL: HTTP/2, Chrome 146 UA/Sec-CH-UA,
  JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, Akamai HTTP/2 fingerprint
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`, and Chrome header order.
  The stdlib control is HTTP/1.1 with JA4 `t13d1813h1_85036bcba153_fb8d5ffd48c1`
  and no HTTP/2 fingerprint.

---

## Native rebuild Phase A - urgent live-test fixes

**Goal:** Fix TLS and nmap regressions found during live validation before
starting the broader native rebuild.

- TLS cert analysis no longer depends on Python 3.12's removed
  `ssl.match_hostname`; SAN/CN matching is native and wildcard matching is
  limited to one left-most label.
- Cert retrieval uses a non-verifying handshake so expired, self-signed, and
  wrong-host certificates can be collected and assessed instead of collapsing to
  "Certificate Not Retrieved." Trust-chain validation runs separately and emits
  "Untrusted Certificate Chain" when the default trust store rejects the chain.
- Native weak-cipher probing pins TLS 1.2 and filters negotiated suites before
  recording a weak-cipher finding. A raw TLS ClientHello probe covers 3DES on
  OpenSSL builds that no longer expose 3DES client suites.
- Grouped nmap service detection includes `-Pn`, and nmap subprocess arguments
  use absolute targets/workspace/generated paths.
- Port-scan assets are merged into the run before module routing, so module
  targets still exist when service-detection output is absent.

**Validation:** badssl answer key TP=7 FP=0 FN=0, precision=1.000,
recall=1.000, speed=0.043 checks/sec. Non-admin scanme run used `-sT` and
grouped `-Pn`, found 22/25/80/443 with service/version data, no failed phases,
and zero critical findings. Full suite green: 348 passed.

---

## Phase 0 — Foundation + rename

**Goal:** Clean foundation and correct positioning.

- Rename the `safe` validation level to `recon` across config, CLI choices,
  profiles, docstrings, comments, and tests. CLI `--validation-level` choices
  become `recon` / `full`.
- Remove all "safe-by-default / safe / controlled" positioning wording from
  README, CHANGELOG, docstrings, and CLI help; describe PortWise as an
  operator-controlled-depth-and-scope PT orchestration platform.
- Add `portwise doctor`: detect installed optional engines (nuclei, ffuf,
  gowitness, testssl, masscan, nmap, ssh-audit, searchsploit) and report which
  checks are therefore available.
- Add an `ExternalTool` adapter base: detect-on-PATH → run-with-timeout → parse
  JSON → graceful skip + handoff fallback. All future integrations use it.
- Add config schema validation with helpful errors.
- Remove the leftover `_fixpack/` folder. Verify IPv6 target handling.

**Acceptance:** No `validation_level: safe` anywhere; CLI rejects `safe` and
accepts `recon`. `portwise doctor` lists engine availability. `ExternalTool`
adapter exists with tests. Config errors are actionable. `_fixpack/` gone.
Full suite green.

## Phase 1 — Parallelism

**Goal:** Biggest perf win — concurrent module execution.

- Run module checks over targets through a bounded thread pool with a
  configurable concurrency limit (default ~10).
- Preserve per-host throttle/politeness (the circuit breaker / throttle is
  per-host) and produce deterministic output ordering regardless of completion
  order.

**Acceptance:** Concurrency is configurable; output ordering is deterministic
and identical to serial output; per-host throttle preserved. Tests assert
ordering + concurrency. Suite green.

## Phase 2 — Web depth (optional engines)

**Goal:** Best-in-class web coverage via orchestration.

- Integrate **nuclei** (optional): run against discovered web targets, parse
  `-jsonl` into findings with severity/CVE mapping, dedup against existing
  findings.
- Integrate **ffuf** (optional) with configurable external wordlist support
  (e.g. SecLists); fold results into content discovery behind the existing
  soft-404 / content-signature guards.
- Keep the native crawler; feed its discovered endpoints to ffuf/nuclei when
  present. When a binary is absent, skip cleanly and emit the equivalent
  handoff command.

**Acceptance:** With binaries present, JSON output is parsed into deduped
Findings; absent, runs are skipped with a note + handoff. Tests use captured
JSON fixtures (no live binary). Suite green.

## Phase 3 — Screenshot evidence

**Goal:** Visual proof for web services.

- Integrate **gowitness** (or headless Chromium) optionally to screenshot each
  web service; attach image paths to findings/evidence for the report and POC
  bundle.

**Acceptance:** When available, screenshots are captured and referenced from
evidence; absent, skipped with a note. Tests cover path attachment. Suite green.

## Phase 4 — Deepen fingerprint-only services + vhost

**Goal:** Replace fingerprint-only stubs with real native checks.

- **NTP:** mode-6 / monlist amplification checks.
- **WinRM:** auth-method enumeration.
- **VPN appliances:** known exposure path probes.
- **SNMP:** write-community check.
- **vhost/SNI:** Host-header and SNI handling so name-based / Cloudflare-fronted
  vhosts are testable, not just the bare IP.

**Acceptance:** Each service emits evidence-backed findings from a real probe;
vhost/SNI is honored by HTTP/TLS engines. Tests with mocked sockets. Suite
green.

## Phase 5 — Vuln intel depth

**Goal:** Exploitability context on CVEs.

- Cross-reference version-matched CVEs with exploit availability (searchsploit /
  ExploitDB index and/or nuclei template presence); annotate findings with an
  `exploit_available` flag + reference.

**Acceptance:** Version-matched CVE findings carry an exploit-availability flag
and reference when an exploit/template is known. Tests with fixtures. Suite
green.

## Phase 6 — Reporting

**Goal:** Auditor-grade report output.

- Executive-summary narrative.
- Per-host grouped view.
- CSV findings export.
- Surface retest diffs in the HTML report.
- Keep the current clean visual theme.

**Acceptance:** HTML report shows exec summary, per-host grouping, and retest
diffs; CSV export produced. Tests assert content. Suite green.

## Phase 7 — Authenticated assessment (operator opt-in)

**Goal:** Credentialed depth, explicitly scoped.

- Allow the operator to supply credentials (config/flags) for authenticated
  checks (web login, SMB with a user, SNMP). Explicit opt-in, clearly scoped per
  engagement.

**Acceptance:** Credentials are only used when explicitly supplied; authenticated
checks are gated behind the opt-in and clearly labeled. Tests cover the gate.
Suite green.

---

## Cross-cutting

- Config schema validation with helpful errors (Phase 0).
- IPv6 target handling verified (Phase 0).
- `_fixpack/` removed (Phase 0).
- External engines are always optional: detect → run JSON → parse → graceful
  fallback to handoff. Never reimplement nuclei/ffuf/nmap in Python.
- Tests stay green; add tests for every feature; one commit per phase.
