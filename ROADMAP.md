# PortWise Roadmap

PortWise is the orchestration + correlation + CVE-mapping + de-duplication +
evidence/POC + reporting engine that ties best-in-class scanners and native
protocol checks into one prioritized, evidence-backed report.

The operator controls **depth** (`recon` = fast enumeration, `full` = complete
active assessment) and **scope** (intrusive or credentialed actions are explicit
opt-in per engagement). That is standard scope control, not a limitation.

This roadmap drives PortWise to professional-grade PT capability. Phases are
implemented in order, one commit per phase, tests green throughout.

**Status: Phases 0-7, native rebuild A-K, and hardening Phases L-P complete.**
The Metasploitable2 remediation loop is complete. P0 adds binary-protocol
HTTP guards, hard per-service deadlines, and local CPE-based CVE matching. P1
adds semantic deduplication, evidence merging, severity calibration, and
client-report cleanup. P2 adds native high-signal service exploit conditions
for the backdoored and command-execution services exposed by Metasploitable2.
P3 adds packaged EPSS/KEV enrichment and exploitability-aware priority.
The final report-hardening pass consolidates repeated service instances while
retaining affected ports and all supporting evidence.
Critical/high POC completeness and specific CVE naming are enforced in the
report artifact pipeline.

## Hardening Phases L-P

### L1 diagnostic follow-up

- Durable isolated stage profiling is available through
  `python -m portwise.modules.http.stage_profiler`. Every stage has an
  independent cap and immediately persists wall-clock, request count, req/s,
  completion state, and error text.
- Root cause fixed: crawler workers previously exited while the first request
  was still producing links, and a timed-out request killed its worker while
  queued work remained, causing `queue.join()` to wait indefinitely. Safe paths
  were also serialized before stage telemetry began.
- The crawler and safe-path probes now use bounded concurrency and explicit
  time budgets. Async stages remain on the shared transport's owning event loop.
  The non-deep aggregate host budget defaults to 300 seconds.
- Final post-fix live testaspnet default run: 291.99 seconds total, with active
  requests in every stage, a complete durable table, and no teardown errors.
  It stays below the five-minute host budget; capped stages emit explicit notes.

### L2 consolidated rerun

- Shared-IP DNS targets are restored as logical named assets before routing;
  expired, self-signed, and TLS-1.0 badssl checks now execute with independent
  SNI and finding identities.
- Windows Playwright capture/PDF use a dedicated Proactor loop and complete
  without the selector-loop subprocess errors found on the first L2 attempt.
- The bounded consolidated scan completed in 865.23 seconds. It produced native
  template results, 21 screenshots, HTML/PDF output, and 106 POC artifacts.
- The scanme Google Analytics false positive was traced to an off-origin JS
  fetch. Same-origin enforcement removed it; targeted live revalidation
  completed in 26.28 seconds with zero high/critical findings.

- **L:** Web stages now record separate wall-clock metrics. The crawler, fuzzer,
  parameter discovery, and template engine expose independent bounded
  concurrency. Hostname mismatch has positive fixture proof. The public
  testaspnet default full-web run remained a known live issue: it exceeded the
  600-second validation window before producing stage results.
- **M:** Explicitly supplied credentials can be checked across routed HTTP and
  SMB targets at a configurable rate. A non-reversible credential identifier
  detects reuse across successful hosts without persisting a password.
- **N:** Correlation emits attack-path findings only for exact credential
  identity reuse or explicit secret-to-endpoint evidence links. Negative
  fixtures prevent same-host coincidence from producing a chain.
- **O:** Configured allowlists and exclusions accept CIDRs, hosts, and domains.
  Supplied out-of-scope targets hard fail, discovered out-of-scope URLs are
  dropped, and bypass requires the explicit scope override.
- **P:** Reports support managed-Chromium PDF output, client name/logo branding,
  operator-injected findings, and stable false-positive suppression files whose
  fingerprints are honored by reporting and future configured runs.

## E2E fixes - template sweep and Windows base install

- Base installs no longer depend on impacket. AD/SMB/LDAP depth is available via
  the `portwise[ad]` extra, and modules keep the existing lazy-import
  availability note when impacket is absent or quarantined.
- Native template sweeps use template-specific concurrency, request budget, and
  delay controls through the shared curl_cffi transport.
- Generic template selection is tiered: default runs execute stack-matched
  templates plus critical exposures; `--deep` / `web_template_engine.selection.deep`
  enables the larger generic CVE/misconfiguration sweep.
- Validation: Windows base install succeeds without impacket, AD modules keep
  lazy degradation, scanme/badssl answer keys hold, and testaspnet deep selected
  template sweep completes at 43.17 templates/sec. Full suite: 405 passed.

## Native rebuild Phase K - native TCP connect-scan fallback

**Goal:** remove the last hard external dependency for a basic run by making
TCP discovery work without nmap.

- PortWise now selects a native async TCP connect scan when nmap is absent or
  when `scanner.force_native_connect_scan` is enabled. The fallback probes a
  configurable common-port set, records open ports, synthesizes assets, and
  feeds them into the existing module-routing pipeline.
- Nmap remains the preferred path when present. The native fallback only takes
  over when the binary is missing or the operator explicitly forces it.
- Fixture validation keeps the selector honest: nmap-present runs stay on the
  nmap path; import-failure handling for impacket now emits a clear
  AD/SMB-availability note instead of silently producing zero findings.
- Live validation on `scanme.nmap.org` with nmap hidden from PATH found ports
  22 and 80, routed HTTP and SSH modules, and measured 2.96 ports/sec on the
  local box. With nmap present, the runner stayed on the nmap path.

## Native rebuild Phase J - AD / SMB / auth via impacket

**Goal:** native AD/SMB assessment using optional impacket, with credentialed
actions opt-in and off by default.

- `impacket>=0.13.0` is installed through `portwise[ad]`. SMB authentication
  uses impacket directly when the extra is present; `nxc`/`netexec` are no
  longer required for capability.
- SMB checks now combine the existing native SMB NEGOTIATE probe with optional
  impacket null-session/share/OS/domain/signing enumeration.
- LDAP routing and an LDAP module enumerate anonymous-bind users, groups,
  computers, domain metadata, SPN accounts, and no-preauth accounts where the
  directory permits anonymous reads.
- Authenticated full-depth checks use supplied SMB credentials for share access
  and Kerberos roast request construction. Evidence contains request metadata
  only and redacts supplied secrets.
- Fixture validation: TP=6 FP=0 FN=0, precision=1.000, recall=1.000 across SMB
  enumeration, LDAP enumeration, Kerberoast construction, AS-REP construction,
  and must-not-emit controls.
- Live validation: public targets exposed no SMB. Localhost TCP/445 was
  reachable, but Windows Defender blocked the local impacket user-site import;
  the live impacket enum failed closed with zero findings.

## Native rebuild Phase I - Playwright screenshots

**Goal:** browser-rendered screenshot evidence without required external
binaries.

- Screenshot capture now uses Playwright through the optional
  `portwise[screenshots]` extra instead of gowitness. The engine launches a
  managed Chromium browser context, captures each unique discovered web service,
  and writes PNGs to `evidence/screenshots`.
- The screenshot evidence contract is stable: findings receive `engine`,
  `url`, and `screenshot` fields, and the POC bundle includes the image path.
- Missing Playwright or missing managed Chromium is a clean skip with an
  operator note; screenshot capture is not a hard dependency and never blocks
  the scan.
- Live validation produced screenshots for `scanme.nmap.org` and
  `testaspnet.vulnweb.com`; both paths were referenced from matching findings
  and the generated POC index. Absent-extra simulation returned no findings and
  a clear `install portwise[screenshots]` note.

## H1-FIX - curl_cffi async transport teardown

**Goal:** eliminate curl_cffi async socket callback errors during shutdown.

- Sync `PoliteHttpClient` requests now use a client-owned background event loop
  instead of repeated `asyncio.run()` calls. The shared curl_cffi `AsyncSession`
  stays bound to one loop for that client lifecycle.
- Module execution injects one shared HTTP client per host batch and explicitly
  closes it after the host's sequential modules complete. Shutdown order is now
  close session, let callbacks settle, then stop and close the loop.
- Dependency floor is `curl_cffi>=0.15.0`; Context7 confirms the current async
  cleanup API is `await AsyncSession.close()` / `async with AsyncSession()`.
- Live validation over scanme, expired.badssl, and testaspnet completed with no
  `Event loop is closed` or curl_cffi callback teardown messages; explicit
  HTTP/TLS module execution produced 18 module results and 29 findings.

## Native rebuild Phase H - TLS deepening and native ExploitDB

**Goal:** sslyze-class native TLS assessment depth and native offline
ExploitDB correlation without requiring external binaries.

- TLS now keeps the default vulnerability path fast while adding optional full
  per-version cipher inventory through `tls.native_full_enumeration`. The
  inventory records accepted cipher/protocol combinations in an informational
  finding; default-on checks still cover certificates, chain trust, hostname
  matching, deprecated protocols, weak cipher families, weak DH parameters, and
  HSTS.
- Certificate evidence includes revocation and issuer metadata exposed by the
  local OpenSSL decoder (`OCSP`, `caIssuers`, CRL distribution points) when
  present.
- Native weak cipher probes run bounded family/raw/DH checks concurrently.
- Exploit intel now ships the official ExploitDB `files_exploits.csv` as package
  data and performs native offline matching by CVE code, product, and detected
  version. `searchsploit` is optional compatibility only, not required
  capability.
- Fixture validation: Log4j CVE lookup, Apache httpd 2.4.7 exact lookup,
  OpenSSH `< 7.4` range lookup, and Apache httpd 2.4.8 must-not-match control:
  TP=3 FP=0 FN=0, precision=1.000, recall=1.000.
- Live validation: badssl answer key remained TP=7 FP=0 FN=0, precision=1.000,
  recall=1.000, speed=0.073 targets/sec. Scanme live service detection found
  OpenSSH 6.6.1p1 and Apache httpd 2.4.7; native ExploitDB returned expected
  references for both, and the Apache 2.4.8 control returned zero hits.

## Native rebuild Phase G - native nuclei-style template engine

**Goal:** Native nuclei-format HTTP template execution through the shared
transport with correctness-first matcher and extractor semantics.

- Added a native async YAML template engine for HTTP templates with method/path,
  raw-request, headers, and body support, plus concurrent execution through the
  shared curl_cffi transport.
- Implemented matchers for `status`, `word`, `regex`, `binary`, and `size`,
  including `matchers-condition`, negative matching, and `part` selection across
  `body`, `header`, and `all`.
- Implemented extractors for `regex`, `kval`, and practical `json` paths, and
  mapped template metadata and classification onto normal findings.
- Added packaged curated templates plus configurable operator template
  directories for custom coverage.
- G-EXPAND: added a native sync/filter script and shipped a substantial
  runnable upstream slice from ProjectDiscovery `nuclei-templates` with manifest
  metadata, pinned source commit, and MIT license attribution. Only templates
  supported by the native engine are shipped.
- Added stack-aware selection so template execution is narrowed by detected
  technologies, service metadata, and product/header terms instead of running
  the whole corpus against every target.
- Unsupported features are skipped and logged rather than crashing. Current skip
  list: top-level `workflow`/`workflows`/`flow`, `interactsh`, HTTP request keys
  `payloads`/`attack`/`race`/`threads`, and matcher/extractor types outside the
  supported subset such as `dsl`.
- Fixture proof covers matcher types `status`, `word`, `regex`, `binary`, and
  `size`; matcher `and`/`or`; negative matchers; parts `body`, `header`, and
  `all`; and extractor types `regex`, `kval`, and `json`.
- Live validation: curated templates achieved TP=4 FP=0 FN=0 across
  `scanme.nmap.org` and `testaspnet.vulnweb.com`, matching Apache on scanme and
  IIS + ASP.NET + exposed `robots.txt` on testaspnet. `testphp.vulnweb.com`
  remained unreachable from this network, so no reachable-path template run was
  possible there. Live throughput was 1.55 templates/sec; fixture benchmark was
  >=100 templates/sec. Full suite green: 381 passed.
- G-EXPAND validation: sync scanned 4,043 candidate upstream templates and
  shipped 2,815 runnable ones, skipping 1,228 unsupported templates at sync
  time. The full runnable corpus is now 2,819 templates including the original
  curated local set. Selected-mode live runs were FP=0: `scanme.nmap.org`
  selected 105/2819 templates and matched 1 expected Apache finding;
  `testaspnet.vulnweb.com` selected 14/2819 templates and matched 4 expected
  findings (IIS, ASP.NET, IIS version, `robots.txt`). Combined TP=5 FP=0 FN=0,
  precision=1.000, recall=1.000.
- G-RECALL-CHECK: selection now keeps generic exposure, misconfiguration,
  default-login/default-credential, common-file exposure, and CVE/vulnerability
  templates always-on in addition to stack-matched templates. Selection
  breakdown is recorded per run. Packaged-corpus breakdown:
  `scanme.nmap.org` selected 1269/2819 templates (tech-matched=104,
  always-on generic=1211, explicit=1, overlap=47);
  `testaspnet.vulnweb.com` selected 1220/2819 templates (tech-matched=13,
  always-on generic=1211, explicit=1, overlap=5). Live vulnweb reachability
  timed out from this network; the deterministic vulnerable-response fixture
  proves an exposed-file/CVE template fires under an unrelated detected stack:
  TP=1 FP=0 FN=0, precision=1.000, recall=1.000.

## Native rebuild Phase F - JavaScript endpoint extraction and secret analysis

**Goal:** Native JS endpoint extraction and secret detection through the shared
transport, with strict false-positive control.

- Added JS analysis over the shared discovered surface with same-origin fetch
  of JS assets and extraction of URLs/endpoints from fetch/XHR/axios calls,
  literals, and script references.
- Added package-data secret rules and a native scanner using regex, entropy,
  and context checks; findings are redacted and marked manual-validation.
- Moved secret scanning out of the crawler so inventory and secret detection are
  cleanly separated.
- F-FIX: added a positive JS-endpoint extraction fixture that proves same-origin
  relative paths, absolute URLs, `fetch()`, `axios`, XHR, `new URL()`, and
  script-source extraction while suppressing off-origin and control values.
- Live validation: `testaspnet.vulnweb.com` produced 16 crawl endpoints, 0 JS
  endpoints on the live surface, and 0 false positives at 1.22 crawl req/s.
  `testphp.vulnweb.com` archive validation fetched 1 archived JS snapshot and
  extracted 0 endpoints with 0 false positives at 20.89 req/s. Fixture
  precision/recall: 1.000/1.000 for both secrets and positive JS extraction.
  Full suite green: 372 passed.

---

## Native rebuild Phase E - content and directory fuzzing

**Goal:** Native ffuf-equivalent content discovery with strict false-positive
control through the shared transport.

- Added an async wordlist fuzzer with bounded concurrency, per-host
  politeness/jitter, configurable status/size/word/line/regex filters, optional
  bounded recursion, and shared discovered-surface deduplication.
- Shipped a compact default package wordlist and support for external wordlist
  paths.
- Strengthened soft-404 handling: multiple random-path baselines are compared
  against every candidate by status, size, word count, line count, normalized
  body digest, and body similarity; sensitive content signatures are reused.
- New genuine hits are added to the discovered surface for later fuzzing and
  template phases.
- Live validation: testaspnet baseline was five random 404 responses with
  size=1245, words=95, lines=30, digest prefix `aa29693f2673e265`. Fuzzer found
  9 expected real paths and six random non-existent paths were suppressed:
  TP=9 FP=0 FN=0, precision=1.000, recall=1.000 at 9.34 req/s. Full suite green:
  371 passed.

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
