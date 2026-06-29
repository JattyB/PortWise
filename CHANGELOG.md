# Changelog

## Metasploitable2 remediation — final validation corrections

- De-duplication now treats the issue identity as `(asset, port, issue)` and
  merges corroborating TCP/UDP evidence instead of emitting duplicate rows.
- CVE findings now receive only ExploitDB records explicitly mapped to that
  CVE. Product/version title matching remains a fallback for records without a
  CVE, preventing cross-product exploit-reference noise.

## Metasploitable2 remediation — P3

- Added packaged FIRST EPSS records with probability, percentile, and date,
  plus a CISA KEV subset preserving the catalog schema.
- CVE findings are enriched offline, including service-specific exploit
  findings that do not originate in the local CVE corpus.
- Priority now combines severity, confidence, KEV, EPSS, and packaged
  ExploitDB availability. KEV and high-confidence critical exploits are P1;
  high-EPSS CVEs outrank generic cleartext findings.
- EPSS percentile and KEV status are surfaced in HTML, PDF, CSV, and JSON.
- Live WSL validation populated EPSS for all Metasploitable2 CVEs. None of the
  validated legacy CVEs are currently present in CISA KEV; they remain
  prioritized by severity, EPSS, and exploit availability.

## Metasploitable2 remediation — P2

- Added native service-exploit correlation for the vsftpd 2.3.4 backdoor,
  UnrealIRCd backdoor, exposed distccd command execution, Samba 3.0.20
  username-map command execution, and unauthenticated root bind shells.
- Findings use exact version, product/port, banner, and SMB null-session
  evidence. They enter the normal CVE deduplication and packaged ExploitDB
  enrichment path.
- Live WSL validation confirmed all five conditions on `192.168.1.15`.

## Metasploitable2 remediation — P1

- Finding deduplication now groups semantic endpoint issues, merges evidence,
  tags, references, exploit signals, and confidence, and retains the strongest
  finding. The original 53-finding Metasploitable2 report collapses to 23
  distinct endpoint issues.
- Exposure, plaintext, service-module, and owner-validation variants no longer
  produce separate rows for FTP, Telnet, SSH, SMB, or Tomcat.
- SSH algorithm findings are consolidated into `Weak SSH Cryptography`; legacy
  exposure/version rows are consolidated into `Legacy SSH Service`.
- Missing HTTP header rows are consolidated into one finding per endpoint.
- Script banners and STARTTLS certificate output no longer cross-route SMTP or
  PostgreSQL into DNS/direct-TLS modules.
- Generic exposure findings are informational. Protocol findings carry impact
  severity.
- Unknown findings no longer receive the repetitive generic four-step
  remediation block. Specific remediation remains attached where available.
- phpinfo uses a disclosure-specific description. POC commands and captured
  output populate the pentest appendices when the bundle exists.
- HTML/PDF templates remove authorization/safety positioning language from the
  cover, footer, tags, and rendered text.

## Metasploitable2 remediation — P0

- Binary services such as AJP, RMI, DRb, databases, SMB, and RPC no longer
  enter the HTTP engine because their product string contains an HTTP vendor
  token.
- Every routed HTTP service has a hard wall-clock deadline. A blocked native
  transport call emits `HTTP Check Not Completed` and the host pipeline
  continues.
- Runtime CVE matching is local and deterministic. A packaged NVD-2.0-shaped
  corpus uses strict CPE 2.3 vendor/product identity plus inclusive/exclusive
  version ranges; scans no longer depend on live NVD responses.
- Nmap CPE 2.2 URIs and known product/version fingerprints are normalized into
  CPE 2.3 candidates. Web technology components with versions enter the same
  local matcher.
- Version-matched CVEs are cross-referenced against the packaged ExploitDB CSV
  even when distribution backport sensitivity keeps finding confidence at
  manual validation.

## L1 diagnostic telemetry

- Added an isolated native web-stage profiler with a hard per-stage cap.
- Crawl, archive, fuzz, parameter discovery, default templates, and deep
  templates now produce independent wall-clock, request-count, and req/s rows.
- Each row is appended and flushed to JSONL immediately and printed, preserving
  completed/capped measurements if a later stage or outer run is terminated.
- Diagnosis identified crawler worker loss/deadlock on request failures and
  premature idle-worker exit. Workers now remain available for discovered
  links, failed requests cannot strand queue items, and JavaScript fetches use
  the crawler's bounded concurrency.
- Crawler requests default to zero transport retries and enforce a Python-level
  total timeout. Repeated failed Playwright challenge attempts are suppressed
  per host.
- Safe-path probes now run concurrently under a 60-second budget. All web
  stages run on the shared client's owning loop, eliminating cross-loop session
  teardown and template-limit resize deadlocks.
- Default non-deep runs have a configurable 300-second per-host aggregate
  budget plus stage-specific caps. Budget exhaustion is persisted and printed
  as `stage time-budget reached`.
- The final live default testaspnet validation completed in 291.99 seconds,
  including active crawl, archive, fuzz, parameter, and template requests.
  Default templates completed 1,543 requests in 72.08 seconds (21.41 req/s).
  Crawl, archive, and parameter discovery reached their clean stage budgets;
  fuzz and templates completed normally.

## L2 consolidated pipeline hardening

- Operator-supplied DNS targets now remain distinct logical assets after Nmap
  merges shared addresses. HTTP Host/SNI, finding identity, and deduplication
  therefore preserve each badssl name.
- Playwright screenshot and PDF subprocesses now run on an isolated Windows
  Proactor loop while curl_cffi retains its selector-based shared transport.
  This removes `NotImplementedError` task leaks during browser teardown.
- JS analysis now fetches same-origin scripts only. The scanme validation had
  followed Google Analytics and reported its public SDK key as a secret; the
  off-origin fetch is now blocked and the targeted rerun is FP-free.
- Full-depth HTTP raises its request budget before preflight so safe-path probes
  cannot silently starve crawl, fuzz, parameter, or template stages.
- The bounded five-name pipeline completed in 865.23 seconds with independent
  badssl SNI findings, 21 screenshots, 18 native template findings, HTML/PDF
  reports, and 106 POC files. CVE enrichment ran but produced no version-matched
  CVEs, so ExploitDB correctly recorded no applicable enrichment.

## Hardening and depth — Phases L–P

- Added per-host web-stage wall-clock telemetry for crawl, archive, fuzz,
  parameter discovery, default templates, and deep templates. Crawl, fuzz, and
  parameter engines retain independent configurable async concurrency.
- Added stable redacted credential identifiers, configurable supplied-credential
  validation rate, and confirmed cross-host credential-reuse findings.
- Added a high-precision correlation pass for credential reuse and explicitly
  linked client-secret/endpoint attack paths.
- Added fail-closed scope allow/exclude policy support for CIDRs, hosts, and
  domains, CLI scope files, an explicit override, and discovered-URL filtering.
- Added PDF rendering from the self-contained pentest HTML via managed Chromium,
  client name/logo branding, operator manual-finding injection, and persistent
  false-positive suppression fingerprints.
- Added deterministic fixture validation for all new paths. The existing
  hostname-mismatch TLS fixture remains the positive proof for the deferred
  wrong.host.badssl.com validation.
- Known issue: the June 27 live default full-web validation against
  testaspnet.vulnweb.com again exceeded 600 seconds before returning stage
  metrics. The target/network path spent requests at timeout and the process was
  terminated at 604 seconds. Fixture precision remained 1.000; live per-stage
  throughput could not be computed from the terminated run.

## Unreleased

### E2E fixes - template sweep and Windows base install
- Moved `impacket>=0.13.0` out of base dependencies and into the optional
  `portwise[ad]` extra. AD/SMB/LDAP modules continue to import impacket lazily
  and emit the existing availability note when the extra is absent or blocked.
- Added template-engine-specific concurrency, request budget, and delay knobs.
  Native nuclei-style sweeps now run through the shared curl_cffi transport with
  a higher template pool instead of crawler limits.
- Split generic template selection into a small default critical-exposure tier
  and a deep generic CVE/misconfiguration tier enabled by `--deep` or
  `web_template_engine.selection.deep: true`.
- Fixed web-phase config plumbing for crawl/archive/fuzz/parameter/template
  sections and made optional Playwright screenshot failures degrade cleanly when
  Windows cannot spawn the browser helper.
- Validation: clean Windows base install completed with no impacket present;
  isolated testaspnet deep selected sweep ran 1,220 templates / 1,851 requests
  in 28.3s at 43.17 templates/sec. Live answer-key groups held for scanme and
  badssl. Full suite: 405 passed.

### Phase K - native TCP connect-scan fallback
- Added a native async TCP connect scanner as the basic discovery fallback when
  nmap is absent or `scanner.force_native_connect_scan` is enabled. The fallback
  probes a configurable common-port list, synthesizes assets, and feeds the
  existing module-routing pipeline so `scanme.nmap.org` still routes HTTP and
  SSH modules without nmap.
- Kept the nmap path unchanged when the binary is present. Added validation for
  both selector paths and recorded the native scan benchmark (ports/sec).
- Impacket import/load failures in SMB/LDAP checks now emit a clear
  `AD/SMB checks unavailable: impacket could not load (blocked or not importable)`
  note instead of silently returning zero findings when the live dependency is
  unavailable.

### Phase J - AD / SMB / auth via impacket
- Added `impacket>=0.13.0` as a bundled dependency for AD/SMB capability. SMB
  authentication no longer shells out to `nxc`/`netexec`; the authenticated SMB
  path uses impacket `SMBConnection` directly and remains gated by the existing
  `authenticated: true` / `--authenticated` full-depth opt-in.
- Added impacket-backed SMB enumeration helpers for null-session checks, share
  enumeration, signing posture, dialect, OS, domain, and server metadata. The
  existing native SMB NEGOTIATE probe still covers fast SMBv1/signing overlap.
- Added LDAP target routing and an LDAP module for impacket anonymous-bind
  enumeration of users, groups, computers, domain metadata, SPN-bearing
  accounts, and no-preauth accounts when the directory permits anonymous reads.
- Added credentialed Kerberoast and AS-REP roast request construction through
  impacket helpers. Evidence records request metadata only; supplied passwords
  are redacted and never written to findings.
- Fixture validation: SMB null session/share/signing/OS/domain parsing, LDAP
  anonymous object parsing, Kerberoast request construction, AS-REP request
  construction, and must-not-emit controls all pass: TP=6 FP=0 FN=0,
  precision=1.000, recall=1.000.
- Live validation: public validation targets exposed no SMB. Localhost TCP/445
  was reachable, but Windows Defender blocked the local impacket user-site
  import as potentially unwanted software, so live impacket enumeration failed
  closed with no findings. Full suite: 400 passed.

### Phase I - Playwright screenshots
- Replaced the optional gowitness screenshot path with native Playwright
  capture behind the `portwise[screenshots]` extra. Screenshot capture uses a
  real Chromium browser context, ignores HTTPS errors by default for assessment
  targets, writes PNG evidence under `evidence/screenshots`, and records
  `engine=playwright`, `url`, and `screenshot` evidence fields.
- Missing Playwright or missing managed Chromium never crashes the scan. PortWise
  skips screenshot capture with a clear note (`install portwise[screenshots]` or
  `playwright install chromium`) and continues.
- Screenshot evidence remains attached to matching web findings and dedicated
  screenshot findings, so the existing POC bundle includes image paths without a
  report-format contract change.
- Validation: live capture produced PNGs for `scanme.nmap.org` and
  `testaspnet.vulnweb.com` and the generated POC index referenced both image
  paths. Absent-extra validation returned zero findings plus a clear skip note.

### H1-FIX - curl_cffi async transport teardown
- Fixed curl_cffi shutdown races where async socket callbacks could fire after
  their event loop closed. Sync `PoliteHttpClient` calls now run on a
  client-owned background event loop instead of repeatedly creating loops with
  `asyncio.run()`, keeping the shared `AsyncSession` and libcurl callbacks on
  one loop until explicit shutdown.
- Added explicit `PoliteHttpClient.close()` / `close_sync()` cleanup. Module
  execution now injects one shared HTTP client per host work batch and closes it
  after that host's sequential modules complete, enforcing session close before
  loop teardown.
- Checked current curl_cffi docs: `AsyncSession.close()` is async and releases
  underlying resources, and `async with AsyncSession()` is the documented
  lifecycle. Raised the dependency floor to `curl_cffi>=0.15.0`, the latest
  installed and published version in this environment.
- Validation: a full multi-target CLI scan over `scanme.nmap.org`,
  `expired.badssl.com`, and `testaspnet.vulnweb.com` completed with no
  `Event loop is closed`, `Exception ignored from cffi callback`, or
  `RuntimeError: Event loop is closed` messages. A forced live HTTP/TLS module
  run over the same target set exercised shared curl sessions across scanme,
  expired.badssl, and testaspnet: 18 module results, 29 findings, zero teardown
  messages.

### Phase H - TLS deepening and native ExploitDB
- Deepened the native TLS path with optional full per-version cipher inventory
  (`tls.native_full_enumeration`) that records accepted cipher/protocol
  combinations as an informational finding. The default TLS path remains focused
  on fast vulnerability coverage: certificate metadata, chain trust, hostname
  matching, deprecated protocols, weak cipher families, weak DH parameters, and
  HSTS.
- Certificate evidence now carries revocation/issuer metadata exposed by the
  local OpenSSL decoder (`OCSP`, `caIssuers`, and CRL distribution points) when
  available.
- Native weak cipher probes now run bounded probes concurrently, preserving
  3DES/DH coverage while reducing wall-clock impact versus sequential handshakes.
- Replaced required `searchsploit` usage with a native offline ExploitDB lookup
  over packaged `data/exploitdb/files_exploits.csv`, synced from the official
  Exploit Database GitLab dump. Matching supports exact CVE codes plus
  product/version title matching with guarded range handling. `searchsploit`
  remains optional compatibility only.
- ExploitDB fixture validation: Log4j CVE lookup, Apache httpd 2.4.7 exact
  product/version lookup, OpenSSH `< 7.4` range lookup, and Apache httpd 2.4.8
  must-not-match control all pass: TP=3 FP=0 FN=0, precision=1.000,
  recall=1.000.
- Live validation: badssl answer-key pass stayed green at TP=7 FP=0 FN=0,
  precision=1.000, recall=1.000, speed=0.073 targets/sec. Live scanme service
  detection found OpenSSH 6.6.1p1 on 22/tcp and Apache httpd 2.4.7 on 80/tcp;
  native ExploitDB returned expected references for both (Apache EDB-34133 and
  EDB-40142; OpenSSH EDB-40962, EDB-40963, and EDB-45939) with the Apache
  2.4.8 control returning zero hits. Full suite: 387 passed.

### Phase G - native nuclei-style template engine
- Added a native async nuclei-style HTTP template engine with YAML parsing,
  concurrent execution through the shared curl_cffi transport, request-path and
  raw-request support, matchers for `status`, `word`, `regex`, `binary`, and
  `size`, and extractors for `regex`, `kval`, and `json`.
- Template metadata now maps onto normal PortWise findings, including severity,
  description, references, and CVE/CVSS classification.
- Unsupported features are skipped and logged rather than crashing. Current
  skipped features include top-level `workflow`/`workflows`/`flow`,
  `interactsh`, HTTP request keys `payloads`/`attack`/`race`/`threads`, and
  matcher or extractor types outside the supported subset such as `dsl`.
- Added a curated packaged template set for live validation and operator
  override support via configurable template directories.
- G-EXPAND: synced a substantial upstream slice from ProjectDiscovery
  `nuclei-templates` into package data using a native sync/filter script. The
  shipped sync source is commit `ffa35164980a981fb28374c317caff2b94e4a607`
  across `http/technologies`, `http/exposures`, `http/misconfiguration`, and
  `http/exposed-panels`, with MIT license attribution and a manifest. Sync-time
  filtering kept only templates the native engine can execute.
- Added stack-aware template relevance selection based on detected
  technologies, service metadata, and product/header terms, so PortWise runs
  only relevant templates instead of the full shipped corpus on every target.
- Fixture proof now covers matcher types `status`, `word`, `regex`, `binary`,
  and `size`, matcher `and`/`or`, negative matchers, parts `body`, `header`,
  and `all`, plus extractor types `regex`, `kval`, and `json`.
- Live validation: curated templates produced TP=4 FP=0 FN=0 across
  `scanme.nmap.org` and `testaspnet.vulnweb.com`, matching Apache on scanme and
  IIS + ASP.NET + `robots.txt` on testaspnet. `testphp.vulnweb.com` remained
  unreachable from this network, so no reachable-path template check ran there.
  Live throughput was 1.55 templates/sec with four templates over each reachable
  target. Fixture benchmark recorded >=100 templates/sec on the in-process fake
  harness. Full suite: 381 passed.
- G-EXPAND validation: upstream sync scanned 4,043 candidate templates and
  shipped 2,815 runnable synced templates, skipping 1,228 unsupported ones at
  sync time. With the original 4 curated local templates, the full runnable
  corpus is 2,819 templates. Selected-template live runs stayed false-positive
  free: `scanme.nmap.org` selected 105/2819 templates and matched 1 Apache
  technology template; `testaspnet.vulnweb.com` selected 14/2819 templates and
  matched 4 expected findings (IIS, ASP.NET, IIS version, `robots.txt`). Live
  selected-mode result: TP=5 FP=0 FN=0, precision=1.000, recall=1.000.
- G-RECALL-CHECK: template selection now always carries generic exposure,
  misconfiguration, default-login/default-credential, common-file exposure, and
  CVE/vulnerability templates alongside stack-tagged templates. The run result
  records a breakdown of `tech_matched`, `always_on_generic`,
  `explicit_always_include`, and dedupe overlap. Packaged-corpus selection
  breakdown: `scanme.nmap.org` selected 1269/2819 templates
  (tech-matched=104, always-on generic=1211, explicit=1, overlap=47);
  `testaspnet.vulnweb.com` selected 1220/2819 templates (tech-matched=13,
  always-on generic=1211, explicit=1, overlap=5). Live vulnweb reachability
  timed out from this network, so the vulnerable-template path is proven by a
  fixture that serves an exposed `.env` response and confirms the generic
  exposure/CVE template fires under an unrelated Apache stack: TP=1 FP=0 FN=0,
  precision=1.000, recall=1.000.

### Phase F - JavaScript endpoint extraction and secret analysis
- Added a native JavaScript analysis pass that reuses the shared discovered
  surface, fetches same-origin JS through the shared curl_cffi transport, and
  extracts URLs/endpoints from fetch/XHR/axios calls, string literals, and
  script references. Newly discovered endpoints are fed back into the shared
  surface for later phases.
- Added gitleaks-style secret rules as package data plus a native secret scanner
  with regex, entropy, and context checks. Findings are redacted and marked for
  manual validation rather than echoing raw values.
- Moved secret scanning out of the crawler so the crawler now owns surface
  inventory and the dedicated analyzer owns secret findings.
- F-FIX: added a positive JavaScript endpoint-extraction fixture covering
  relative paths, same-origin absolute URLs, `fetch()`, `axios`, `XHR.open`,
  `new URL()`, and script sources. The fixture suppresses off-origin URLs and
  non-HTTP/control values. Fixture precision/recall: 1.000/1.000.
- Validation: fixture precision/recall reached 1.000/1.000 with
  must-not-flag samples `example.js`, `noise.js`, `doc.js`, and
  `vendor.min.js` suppressed. Live validation on `testaspnet.vulnweb.com`
  found 16 same-origin crawl endpoints, 0 JS-file endpoints on the live surface,
  and 0 false positives at 1.22 crawl req/s. Archive validation on
  `testphp.vulnweb.com` fetched 1 archived JS snapshot and extracted 0
  endpoints with 0 false positives at 20.89 req/s. Full suite: 372 passed.

### Phase E - native content and directory fuzzing
- Added a native async content fuzzer using the shared Chrome-fingerprinted
  transport, bounded concurrency, per-host politeness, configurable response
  filters, optional bounded recursion, and discovered-surface deduplication.
- Shipped a compact default content-fuzzing wordlist as package data and added
  external wordlist support for SecLists-style files.
- False-positive control is baseline-first: the fuzzer calibrates multiple
  random non-existent paths and compares every candidate response by status,
  byte size, word count, line count, normalized body digest, and body similarity
  before reporting. Existing content signatures are reused for sensitive paths.
- New fuzzer hits are written back into the shared discovered surface for later
  phases.
- Validation: `testaspnet.vulnweb.com` soft-404 baseline used five random paths,
  each returning HTTP 404 with size=1245, words=95, lines=30, digest prefix
  `aa29693f2673e265`. Fuzzing found 9 real paths:
  `/about.aspx`, `/default.aspx`, `/login.aspx`, `/Signup.aspx`,
  `/rssFeed.aspx`, `/Comments.aspx`, `/ReadNews.aspx`, `/ads/def.html`, and
  `/robots.txt`. TP=9 FP=0 FN=0, precision=1.000, recall=1.000 at 9.34 req/s.
  Six additional random non-existent paths all matched the baseline and were not
  reported as findings. Full suite: 371 passed.

### Phase D - native crawler and URL discovery
- Silenced Windows `curl_cffi` selector warnings by installing
  `WindowsSelectorEventLoopPolicy` before async curl sessions are created.
- Rebuilt the web crawler around an async same-origin crawl core using the shared
  Chrome-fingerprinted transport. The crawler now supports configurable depth,
  page and JS budgets, bounded concurrency, robots `Disallow` handling, link,
  form, JS-source, endpoint, and secret extraction, deduplication, and
  off-origin redirect skips.
- Added a shared discovered-surface model that records endpoints, forms,
  JavaScript files, archive URLs, and parameters for later content fuzzing and
  template phases.
- Added native archive URL discovery from Wayback CDX (`matchType=host`),
  Common Crawl, OTX, and urlscan.io. Archive discovery queries public archives,
  so it works independently of whether the live target is reachable.
- Added archive parameter extraction and bounded active parameter probing. Active
  probing routes through the shared transport and detects meaningful reflection,
  status changes, and response-shape changes while ignoring ASP.NET self-post
  form-action echo.
- Validation: `testaspnet.vulnweb.com` crawl found 16 expected endpoints and 14
  expected parameters/form fields, TP=30 FP=0 FN=0, precision=1.000,
  recall=1.000 at 5.65 req/s. Active probing ran 48 tests at 10.17 req/s and
  found no additional hidden parameters on the answer key, TP=0 FP=0 FN=0.
  Archive discovery for `testphp.vulnweb.com` found 497 historical URLs
  independent of live-host reachability, including 250 Wayback URLs, 250 OTX
  URLs, and 5 urlscan URLs; parameter extraction found the expected `artist`
  parameter, TP=1 FP=0 FN=0, precision=1.000, recall=1.000 at 158.70 URL/sec.
  Full suite: 365 passed.

### Phase C - native HTTP probe and technology fingerprinting
- Added a native async HTTP prober that uses the shared `PoliteHttpClient`
  transport for status, title, headers, body hashing, and explicit redirect-chain
  capture. Redirect following is now configurable on the one shared transport so
  probes can record chains without opening a second HTTP path.
- Shipped the MIT-licensed ProjectDiscovery Wappalyzer fingerprint dataset as
  package data and added a native Wappalyzer-compatible detector for headers,
  cookies, meta tags, HTML/text patterns, script URLs, inline scripts, URL
  patterns, versions, confidences, categories, and implied technologies.
- HTTP module output now includes an `HTTP Technology Fingerprint` informational
  finding with matched technologies, versions, confidence, categories, and
  evidence sources.
- Validation: `scanme.nmap.org` returned HTTP 200, title "Go ahead and ScanMe!",
  and detected `Apache HTTP Server 2.4.7` plus `Ubuntu`. `testaspnet.vulnweb.com`
  returned HTTP 200, title "acublog news", and detected `IIS 8.5` plus
  `Microsoft ASP.NET 2.0.50727`. Answer-key pass TP=3 FP=0 FN=0,
  precision=1.000, recall=1.000. Live probe batch speed: 14.35 req/s across
  20 requests with zero errors.

### Phase B - native rebuild transport and anti-bot foundation
- Replaced the legacy `requests`/stdlib HTTP client with one shared
  `curl_cffi` async transport using Chrome impersonation (`impersonate="chrome"`),
  pooled async sessions, bounded concurrency, persistent cookies, redirects,
  optional HTTP/SOCKS proxy support, and configurable browser-profile rotation.
- Preserved the existing `PoliteHttpClient` module interface while adding
  `request_async()` and full-URL `request_url()` helpers. Vhost/SNI targets now
  use libcurl `RESOLVE` mapping so the URL host, Host header, and TLS SNI stay
  coherent while connecting to the scanned IP.
- Circuit-breaker behavior now trips only on explicit rate-limit signals
  (429 or 403 with retry/rate-limit indicators). Generic 403s, timeouts, and
  connection errors no longer starve other modules.
- Added optional Playwright challenge clearing behind `portwise[browser]`.
  When Playwright is absent, the transport degrades cleanly and returns the
  original blocked response.
- HTTP homepage blocks now emit a `WAF / Access Blocked` finding instead of
  silently reporting "HTTP Check Not Completed" or producing misleading header
  findings.
- Routed CVE provider downloads through the shared HTTP client and removed the
  secondary `requests`/`urllib` fetch path. Removed the unused raw registry HTTP
  helper.
- Tightened native TLS weak-cipher probing after live validation: weak-family
  probes only record negotiated suites from the requested family, raw 3DES
  fallback runs only when normal certificate retrieval fails, and weak-DH
  probing is scoped to standard HTTPS unless explicitly forced.
- Dependencies: `curl_cffi` is now a default pip dependency; Playwright is an
  optional `browser` extra.
- Validation: `scanme.nmap.org` HTTP HEAD/GET returned 200 through the new
  transport. badssl answer-key pass TP=7 FP=0 FN=0, precision=1.000,
  recall=1.000 at 0.053 checks/sec. `testaspnet.vulnweb.com` completed with
  0/5 blocks through both plain stdlib and JA3 transport; `testphp.vulnweb.com`
  timed out through both clients from this network, so the requested block-rate
  drop was not measurable. Async transport benchmark on reachable vulnweb paths:
  17.23 req/s versus 1.76 req/s for sequential stdlib. Full suite: 354 passed.
- B-VERIFY added a one-off non-runtime validator against `tls.peet.ws/api/all`.
  PortWise now proves Chrome 146 impersonation with HTTP/2, Sec-CH-UA, stable
  JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, Akamai HTTP/2 fingerprint
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`, and Chrome header order.
  The stdlib control stays distinct: HTTP/1.1, no Sec-CH-UA/H2 fingerprint,
  JA3 hash `331a436afb23d4e31134c11b301bdcb5`, and JA4
  `t13d1813h1_85036bcba153_fb8d5ffd48c1`.

### Phase A - native rebuild urgent fixes
- TLS certificate retrieval now uses a non-verifying handshake first, decodes the
  peer certificate locally, and separately reports expiry, self-signed
  certificates, hostname mismatch, and untrusted certificate chains.
- Replaced removed Python 3.12 `ssl.match_hostname` usage with native SAN/CN
  hostname matching. DNS wildcards only match one left-most label.
- Native weak-cipher probing now pins TLS 1.2, ignores TLS 1.3 negotiated
  suites, avoids AES-CBC false positives, and includes a raw TLS ClientHello
  probe for 3DES when OpenSSL 3 no longer exposes 3DES client suites.
- Nmap service-detection groups now include `-Pn`; scan targets, workspace
  paths, generated scan paths, and grouped host files are resolved to absolute
  paths before subprocess execution.
- Parsed port-scan assets are merged into the run before module routing, so
  module targets are still built when service-detection XML is missing or a
  service-detection group fails.
- Validation: badssl answer-key pass TP=7 FP=0 FN=0, precision=1.000,
  recall=1.000 at 0.043 checks/sec. Non-admin scanme run used `-sT` plus
  grouped `-Pn`, found ports 22/25/80/443 with service data, no failed phases,
  and zero critical findings. Full suite: 348 passed.

## v0.7.0 — orchestration platform foundation

PortWise is a penetration-testing orchestration platform: the orchestration +
correlation + CVE + de-duplication + evidence + reporting engine that ties
best-in-class scanners and native protocol checks into one prioritized,
evidence-backed report. The operator controls **depth** (`recon` = fast
enumeration, `full` = complete active assessment) and **scope** (intrusive or
credentialed actions are explicit opt-in per engagement).

### Phase 7 — authenticated assessment (operator opt-in)
- Credentials framework (`credentials.py`): load from `credentials:` config or
  `--cred SERVICE:USER:PASS` / `--cred-file`; master `authenticated` switch.
  Only operator-supplied credentials are used — no brute force, no guessing.
- Authenticated checks gated to **explicit opt-in AND full depth**:
  - **Web**: HTTP Basic auth + form login with supplied creds.
  - **SMB**: orchestrated netexec/nxc session check (graceful skip + handoff).
  - **SNMP**: supplied community strings fed into read + write checks.
- Passwords are redacted in all output. HTTP client gained `extra_headers`/`body`
  support to enable Basic auth and form login.

### Phase 6 — reporting
- **Executive-summary narrative** at the top of the HTML report (severity chips,
  priority drivers — exploit-available/KEV/cleartext — and a "remediate first"
  list), plus a reusable text version.
- **Findings-by-host** grouped view with per-host severity rollup.
- **CSV findings export** (`--format csv`, included in `all`) — flat,
  spreadsheet/grep-friendly, with exploit/KEV columns.
- **Retest diff in HTML**: `report --previous <run.json>` embeds a Fixed/Still
  Open/New section.
- Exploit availability surfaced in the findings table, per-host view, and detail.
  Kept the clean visual theme.

### Phase 5 — vuln intel depth (exploit availability)
- Cross-reference version-matched CVE findings (Likely/Confirmed) with public
  exploit availability via **searchsploit/ExploitDB** (JSON) and **nuclei
  template** presence in the local templates tree. Local-only, no network.
- Findings gain `exploit_available` + `exploit_refs` (EDB IDs/URLs, template
  paths) and an `exploit-available` tag; results cached per CVE.
- New "Exploit intel" scan phase and `exploit_intel:` config section.

### Phase 4 — deepened service checks + vhost/SNI
- **NTP**: native mode-6 (control readvar) and mode-7 monlist probes — flags
  amplification/disclosure vectors, monlist tagged CVE-2013-5211 (HIGH).
- **WinRM**: unauthenticated auth-method enumeration from WWW-Authenticate;
  flags Basic auth (HIGH over cleartext 5985, MEDIUM over 5986).
- **VPN appliances**: vendor SSL-VPN login-portal probes (Fortinet, GlobalProtect,
  Ivanti/Pulse, Citrix/NetScaler, Cisco, SonicWall) confirm exposed entry points.
- **SNMP**: opt-in, non-destructive write-community check (sysName.0 round-trip
  SET) — CRITICAL when a community grants write; gated to `full` depth +
  `snmp.write_check`. Added a small BER encoder/decoder for SNMP SET/GET.
- **vhost/SNI**: targets carry their DNS hostname; HTTP/TLS modules send a
  `Host:` header and TLS SNI for the name so name-based / fronted vhosts are
  tested instead of only the bare IP. New SNI-controlled HTTPS client path.

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
