# PortWise Roadmap

PortWise is the orchestration + correlation + CVE-mapping + de-duplication +
evidence/POC + reporting engine that ties best-in-class scanners and native
protocol checks into one prioritized, evidence-backed report.

The operator controls **depth** (`recon` = fast enumeration, `full` = complete
active assessment) and **scope** (intrusive or credentialed actions are explicit
opt-in per engagement). That is standard scope control, not a limitation.

This roadmap drives PortWise to professional-grade PT capability. Phases are
implemented in order, one commit per phase, tests green throughout.

**Status: Phases 0-7 complete; native rebuild Phase A complete.** 348 tests passing.

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
