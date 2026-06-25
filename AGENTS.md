# AGENTS.md — PortWise engineering operating contract

Binding rules for any AI agent (Claude Code or otherwise) that modifies this
repository. Read this before making changes. `CLAUDE.md` carries project
orientation; this file is how you work. These rules win over convenience.

## Mission

PortWise is a self-sufficient, professional penetration-testing platform. The
bar is native capability that ships with the tool, accurate findings, and speed
that holds up against the dedicated tools it replaces.

## Non-negotiables

1. **Self-sufficiency.** `pip install` must deliver full capability with nothing
   else to set up. Order of preference for any capability:
   native Python logic > bundled pip libraries > shipped/synced data files.
   External binaries (nuclei, ffuf, gowitness, netexec, masscan, sqlmap) may
   exist ONLY as optional accelerators behind the `ExternalTool` adapter — never
   required. nmap is the one assumed scanner, and a native connect-scan fallback
   covers its absence.

2. **Speed.** Async-first: `asyncio` with `curl_cffi`/`httpx`, bounded
   concurrency, connection pooling and keep-alive, streamed bodies. CPU-bound
   work (large regex / template matching) uses a process pool. Benchmark every
   engine and record req/s in its tests. Do not ship an engine an order of
   magnitude slower than the tool it replaces without a written reason.

3. **Human-like transport.** All HTTP flows through ONE shared transport built on
   `curl_cffi` with Chrome JA3/TLS + HTTP2 impersonation: realistic ordered
   headers, Sec-CH-UA, Accept-Language, cookie jar, redirect handling, timing
   jitter, user-agent rotation, optional upstream proxy (Burp/SOCKS). A
   Playwright path handles JS challenges. Never hand-roll a second HTTP path;
   never let fingerprinting cost coverage.

4. **Regression gate.** The full test suite stays green. Run `pytest -q` before
   every commit. Every change ships with tests.

5. **Voice.** Write like a senior operator: direct, technical, no hedging or
   disclaimer phrasing. Depth and scope are operator-driven — depth is `recon`
   (fast enumeration) or `full` (complete assessment); intrusive and credentialed
   actions are explicit opt-in. State capability plainly.

6. **Context7.** Pull current docs/APIs/schemas (curl_cffi, playwright, impacket,
   nuclei template format, Wappalyzer fingerprints, ExploitDB) from context7
   rather than memory — these change.

## Build loop — run per capability, autonomously

1. Implement natively (async, through the shared transport).
2. Unit tests.
3. Live-validate against the targets + answer keys below: compute TP / FP / FN,
   precision/recall, and req/s.
4. If false positives, misses, or it is slow → fix and re-loop (≤5 iterations,
   then record the blocker).
5. Run the full suite (gate — fix anything you broke).
6. Update `CHANGELOG.md` and `ROADMAP.md`; commit.

**Acceptance per capability:** precision ≥ 0.95 on the answer key, zero
regressions, benchmarked speed recorded. Pause only at phase-group boundaries
with a results summary (TP/FP/FN + speed per capability).

## Live validation targets

Use these public test endpoints (or operator-owned hosts) for live checks. Each
has a known answer key so true/false positives can be measured precisely.

- **scanme.nmap.org** — port/SSH/HTTP/version-disclosure baseline. Expect 22/ssh
  + 80/http and SSH/HTTP version disclosure; it must stay false-positive free
  (no invented criticals).
- **badssl.com** subdomains — TLS answer key.
  - MUST flag: `expired`, `self-signed`, `wrong.host`, `3des`, `dh1024`,
    `tls-v1-0` (:1010), `tls-v1-1` (:1011).
  - MUST NOT flag: `sha256`, `tls-v1-2` (:1012), `mozilla-modern`.
  - All subdomains share one IP — scan each name separately (SNI) rather than
    merging by IP.
- **testphp.vulnweb.com**, **testaspnet.vulnweb.com** — web crawl / fuzz /
  parameter discovery / tech fingerprint / JS analysis. These may return 403 to
  datacenter IPs; that itself exercises the transport layer (compare 403 rate
  through the JA3 transport vs a plain client).

## Commit & test discipline

- One logical change per commit; clear messages; commit per capability/phase.
- Never commit run output: `runs/`, `scans/`, `reports/`, `evidence/`, `cache/`,
  `config.yaml`.
- Keep `CHANGELOG.md` and `ROADMAP.md` current.

## When unsure

Make the change and report it. Stop only when a decision would change the
platform's identity or break a rule above.
