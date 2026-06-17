# Contributing

PortWise is a penetration-testing orchestration platform for authorized
engagements. The operator controls assessment depth (`recon` / `full`) and
scope (intrusive or credentialed actions are explicit opt-in).

Contributions are welcome when they preserve the platform's design:

- Use PortWise only on systems where you have explicit authorization.
- Keep protocol-level checks **native** and dependency-free.
- Orchestrate heavy/fast-moving engines (nuclei, ffuf, gowitness, testssl,
  masscan) as **optional** integrations through the `ExternalTool` adapter:
  detect on PATH → run with timeout → parse JSON → graceful fallback to handoff.
  Do not reimplement those engines in Python.
- Intrusive or credentialed actions run only at `full` depth or behind an
  explicit flag — framed as engagement scope control.
- Preserve de-duplication, confidence scoring, and CVE version-matching; do not
  regress false-positive controls.
- New checks must fail gracefully and must not break scans when a dependency,
  network path, or provider is unavailable.
- Add or update tests for new behavior.

Before opening a pull request, run:

```bash
python -m pytest -q
```
