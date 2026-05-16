# Contributing

PortWise is safe-by-default tooling for authorized VAPT and security audit workflows.

Contributions are welcome when they preserve that model:

- Use PortWise only on systems where you have explicit authorization.
- Do not add destructive modules.
- Do not add brute force, exploitation, RCE payloads, password spraying, fuzzing, DoS behavior, or data dumping.
- New modules must be read-only, safe by default, bounded by timeouts, and clear about confidence and false-positive risk.
- New checks must fail gracefully and must not break scans when a dependency, network path, or provider is unavailable.
- Add or update tests for new behavior.

Before opening a pull request, run:

```bash
python -m pytest
```
