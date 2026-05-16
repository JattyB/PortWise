# Changelog

## v0.1.0 - Initial MVP

Initial pre-release MVP for PortWise, a safe, evidence-first VAPT intelligence and reporting tool.

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

### Safety Notes

- No exploit modules, brute force, password spraying, RCE payloads, fuzzing, DoS checks, write tests, or data dumping.
- Imported findings and CVE matches are not treated as confirmed without safe validation.
