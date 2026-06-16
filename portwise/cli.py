from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from portwise import __version__
from portwise.core.config import ConfigError, load_config
from portwise.core.logging import configure_logging
from portwise.core.progress import PHASE_DONE, PHASE_FAILED, PHASE_RUNNING, ProgressTracker, default_scan_phases, load_progress, update_progress_file_phase
from portwise.core.runner import analyze_assets, build_run_state_from_assets, run_scan
from portwise.core.routing import write_target_files
from portwise.core.workspace import create_workspace
from portwise.intelligence.importers import import_nessus_csv, import_testssl_json
from portwise.modules.registry import available_modules
from portwise.reporting.excel_report import write_excel_report
from portwise.reporting.html_report import write_html_report
from portwise.reporting.json_report import build_json_report_from_dict
from portwise.reporting.pentest_report import write_pentest_report
from portwise.reporting.retest import write_retest_report
from portwise.scanners.nmap_parser import parse_nmap_xml
from portwise.utils.files import ensure_text, make_json_safe, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portwise",
        description="Safe, evidence-first VAPT intelligence and reporting.",
        epilog="Examples: portwise scan --targets targets.txt --profile full-vapt --config config.yaml --dry-run | portwise report --run runs/latest.json --format all",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    parser.add_argument("--debug", action="store_true", help="Show tracebacks for unexpected runtime errors.")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init", help="Create a PortWise workspace.")
    init_cmd.add_argument("project_name")

    scan_cmd = sub.add_parser("scan", help="Build and optionally run safe nmap scan steps.")
    scan_cmd.add_argument("--targets", required=True, type=Path)
    scan_cmd.add_argument("--profile", required=True)
    scan_cmd.add_argument("--config", type=Path, default=Path("config.yaml"))
    scan_cmd.add_argument("--workspace", type=Path, default=Path("."))
    scan_cmd.add_argument("--dry-run", action="store_true", default=True, help="Build commands without executing nmap. Default.")
    scan_cmd.add_argument("--execute", action="store_true", help="Execute nmap commands. Use only with authorization.")
    scan_cmd.add_argument("--skip-udp", action="store_true")
    scan_cmd.add_argument("--udp-open-filtered", action="store_true")
    scan_cmd.add_argument("--validation-level", choices=["safe", "full"], default=None,
                          help="'safe' = light recon only. 'full' = run every active check (default for full-vapt).")
    scan_cmd.add_argument("--internet-facing", action="store_true")
    scan_cmd.add_argument("--timeout", type=int)
    scan_cmd.add_argument("--no-cve", action="store_true")
    scan_cmd.add_argument("--no-modules", action="store_true")
    scan_cmd.add_argument("--no-progress", action="store_true", help="Disable live progress output and only print the JSON command summary.")
    scan_cmd.add_argument("--polite", action="store_true", help="4× request delays and halved budget. For sensitive targets.")
    scan_cmd.add_argument("--aggressive", action="store_true", help="Reduced delays for authorized lab/CTF use only.")
    scan_cmd.add_argument("--debug", action="store_true", help="Show traceback for unexpected errors.")

    analyze_cmd = sub.add_parser("analyze", help="Analyze existing Nmap XML.")
    analyze_cmd.add_argument("--nmap", required=True, type=Path)
    analyze_cmd.add_argument("--profile", default="offline-analysis")
    analyze_cmd.add_argument("--config", type=Path, default=Path("config.yaml"))
    analyze_cmd.add_argument("--workspace", type=Path, default=Path("."))
    analyze_cmd.add_argument("--active-modules", action="store_true", help="Allow safe HTTP/TLS active checks during analysis.")
    analyze_cmd.add_argument("--testssl-json-dir", type=Path, help="Import recognizable testssl JSON findings as manual-validation evidence.")
    analyze_cmd.add_argument("--nessus-csv", type=Path, help="Import common Nessus CSV fields as non-confirmed findings.")
    analyze_cmd.add_argument("--no-cve", action="store_true")
    analyze_cmd.add_argument("--debug", action="store_true", help="Show traceback for unexpected errors.")

    report_cmd = sub.add_parser("report", help="Generate report from a run JSON.")
    report_cmd.add_argument("--run", required=True, type=Path)
    report_cmd.add_argument("--format", choices=["json", "excel", "html", "pentest", "all"], default="json")
    report_cmd.add_argument("--output", type=Path)
    report_cmd.add_argument("--evidence-dir", type=Path, help="Write per-finding sanitized evidence transcripts to this directory.")
    report_cmd.add_argument("--debug", action="store_true", help="Show traceback for unexpected errors.")

    retest_cmd = sub.add_parser("retest", help="Compare previous and current run JSON files.")
    retest_cmd.add_argument("--previous", required=True, type=Path)
    retest_cmd.add_argument("--current", required=True, type=Path)
    retest_cmd.add_argument("--format", choices=["json", "excel", "all"], default="json")
    retest_cmd.add_argument("--output-dir", type=Path, default=Path("reports"))
    retest_cmd.add_argument("--debug", action="store_true", help="Show traceback for unexpected errors.")

    status_cmd = sub.add_parser("status", help="Show current or last PortWise run progress.")
    status_cmd.add_argument("--workspace", type=Path, default=Path("."))
    status_cmd.add_argument("--debug", action="store_true", help="Show traceback for unexpected errors.")

    ports_cmd = sub.add_parser("ports", help="Aggregate open ports across hosts (e.g. which IPs have 22 open).")
    ports_cmd.add_argument("--run", type=Path, default=Path("runs/latest.json"))
    ports_cmd.add_argument("--port", type=int, help="Filter to a single port number.")
    ports_cmd.add_argument("--protocol", choices=["tcp", "udp"], help="Filter by protocol.")
    ports_cmd.add_argument("--service", help="Filter by service name substring (e.g. ssh, http).")
    ports_cmd.add_argument("--min-count", type=int, default=1, help="Only show ports open on at least N hosts.")
    ports_cmd.add_argument("--hosts", action="store_true", help="List the affected IPs under each port.")
    ports_cmd.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    ports_cmd.add_argument("--debug", action="store_true")

    summary_cmd = sub.add_parser("summary", help="PT-buddy overview: port histogram, cleartext exposure, weak crypto.")
    summary_cmd.add_argument("--run", type=Path, default=Path("runs/latest.json"))
    summary_cmd.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    summary_cmd.add_argument("--debug", action="store_true")

    handoff_cmd = sub.add_parser("handoff", help="Emit suggested attack-tool commands per finding (PortWise never runs them).")
    handoff_cmd.add_argument("--run", type=Path, default=Path("runs/latest.json"))
    handoff_cmd.add_argument("--out", type=Path, help="Write a review-before-run .sh script to this path.")
    handoff_cmd.add_argument("--category", help="Filter to one category (smb-relay, ssh-weak-crypto, web, tls, snmp, dns, rdp, ftp, cve, default-creds).")
    handoff_cmd.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    handoff_cmd.add_argument("--debug", action="store_true")

    poc_cmd = sub.add_parser("poc", help="Generate per-finding POC/evidence files (optionally capture read-only output).")
    poc_cmd.add_argument("--run", type=Path, default=Path("runs/latest.json"))
    poc_cmd.add_argument("--out", type=Path, default=Path("evidence/poc"))
    poc_cmd.add_argument("--min-severity", default="low", choices=["critical", "high", "medium", "low", "informational"])
    poc_cmd.add_argument("--capture", action="store_true", help="Run safe read-only POC commands (nmap/curl/openssl/dig/ssh-audit) and save output as evidence.")
    poc_cmd.add_argument("--debug", action="store_true")

    sub.add_parser("modules", help="List available safe modules.")

    sub.add_parser("version", help="Show PortWise version.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        if args.command == "init":
            root = create_workspace(args.project_name)
            print(f"Created workspace: {root}")
            return 0

        if args.command == "version":
            print(f"PortWise {__version__}")
            return 0

        if args.command == "scan":
            config = load_config(args.config)
            profile = config.get_profile(args.profile)
            if args.skip_udp:
                profile.nmap_steps = [step for step in profile.nmap_steps if not step.startswith("udp")]
            if args.timeout:
                config.scanner["nmap_timeout_seconds"] = args.timeout
                config.scanner["timeout"] = args.timeout
            # Validation level precedence: explicit CLI flag > profile > config default > safe.
            effective_vl = (
                args.validation_level
                or profile.raw.get("validation_level")
                or config.scanner.get("validation_level")
                or "safe"
            )
            config.scanner["validation_level"] = effective_vl
            config.scanner["internet_facing"] = args.internet_facing
            config.scanner["udp_service_detection_on_open_filtered"] = args.udp_open_filtered
            if args.polite:
                config.raw["politeness_mode"] = "polite"
            elif args.aggressive:
                config.raw["politeness_mode"] = "aggressive"
            dry_run = not args.execute
            progress = None
            if not args.no_progress:
                progress_config = config.raw.get("progress", {}) if isinstance(config.raw.get("progress"), dict) else {}
                progress = ProgressTracker(
                    workspace=args.workspace,
                    profile=profile.name,
                    phases=default_scan_phases(profile.nmap_steps),
                    enabled=bool(progress_config.get("enabled", True)),
                    show_current_command=bool(progress_config.get("show_current_command", True)),
                )
            run = run_scan(
                args.workspace,
                config,
                profile,
                args.targets,
                dry_run=dry_run,
                no_modules=args.no_modules,
                no_cve=args.no_cve,
                internet_facing=args.internet_facing,
                progress=progress,
            )
            if progress:
                progress.skip_phase("Report generation", "Run portwise report --run runs/latest.json --format all to generate reports.")
            state = run.metadata.get("state", {})
            summary = {
                "run": str(args.workspace / "runs" / "latest.json"),
                "dry_run": dry_run,
                "commands": [command.command for command in run.commands],
                "tcp_service_detection_group_count": len(state.get("tcp_service_detection_groups", [])),
                "udp_service_detection_group_count": len(state.get("udp_service_detection_groups", [])),
                "tcp_service_detection_groups": state.get("tcp_service_detection_groups", []),
                "udp_service_detection_groups": state.get("udp_service_detection_groups", []),
                "generated_files": state.get("generated_files", []),
                "skipped_phases": state.get("skipped_phases", []),
                "module_routing": state.get("module_targets", {}),
                "module_runs": state.get("module_runs", []),
                "expected_routing_steps": [
                    "Parse discovered services",
                    "Classify HTTP/TLS/SMB/remote-access/database/devops/container/VPN targets",
                    "Write evidence/targets/*.json",
                ],
            }
            if args.no_progress:
                print(json.dumps(make_json_safe(summary), indent=2))
            else:
                _print_scan_summary(run, state)
            return 0

        if args.command == "analyze":
            config = load_config(args.config)
            profile = config.get_profile(args.profile)
            assets = parse_nmap_xml(args.nmap)
            targets = [asset.ip for asset in assets]
            modules = profile.modules
            run = analyze_assets(
                assets,
                project=str(config.project.get("name", args.workspace.name)),
                profile=profile.name,
                context=profile.context,
                enable_tls=args.active_modules and bool(modules.get("tls", False)),
                enable_http=args.active_modules and bool(modules.get("http", False)),
                enable_exposure=bool(modules.get("exposure", True)),
                no_cve=args.no_cve or not bool(modules.get("cve_enrichment", False)),
            )
            imported_findings = []
            import_notes = []
            testssl_findings, testssl_notes = import_testssl_json(args.testssl_json_dir)
            nessus_findings, nessus_notes = import_nessus_csv(args.nessus_csv)
            imported_findings.extend(testssl_findings + nessus_findings)
            import_notes.extend(testssl_notes + nessus_notes)
            run.findings.extend(imported_findings)
            run.evidence.extend([e for f in imported_findings for e in f.evidence])
            if import_notes:
                run.metadata["import_notes"] = import_notes
            state = build_run_state_from_assets(assets, run.project, run.profile, targets=targets)
            state.generated_files.extend(write_target_files(state.module_targets, args.workspace))
            run.metadata["state"] = state.to_dict()
            output = args.workspace / "runs" / "latest.json"
            write_json(output, run.to_dict())
            print(json.dumps({"run": str(output), "assets": len(run.assets), "findings": len(run.findings)}, indent=2))
            return 0

        if args.command == "report":
            with args.run.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            report = build_json_report_from_dict(data)
            output_dir = Path("reports")
            written: list[str] = []
            update_progress_file_phase(Path("."), "Report generation", PHASE_RUNNING, f"Generating {args.format} report output")
            report_errors: list[str] = []
            if args.format in {"json", "all"}:
                default_json = output_dir / ("sample_report.json" if "examples" in str(args.run) else "PortWise_Report.json")
                output = args.output if args.format == "json" and args.output else default_json
                try:
                    write_json(output, report)
                    written.append(str(output))
                except Exception as exc:
                    report_errors.append(f"json: {ensure_text(exc)}")
            if args.format in {"excel", "all"}:
                output = args.output if args.format == "excel" and args.output else output_dir / "PortWise_Report.xlsx"
                try:
                    write_excel_report(report, output)
                    written.append(str(output))
                except Exception as exc:
                    report_errors.append(f"excel: {ensure_text(exc)}")
            if args.format in {"html", "all"}:
                output = args.output if args.format == "html" and args.output else output_dir / "PortWise_Report.html"
                try:
                    write_html_report(report, output)
                    written.append(str(output))
                except Exception as exc:
                    report_errors.append(f"html: {ensure_text(exc)}")
            if args.format in {"pentest", "all"}:
                output = args.output if args.format == "pentest" and args.output else output_dir / "PortWise_Pentest_Report.html"
                try:
                    write_pentest_report(report, output)
                    written.append(str(output))
                except Exception as exc:
                    report_errors.append(f"pentest: {ensure_text(exc)}")
            evidence_dir = getattr(args, "evidence_dir", None)
            if evidence_dir:
                _export_evidence_transcripts(report, Path(evidence_dir), written, report_errors)
            status = PHASE_DONE if written and not report_errors else PHASE_FAILED
            message = f"Wrote {len(written)} report file(s)" + (f"; errors: {'; '.join(report_errors)}" if report_errors else "")
            update_progress_file_phase(Path("."), "Report generation", status, message)
            print(json.dumps(make_json_safe({"written": written, "errors": report_errors}), indent=2))
            return 0 if written else 1

        if args.command == "retest":
            written = write_retest_report(args.previous, args.current, args.output_dir, args.format)
            print(json.dumps({"written": [str(path) for path in written]}, indent=2))
            return 0

        if args.command == "status":
            _print_status(args.workspace)
            return 0

        if args.command == "ports":
            return _cmd_ports(args)

        if args.command == "summary":
            return _cmd_summary(args)

        if args.command == "handoff":
            return _cmd_handoff(args)

        if args.command == "poc":
            return _cmd_poc(args)

        if args.command == "modules":
            rows = [
                {
                    "name": module.name,
                    "description": module.description,
                    "supported_target_types": module.supported_target_types,
                    "safe_by_default": module.safe_by_default,
                }
                for module in available_modules()
            ]
            print(json.dumps(make_json_safe(rows), indent=2))
            return 0

    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if getattr(args, "command", None) == "report":
            try:
                update_progress_file_phase(Path("."), "Report generation", PHASE_FAILED, ensure_text(exc))
            except Exception:
                pass
        if getattr(args, "debug", False):
            traceback.print_exc()
        else:
            print(f"PortWise error: {ensure_text(exc)}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


def _print_scan_summary(run, state: dict) -> None:
    from dataclasses import asdict
    from portwise.intelligence.aggregation import aggregate_ports, plaintext_summary, weak_crypto_summary, finding_overview

    run_dict = {
        "metadata": {"state": state},
        "findings": [asdict(f) for f in run.findings],
    }
    overview = finding_overview(run_dict)
    ports = aggregate_ports(run_dict)
    plaintext = plaintext_summary(run_dict)
    weak = weak_crypto_summary(run_dict)

    print()
    print("PortWise scan complete")
    print(f"  Targets: {len(state.get('targets_loaded', []))}   "
          f"Live hosts: {len(state.get('live_hosts', []))}   "
          f"Services: {sum(len(v) for v in state.get('services_by_host', {}).values())}")
    print(f"  Findings: {overview['total']} total, {overview['actionable']} actionable "
          f"(Confirmed/Likely + medium or higher)")

    if ports:
        print()
        print("  Top open ports:")
        for g in ports[:8]:
            print(f"    {g.protocol}/{g.port:<5} {g.label[:16]:<16} {g.count} host(s)")

    if plaintext:
        print()
        print("  Cleartext exposure:")
        for b in plaintext[:6]:
            print(f"    [{b['severity']:>6}] {b['protocol']:<12} {b['host_count']} endpoint(s)")

    if weak:
        print()
        print("  Weak crypto / hardening:")
        for b in weak[:6]:
            print(f"    [{b['severity']:>6}] {b['title']} ({b['host_count']} host(s))")

    print()
    print("  Next: portwise summary   |   portwise ports --port 22 --hosts   |   runs/latest.json")
    print()


def _export_evidence_transcripts(
    report: dict,
    evidence_dir: Path,
    written: list[str],
    errors: list[str],
) -> None:
    """Write per-finding sanitized evidence transcripts to evidence_dir."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for finding in report.get("findings", []):
        fid = finding.get("id", "unknown")
        for ev in (finding.get("evidence") or []):
            transcript = (ev.get("data") or {}).get("transcript") if isinstance(ev, dict) else None
            if not transcript:
                continue
            out_path = evidence_dir / f"{fid}.txt"
            try:
                req = transcript.get("request", {})
                resp = transcript.get("response", {})
                lines = [
                    f"Finding: {finding.get('title', '')}",
                    f"Asset: {finding.get('asset', '')}:{finding.get('port', '')}",
                    f"Observed: {transcript.get('observed_at', '')}",
                    f"Timing: {transcript.get('timing_ms', '')}ms",
                    "",
                    "--- REQUEST ---",
                    f"{req.get('method', 'GET')} {req.get('url', '')}",
                ]
                for k, v in (req.get("headers") or {}).items():
                    lines.append(f"{k}: {v}")
                if req.get("body_sent"):
                    lines += ["", req["body_sent"]]
                lines += ["", "--- RESPONSE ---", f"HTTP {resp.get('status', '')} {resp.get('reason', '')}"]
                for k, v in (resp.get("headers") or {}).items():
                    lines.append(f"{k}: {v}")
                if resp.get("body_excerpt"):
                    lines += ["", resp["body_excerpt"]]
                out_path.write_text("\n".join(lines), encoding="utf-8")
                written.append(str(out_path))
            except Exception as exc:
                errors.append(f"evidence-export:{fid}: {ensure_text(exc)}")
            break  # one transcript file per finding


def _load_run_dict(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Run file not found: {path}. Run a scan/analyze first, or pass --run.")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _cmd_ports(args) -> int:
    from portwise.intelligence.aggregation import aggregate_ports, filter_ports

    run = _load_run_dict(args.run)
    groups = aggregate_ports(run)
    groups = filter_ports(
        groups,
        port=args.port,
        protocol=args.protocol,
        service=args.service,
        min_count=args.min_count,
    )
    if args.json:
        print(json.dumps([g.to_dict() for g in groups], indent=2))
        return 0

    if not groups:
        print("No open ports matched the filter.")
        return 0

    total_hosts = len({h for g in groups for h in g.hosts})
    print()
    print(f"Open-port rollup  ({len(groups)} distinct port/proto, {total_hosts} host(s))")
    print(f"{'PROTO':<5}  {'PORT':>5}  {'SERVICE':<14}  {'HOSTS':>5}")
    print("-" * 40)
    for g in groups:
        print(f"{g.protocol:<5}  {g.port:>5}  {g.label[:14]:<14}  {g.count:>5}")
        if args.hosts:
            for host in g.hosts:
                print(f"        - {host}")
    print()
    return 0


def _cmd_summary(args) -> int:
    from portwise.intelligence.aggregation import (
        aggregate_ports,
        finding_overview,
        plaintext_summary,
        weak_crypto_summary,
    )

    run = _load_run_dict(args.run)
    ports = aggregate_ports(run)
    plaintext = plaintext_summary(run)
    weak = weak_crypto_summary(run)
    overview = finding_overview(run)

    if args.json:
        print(json.dumps({
            "overview": overview,
            "top_ports": [g.to_dict() for g in ports[:15]],
            "cleartext_exposure": plaintext,
            "weak_crypto": weak,
        }, indent=2, default=str))
        return 0

    print()
    print("=== PortWise Summary ===")
    print(f"Findings: {overview['total']} total | {overview['actionable']} actionable (Confirmed/Likely, med+).")
    if overview["by_severity"]:
        sev = overview["by_severity"]
        order = ["critical", "high", "medium", "low", "informational"]
        line = "  ".join(f"{s}:{sev[s]}" for s in order if s in sev)
        print(f"Severity: {line}")

    print()
    print("Top open ports:")
    if not ports:
        print("  (none)")
    for g in ports[:12]:
        print(f"  {g.protocol}/{g.port:<5} {g.label[:16]:<16} {g.count} host(s)")

    print()
    print("Cleartext / plaintext exposure:")
    if not plaintext:
        print("  (none detected)")
    for b in plaintext:
        ports_txt = ",".join(str(p) for p in b["ports"])
        print(f"  [{b['severity']:>6}] {b['protocol']:<14} {b['host_count']} endpoint(s)  ports: {ports_txt}")

    print()
    print("Weak crypto / hardening highlights:")
    if not weak:
        print("  (none detected)")
    for b in weak[:15]:
        print(f"  [{b['severity']:>6}] {b['title']}  ({b['host_count']} host(s), {b['confidence']})")
    print()
    return 0


def _cmd_handoff(args) -> int:
    from portwise.intelligence.handoff import build_handoff, render_script

    run = _load_run_dict(args.run)
    items = build_handoff(run)
    if args.category:
        items = [it for it in items if it.category == args.category]

    if args.json:
        print(json.dumps([it.to_dict() for it in items], indent=2))
        return 0

    if not items:
        print("No handoff commands generated (no actionable findings matched).")
        return 0

    if args.out:
        args.out.write_text(render_script(items), encoding="utf-8")
        print(f"Wrote {len(items)} command group(s) to {args.out}")
        print("Review every line and confirm scope before running. PortWise ran none of these.")
        return 0

    by_cat: dict[str, list] = {}
    for it in items:
        by_cat.setdefault(it.category, []).append(it)
    print()
    print("PortWise handoff — SUGGESTED commands (PortWise ran none of these; confirm scope first)")
    for cat in sorted(by_cat):
        print()
        print(f"== {cat} ==")
        for it in by_cat[cat]:
            tag = "  [credential attack — authorization required]" if it.requires_auth_note else ""
            print(f"  # {it.target}: {it.rationale}{tag}")
            for cmd in it.commands:
                print(f"  {cmd}")
    print()
    return 0


def _cmd_poc(args) -> int:
    from portwise.intelligence.poc import build_poc_items, write_poc_artifacts

    run = _load_run_dict(args.run)
    items = build_poc_items(run, min_severity=args.min_severity)
    if not items:
        print("No findings with reproducible POC commands matched.")
        return 0
    index = write_poc_artifacts(items, args.out, capture=args.capture)
    captured = sum(1 for it in items if it.captured_output)
    print(f"Wrote {len(items)} POC file(s) to {args.out}")
    if args.capture:
        print(f"Captured live output for {captured}/{len(items)} (tools available + read-only).")
    else:
        print("Run with --capture to execute the safe read-only commands and save their output.")
    print(f"Index: {index}")
    return 0


def _print_status(workspace: Path) -> None:
    progress = load_progress(workspace)
    latest = workspace / "runs" / "latest.json"
    if not progress:
        print(f"No progress file found at {workspace / 'runs' / 'progress.json'}")
        if latest.exists():
            print(f"Latest run exists: {latest}")
        return
    print(f"Run ID: {progress.get('run_id')}")
    print(f"Profile: {progress.get('profile')}")
    print(f"Workspace: {progress.get('workspace')}")
    print(f"Current phase: {progress.get('current_phase')}")
    print(f"Elapsed seconds: {progress.get('elapsed_seconds')}")
    print()
    print("Phases:")
    for phase in progress.get("phases", []):
        status = phase.get("status")
        name = phase.get("name")
        elapsed = phase.get("elapsed_seconds", 0)
        message = phase.get("message", "")
        print(f"- {name}: {status} ({elapsed}s) {message}")
        if phase.get("error"):
            print(f"  error: {phase['error']}")
    print()
    counters = progress.get("counters", {})
    print("Counters:")
    for key, value in counters.items():
        print(f"- {key}: {value}")
    if latest.exists():
        try:
            data = json.loads(latest.read_text(encoding="utf-8"))
            generated = data.get("metadata", {}).get("state", {}).get("generated_files", [])
            if generated:
                print()
                print("Generated files:")
                for item in generated:
                    print(f"- {item}")
        except Exception:
            print(f"Latest run exists: {latest}")


if __name__ == "__main__":
    raise SystemExit(main())
