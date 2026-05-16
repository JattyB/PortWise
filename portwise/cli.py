from __future__ import annotations

import argparse
import json
import sys
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
from portwise.reporting.retest import write_retest_report
from portwise.scanners.nmap_parser import parse_nmap_xml
from portwise.utils.files import write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portwise",
        description="Safe, evidence-first VAPT intelligence and reporting.",
        epilog="Examples: portwise scan --targets targets.txt --profile full-vapt --config config.yaml --dry-run | portwise report --run runs/latest.json --format all",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
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
    scan_cmd.add_argument("--validation-level", choices=["safe", "proof", "controlled"], default="safe")
    scan_cmd.add_argument("--internet-facing", action="store_true")
    scan_cmd.add_argument("--timeout", type=int)
    scan_cmd.add_argument("--no-cve", action="store_true")
    scan_cmd.add_argument("--no-modules", action="store_true")
    scan_cmd.add_argument("--no-progress", action="store_true", help="Disable live progress output and only print the JSON command summary.")

    analyze_cmd = sub.add_parser("analyze", help="Analyze existing Nmap XML.")
    analyze_cmd.add_argument("--nmap", required=True, type=Path)
    analyze_cmd.add_argument("--profile", default="offline-analysis")
    analyze_cmd.add_argument("--config", type=Path, default=Path("config.yaml"))
    analyze_cmd.add_argument("--workspace", type=Path, default=Path("."))
    analyze_cmd.add_argument("--active-modules", action="store_true", help="Allow safe HTTP/TLS active checks during analysis.")
    analyze_cmd.add_argument("--testssl-json-dir", type=Path, help="Import recognizable testssl JSON findings as manual-validation evidence.")
    analyze_cmd.add_argument("--nessus-csv", type=Path, help="Import common Nessus CSV fields as non-confirmed findings.")
    analyze_cmd.add_argument("--no-cve", action="store_true")

    report_cmd = sub.add_parser("report", help="Generate report from a run JSON.")
    report_cmd.add_argument("--run", required=True, type=Path)
    report_cmd.add_argument("--format", choices=["json", "excel", "html", "all"], default="json")
    report_cmd.add_argument("--output", type=Path)

    retest_cmd = sub.add_parser("retest", help="Compare previous and current run JSON files.")
    retest_cmd.add_argument("--previous", required=True, type=Path)
    retest_cmd.add_argument("--current", required=True, type=Path)
    retest_cmd.add_argument("--format", choices=["json", "excel", "all"], default="json")
    retest_cmd.add_argument("--output-dir", type=Path, default=Path("reports"))

    status_cmd = sub.add_parser("status", help="Show current or last PortWise run progress.")
    status_cmd.add_argument("--workspace", type=Path, default=Path("."))

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
            config.scanner["validation_level"] = args.validation_level
            config.scanner["internet_facing"] = args.internet_facing
            config.scanner["udp_service_detection_on_open_filtered"] = args.udp_open_filtered
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
                print(json.dumps(summary, indent=2))
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
            if args.format in {"json", "all"}:
                default_json = output_dir / ("sample_report.json" if "examples" in str(args.run) else "PortWise_Report.json")
                output = args.output if args.format == "json" and args.output else default_json
                write_json(output, report)
                written.append(str(output))
            if args.format in {"excel", "all"}:
                output = args.output if args.format == "excel" and args.output else output_dir / "PortWise_Report.xlsx"
                write_excel_report(report, output)
                written.append(str(output))
            if args.format in {"html", "all"}:
                output = args.output if args.format == "html" and args.output else output_dir / "PortWise_Report.html"
                write_html_report(report, output)
                written.append(str(output))
            update_progress_file_phase(Path("."), "Report generation", PHASE_DONE, f"Wrote {len(written)} report file(s)")
            print(json.dumps({"written": written}, indent=2))
            return 0

        if args.command == "retest":
            written = write_retest_report(args.previous, args.current, args.output_dir, args.format)
            print(json.dumps({"written": [str(path) for path in written]}, indent=2))
            return 0

        if args.command == "status":
            _print_status(args.workspace)
            return 0

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
            print(json.dumps(rows, indent=2))
            return 0

    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if getattr(args, "command", None) == "report":
            try:
                update_progress_file_phase(Path("."), "Report generation", PHASE_FAILED, str(exc))
            except Exception:
                pass
        print(f"PortWise error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


def _print_scan_summary(run, state: dict) -> None:
    findings = run.findings
    confirmed = sum(1 for finding in findings if str(finding.confidence) == "Confirmed" or getattr(finding.confidence, "value", "") == "Confirmed")
    needs_validation = sum(1 for finding in findings if getattr(finding, "manual_validation", False) or getattr(finding.confidence, "value", "") == "Needs Manual Validation")
    false_positive = sum(1 for finding in findings if getattr(finding.confidence, "value", "") == "False Positive Candidate")
    print()
    print("PortWise scan completed")
    print()
    print(f"Targets loaded: {len(state.get('targets_loaded', []))}")
    print(f"Live hosts: {len(state.get('live_hosts', []))}")
    print(f"TCP open ports: {sum(len(v) for v in state.get('tcp_open_ports_by_host', {}).values())}")
    print(f"UDP open ports: {sum(len(v) for v in state.get('udp_open_ports_by_host', {}).values())}")
    print(f"Services discovered: {sum(len(v) for v in state.get('services_by_host', {}).values())}")
    print(f"Findings: {len(findings)}")
    print(f"Confirmed: {confirmed}")
    print(f"Needs validation: {needs_validation}")
    print(f"False positive candidates: {false_positive}")
    print()
    print("Reports:")
    print("- runs/latest.json")
    print("- reports/PortWise_Report.html")
    print("- reports/PortWise_Report.xlsx")
    print()
    print("Next commands:")
    print("portwise report --run runs/latest.json --format all")
    print("portwise retest --previous runs/old.json --current runs/latest.json --format all")


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
