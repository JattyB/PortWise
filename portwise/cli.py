from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from portwise import __version__
from portwise.core.config import ConfigError, load_config
from portwise.core.logging import configure_logging
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
            run = run_scan(args.workspace, config, profile, args.targets, dry_run=dry_run, no_modules=args.no_modules, no_cve=args.no_cve, internet_facing=args.internet_facing)
            state = run.metadata.get("state", {})
            print(json.dumps({
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
            }, indent=2))
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
            print(json.dumps({"written": written}, indent=2))
            return 0

        if args.command == "retest":
            written = write_retest_report(args.previous, args.current, args.output_dir, args.format)
            print(json.dumps({"written": [str(path) for path in written]}, indent=2))
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
        print(f"PortWise error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
