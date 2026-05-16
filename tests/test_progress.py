import json
from pathlib import Path

from portwise.cli import main
from portwise.core.config import load_config
from portwise.core.models import ModuleTarget
from portwise.core.module_runner import execute_safe_modules
from portwise.core.progress import PHASE_DONE, PHASE_RUNNING, ProgressTracker, default_scan_phases, load_progress, update_progress_file_phase
from portwise.core.runner import run_scan
from portwise.core.service_groups import group_hosts_by_ports


def test_progress_model_creation_and_phase_transitions(tmp_path: Path) -> None:
    tracker = ProgressTracker(workspace=tmp_path, profile="full-vapt", phases=["Target validation"], enabled=False)
    tracker.start_phase("Target validation", "loading targets")
    tracker.update_counters(targets_total=2)
    tracker.finish_phase("Target validation", status=PHASE_DONE, message="loaded")

    data = load_progress(tmp_path)

    assert data is not None
    assert data["profile"] == "full-vapt"
    assert data["phases"][0]["status"] == PHASE_DONE
    assert data["counters"]["targets_total"] == 2


def test_progress_file_update_for_report_phase(tmp_path: Path) -> None:
    ProgressTracker(workspace=tmp_path, profile="full-vapt", phases=["Report generation"], enabled=False)
    update_progress_file_phase(tmp_path, "Report generation", PHASE_RUNNING, "writing")
    update_progress_file_phase(tmp_path, "Report generation", PHASE_DONE, "done")

    data = json.loads((tmp_path / "runs" / "progress.json").read_text(encoding="utf-8"))

    assert data["phases"][0]["status"] == PHASE_DONE
    assert data["phases"][0]["message"] == "done"


def test_group_progress_updates_with_mocked_groups(tmp_path: Path) -> None:
    groups = group_hosts_by_ports({"192.0.2.1": [80, 443], "192.0.2.2": [80, 443]}, "tcp")
    tracker = ProgressTracker(workspace=tmp_path, profile="full-vapt", phases=["Grouped TCP service detection"], enabled=False)
    tracker.start_phase("Grouped TCP service detection", "groups", progress_total=len(groups))
    for index, group in enumerate(groups, start=1):
        tracker.update_phase("Grouped TCP service detection", current=index, total=len(groups), message=f"{group.group_id}")
    tracker.finish_phase("Grouped TCP service detection")

    data = load_progress(tmp_path)

    assert data["phases"][0]["progress_current"] == 1
    assert data["phases"][0]["progress_total"] == 1


def test_module_progress_updates_with_mocked_module_run(tmp_path: Path) -> None:
    tracker = ProgressTracker(workspace=tmp_path, profile="full-vapt", phases=["Module execution"], enabled=False)
    tracker.start_phase("Module execution", "modules")

    routes = {
        "ssh_targets": [
            ModuleTarget(host="192.0.2.10", port=22, protocol="tcp", service="ssh", product="OpenSSH")
        ]
    }
    execute_safe_modules(
        routes,
        config={"context": "external"},
        enabled_modules={"ssh": True},
        dry_run=True,
        progress_callback=lambda module, current, total, findings, completed, overall: tracker.update_phase(
            "Module execution",
            current=completed,
            total=overall,
            message=f"{module}: {current}/{total}",
        ),
    )

    data = load_progress(tmp_path)

    assert data["phases"][0]["progress_current"] == 1
    assert data["phases"][0]["progress_total"] == 1


def test_no_progress_does_not_break_scan_flow(tmp_path: Path) -> None:
    _write_minimal_config(tmp_path / "config.yaml")
    targets = tmp_path / "targets.txt"
    targets.write_text("192.0.2.10\n", encoding="utf-8")
    config = load_config(tmp_path / "config.yaml")

    run = run_scan(tmp_path, config, config.get_profile("full-vapt"), targets, dry_run=True, no_modules=True, no_cve=True, progress=None)

    assert run.commands
    assert not (tmp_path / "runs" / "progress.json").exists()


def test_dry_run_progress_output_includes_planned_phases(tmp_path: Path, capsys) -> None:
    _write_minimal_config(tmp_path / "config.yaml")
    targets = tmp_path / "targets.txt"
    targets.write_text("192.0.2.10\n", encoding="utf-8")

    exit_code = main([
        "scan",
        "--targets",
        str(targets),
        "--profile",
        "full-vapt",
        "--config",
        str(tmp_path / "config.yaml"),
        "--workspace",
        str(tmp_path),
        "--dry-run",
    ])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Target validation" in output
    assert "Host discovery" in output
    assert (tmp_path / "runs" / "progress.json").exists()


def test_status_command_reads_progress(tmp_path: Path, capsys) -> None:
    tracker = ProgressTracker(workspace=tmp_path, profile="full-vapt", phases=default_scan_phases(["discovery"]), enabled=False)
    tracker.start_phase("Target validation", "loading")
    tracker.finish_phase("Target validation")

    exit_code = main(["status", "--workspace", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Run ID:" in output
    assert "Target validation" in output


def _write_minimal_config(path: Path) -> None:
    path.write_text(
        """
project:
  name: Test
scanner:
  nmap_timeout_seconds: 30
progress:
  enabled: true
profiles:
  full-vapt:
    context: unknown
    nmap_steps:
      - discovery
    modules:
      exposure: true
      cve_enrichment: false
    reports:
      - json
""",
        encoding="utf-8",
    )
