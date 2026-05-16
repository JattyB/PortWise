from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from portwise.core.models import utc_now
from portwise.utils.files import ensure_dir


PHASE_PENDING = "pending"
PHASE_RUNNING = "running"
PHASE_DONE = "done"
PHASE_FAILED = "failed"
PHASE_SKIPPED = "skipped"


@dataclass(slots=True)
class ProgressPhase:
    name: str
    status: str = PHASE_PENDING
    started_at: str | None = None
    ended_at: str | None = None
    elapsed_seconds: float = 0.0
    progress_current: int = 0
    progress_total: int = 0
    message: str = ""
    command: list[str] = field(default_factory=list)
    output_file: str | None = None
    error: str | None = None


@dataclass(slots=True)
class ProgressState:
    run_id: str
    profile: str
    workspace: str
    started_at: str
    updated_at: str
    elapsed_seconds: float = 0.0
    total_phases: int = 0
    current_phase: str = ""
    phases: list[ProgressPhase] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=lambda: {
        "targets_total": 0,
        "live_hosts": 0,
        "dead_hosts": 0,
        "tcp_ports_found": 0,
        "udp_ports_found": 0,
        "services_found": 0,
        "findings_found": 0,
        "modules_completed": 0,
        "modules_total": 0,
    })

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProgressTracker:
    def __init__(
        self,
        *,
        workspace: Path,
        profile: str,
        phases: list[str],
        enabled: bool = True,
        show_current_command: bool = True,
    ) -> None:
        self.workspace = workspace
        self.path = workspace / "runs" / "progress.json"
        self.enabled = enabled
        self.show_current_command = show_current_command
        started = utc_now()
        self._start_monotonic = time.monotonic()
        self._phase_starts: dict[str, float] = {}
        self.state = ProgressState(
            run_id=str(uuid4()),
            profile=profile,
            workspace=str(workspace),
            started_at=started,
            updated_at=started,
            total_phases=len(phases),
            phases=[ProgressPhase(name=name) for name in phases],
        )
        self.console = None
        if enabled:
            try:
                from rich.console import Console

                self.console = Console()
            except Exception:
                self.console = None
        self.save()

    def set_counter(self, name: str, value: int) -> None:
        self.state.counters[name] = int(value)
        self.save()

    def update_counters(self, **values: int) -> None:
        for key, value in values.items():
            self.state.counters[key] = int(value)
        self.save()

    def start_phase(self, name: str, message: str = "", command: list[str] | None = None, output_file: str | None = None, progress_total: int = 0) -> None:
        phase = self._phase(name)
        phase.status = PHASE_RUNNING
        phase.started_at = phase.started_at or utc_now()
        self._phase_starts[name] = time.monotonic()
        phase.ended_at = None
        phase.message = message
        phase.command = command or []
        phase.output_file = output_file
        phase.progress_total = progress_total
        self.state.current_phase = name
        self.emit(f"[{self._phase_index(name)}/{self.state.total_phases}] {name}: {message or 'running'}", command=phase.command)
        self.save()

    def update_phase(self, name: str, *, current: int | None = None, total: int | None = None, message: str | None = None) -> None:
        phase = self._phase(name)
        if current is not None:
            phase.progress_current = current
        if total is not None:
            phase.progress_total = total
        if message is not None:
            phase.message = message
        self.emit(f"{name}: {phase.progress_current}/{phase.progress_total} {phase.message}".strip())
        self.save()

    def finish_phase(self, name: str, status: str = PHASE_DONE, message: str = "", error: str | None = None) -> None:
        phase = self._phase(name)
        phase.status = status
        phase.ended_at = utc_now()
        phase.error = error
        if message:
            phase.message = message
        if phase.started_at:
            phase.elapsed_seconds = round(max(0.0, time.monotonic() - self._phase_starts.get(name, time.monotonic())), 2)
        self.state.current_phase = name
        marker = "done" if status == PHASE_DONE else status
        self.emit(f"{name}: {marker}{' - ' + phase.message if phase.message else ''}")
        self.save()

    def skip_phase(self, name: str, reason: str) -> None:
        self.finish_phase(name, status=PHASE_SKIPPED, message=reason)

    def fail_phase(self, name: str, error: str) -> None:
        self.finish_phase(name, status=PHASE_FAILED, message=error, error=error)

    def emit(self, message: str, command: list[str] | None = None) -> None:
        if not self.enabled:
            return
        if self.console:
            self.console.print(f"[cyan]PortWise[/cyan] {message}")
            if command and self.show_current_command:
                self.console.print(f"[dim]{' '.join(command)}[/dim]")
        else:
            print(f"PortWise {message}")
            if command and self.show_current_command:
                print(" ".join(command))

    def save(self) -> None:
        self.state.updated_at = utc_now()
        self.state.elapsed_seconds = round(time.monotonic() - self._start_monotonic, 2)
        ensure_dir(self.path.parent)
        self.path.write_text(json.dumps(self.state.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _phase(self, name: str) -> ProgressPhase:
        for phase in self.state.phases:
            if phase.name == name:
                return phase
        phase = ProgressPhase(name=name)
        self.state.phases.append(phase)
        self.state.total_phases = len(self.state.phases)
        return phase

    def _phase_index(self, name: str) -> int:
        for index, phase in enumerate(self.state.phases, start=1):
            if phase.name == name:
                return index
        return len(self.state.phases)


def default_scan_phases(profile_steps: list[str]) -> list[str]:
    names = ["Target validation"]
    labels = {
        "discovery": "Host discovery",
        "tcp_top_1000": "TCP top 1000 scan",
        "tcp_full": "TCP full scan",
        "tcp_services": "Grouped TCP service detection",
        "udp_top_1000": "UDP top 1000 scan",
        "udp_services": "Grouped UDP service detection",
    }
    names.extend(labels.get(step, step) for step in profile_steps)
    names.extend(["Module routing", "Module execution", "CVE enrichment", "Report generation"])
    return names


def load_progress(workspace: Path) -> dict[str, Any] | None:
    path = workspace / "runs" / "progress.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def update_progress_file_phase(workspace: Path, name: str, status: str, message: str = "") -> None:
    path = workspace / "runs" / "progress.json"
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    phases = data.setdefault("phases", [])
    phase = next((item for item in phases if item.get("name") == name), None)
    if phase is None:
        phase = {"name": name}
        phases.append(phase)
    now = utc_now()
    phase["status"] = status
    phase["message"] = message
    if status == PHASE_RUNNING:
        phase["started_at"] = phase.get("started_at") or now
        data["current_phase"] = name
    if status in {PHASE_DONE, PHASE_FAILED, PHASE_SKIPPED}:
        phase["ended_at"] = now
    data["updated_at"] = now
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
