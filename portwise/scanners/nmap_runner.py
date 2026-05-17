from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
from pathlib import Path

from portwise.core.models import CommandResult, utc_now
from portwise.core.service_groups import ServiceDetectionGroup, ports_to_arg
from portwise.utils.files import ensure_dir, ensure_text


NMAP_TEMPLATES: dict[str, list[str]] = {
    "discovery": [
        "nmap", "-sn", "-PE", "-PS22,80,443,445,3389", "-PA80,443,445",
        "--reason", "-iL", "{targets}", "-oA", "{scans}/01_discovery",
    ],
    "tcp_top_1000": [
        "nmap", "-sS", "--top-ports", "1000", "-T3", "--max-retries", "3",
        "--max-rtt-timeout", "2s", "--host-timeout", "10m", "--reason",
        "-iL", "{live_hosts}", "-oA", "{scans}/02_tcp_top_1000",
    ],
    "tcp_full": [
        "nmap", "-sS", "-p-", "-T3", "--min-rate", "500", "--max-retries", "3",
        "--max-rtt-timeout", "2s", "--host-timeout", "20m", "--reason",
        "-iL", "{live_hosts}", "-oA", "{scans}/03_tcp_full",
    ],
    "tcp_services": [
        "nmap", "-sV", "--version-light", "-sC", "--reason", "-p",
        "{open_tcp_ports}", "-iL", "{live_hosts}", "-oA", "{scans}/04_tcp_services",
    ],
    "udp_top_1000": [
        "nmap", "-sU", "--top-ports", "1000", "-T3", "--max-retries", "2",
        "--max-rtt-timeout", "3s", "--host-timeout", "30m", "--reason",
        "-iL", "{live_hosts}", "-oA", "{scans}/06_udp_top_1000",
    ],
    "udp_services": [
        "nmap", "-sU", "-sV", "--version-light", "--reason", "-p",
        "{open_udp_ports}", "-iL", "{live_hosts}", "-oA", "{scans}/07_udp_services",
    ],
}


def has_admin_privileges() -> bool:
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


class NmapRunner:
    def __init__(self, workspace: Path, timeout_seconds: int = 1800) -> None:
        self.workspace = workspace
        self.timeout_seconds = timeout_seconds
        self.scans_dir = ensure_dir(workspace / "scans")
        self.logs_dir = ensure_dir(workspace / "logs")
        self.command_logs_dir = ensure_dir(self.logs_dir / "commands")

    @staticmethod
    def nmap_available() -> bool:
        return shutil.which("nmap") is not None

    def build_command(
        self,
        step: str,
        targets_file: Path,
        live_hosts_file: Path | None = None,
        open_tcp_ports: str = "T:1-65535",
        open_udp_ports: str = "U:53,67,68,69,123,137,161,500,514,520,1900,4500",
    ) -> tuple[list[str], str | None]:
        if step not in NMAP_TEMPLATES:
            raise ValueError(f"Unknown nmap step: {step}")

        replacements = {
            "targets": str(targets_file),
            "live_hosts": str(live_hosts_file or targets_file),
            "open_tcp_ports": open_tcp_ports,
            "open_udp_ports": open_udp_ports,
            "scans": str(self.scans_dir),
        }
        command = [part.format(**replacements) for part in NMAP_TEMPLATES[step]]
        warning = None
        if "-sS" in command and not has_admin_privileges():
            command = ["-sT" if part == "-sS" else part for part in command]
            warning = "SYN scan requires admin/root privileges; falling back to TCP connect scan (-sT)."
        return command, warning

    def run_step(
        self,
        step: str,
        targets_file: Path,
        dry_run: bool = True,
        live_hosts_file: Path | None = None,
        open_tcp_ports: str = "T:1-65535",
        open_udp_ports: str = "U:53,67,68,69,123,137,161,500,514,520,1900,4500",
    ) -> CommandResult:
        command, warning = self.build_command(step, targets_file, live_hosts_file, open_tcp_ports, open_udp_ports)
        result = CommandResult(name=step, command=command, started_at=utc_now(), dry_run=dry_run, warning=warning)

        stdout_path = self.command_logs_dir / f"{step}.stdout.log"
        stderr_path = self.command_logs_dir / f"{step}.stderr.log"
        result.stdout_path = str(stdout_path)
        result.stderr_path = str(stderr_path)

        if dry_run:
            result.skipped = True
            result.finished_at = utc_now()
            return result

        if not self.nmap_available():
            result.skipped = True
            result.error = "nmap was not found in PATH."
            result.finished_at = utc_now()
            return result

        try:
            completed = subprocess.run(
                command,
                cwd=self.workspace,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )
            stdout = ensure_text(completed.stdout)
            stderr = ensure_text(completed.stderr)
            _write_command_log(stdout_path, stdout)
            _write_command_log(stderr_path, stderr)
            result.return_code = completed.returncode
            if completed.returncode != 0:
                result.error = _format_command_error(f"nmap exited with return code {completed.returncode}.", stderr, stdout)
        except subprocess.TimeoutExpired as exc:
            _write_command_log(stdout_path, ensure_text(exc.stdout))
            _write_command_log(stderr_path, ensure_text(exc.stderr))
            result.error = _format_command_error(f"nmap timed out after {self.timeout_seconds} seconds.", ensure_text(exc.stderr), ensure_text(exc.stdout))
        except OSError as exc:
            result.error = ensure_text(exc)
        finally:
            result.finished_at = utc_now()
        return result

    def build_service_detection_command(self, protocol: str, group: ServiceDetectionGroup) -> list[str]:
        if not group.hosts_file:
            raise ValueError("Service detection group host file has not been prepared.")
        output_prefix = self.scans_dir / (
            f"04_tcp_services_{group.group_id}" if protocol == "tcp" else f"07_udp_services_{group.group_id}"
        )
        group.output_prefix = str(output_prefix)
        group.parsed_xml_file = f"{output_prefix}.xml"
        base = ["nmap"]
        if protocol == "udp":
            base.append("-sU")
        base.extend([
            "-sV",
            "--version-light",
        ])
        if protocol == "tcp":
            base.append("-sC")
        base.extend([
            "--reason",
            "-p",
            ports_to_arg(group.ports),
            "-iL",
            group.hosts_file,
            "-oA",
            str(output_prefix),
        ])
        group.command = base
        return base

    def run_command(self, name: str, command: list[str], dry_run: bool = True) -> CommandResult:
        result = CommandResult(name=name, command=command, started_at=utc_now(), dry_run=dry_run)
        stdout_path = self.command_logs_dir / f"{name}.stdout.log"
        stderr_path = self.command_logs_dir / f"{name}.stderr.log"
        result.stdout_path = str(stdout_path)
        result.stderr_path = str(stderr_path)

        if dry_run:
            result.skipped = True
            result.finished_at = utc_now()
            return result

        if not self.nmap_available():
            result.skipped = True
            result.error = "nmap was not found in PATH."
            result.finished_at = utc_now()
            return result

        try:
            completed = subprocess.run(
                command,
                cwd=self.workspace,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )
            stdout = ensure_text(completed.stdout)
            stderr = ensure_text(completed.stderr)
            _write_command_log(stdout_path, stdout)
            _write_command_log(stderr_path, stderr)
            result.return_code = completed.returncode
            if completed.returncode != 0:
                result.error = _format_command_error(f"nmap exited with return code {completed.returncode}.", stderr, stdout)
        except subprocess.TimeoutExpired as exc:
            _write_command_log(stdout_path, ensure_text(exc.stdout))
            _write_command_log(stderr_path, ensure_text(exc.stderr))
            result.error = _format_command_error(f"nmap timed out after {self.timeout_seconds} seconds.", ensure_text(exc.stderr), ensure_text(exc.stdout))
        except OSError as exc:
            result.error = ensure_text(exc)
        finally:
            result.finished_at = utc_now()
        return result


def _write_command_log(path: Path, data: object) -> None:
    try:
        ensure_dir(path.parent)
        path.write_text(ensure_text(data), encoding="utf-8", errors="replace")
    except OSError:
        return


def _format_command_error(message: str, stderr: object = "", stdout: object = "") -> str:
    stderr_text = ensure_text(stderr)
    stdout_text = ensure_text(stdout)
    lines = [line for line in stderr_text.splitlines() if line.strip()]
    if not lines:
        lines = [line for line in stdout_text.splitlines() if line.strip()]
    tail = "\n".join(lines[-10:])
    return f"{message}\nLast output lines:\n{tail}" if tail else message
