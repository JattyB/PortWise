"""Shared adapter for optional external engines.

PortWise is the orchestration + correlation brain; heavy/fast-moving external
engines (nuclei, ffuf, testssl, masscan, searchsploit, ssh-audit) are *optional*
hands. Every external-binary integration goes through this adapter so behavior is uniform:

    detect-on-PATH  ->  run-with-timeout  ->  parse JSON  ->  graceful fallback

When the binary is absent (or the run fails/times out), the adapter never raises
into the pipeline: it returns a result flagged ``available=False`` / ``ran=False``
carrying a ``skipped_reason`` and, when supplied, the equivalent ``handoff_command``
the operator can run with their own tooling.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ExternalToolResult:
    """Outcome of an optional external-engine invocation."""

    tool: str
    available: bool = False
    ran: bool = False
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    parsed: Any = None
    records: list[Any] = field(default_factory=list)
    error: str | None = None
    skipped_reason: str | None = None
    handoff_command: str | None = None
    command: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when the engine ran and produced a usable (non-error) result."""
        return self.ran and self.error is None

    def note(self) -> str:
        """A short human-readable status line for skipped-checks / progress."""
        if self.ok:
            return f"{self.tool}: ran ({len(self.records)} record(s))"
        if not self.available:
            base = f"{self.tool}: not installed; skipped"
        elif self.error:
            base = f"{self.tool}: {self.error}"
        else:
            base = f"{self.tool}: {self.skipped_reason or 'skipped'}"
        if self.handoff_command:
            base += f" — handoff: {self.handoff_command}"
        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "available": self.available,
            "ran": self.ran,
            "returncode": self.returncode,
            "records": len(self.records),
            "error": self.error,
            "skipped_reason": self.skipped_reason,
            "handoff_command": self.handoff_command,
        }


class ExternalTool:
    """Detect-and-run wrapper around a single optional binary.

    Subclasses (or callers) provide the binary name; ``run`` / ``run_json`` build
    an :class:`ExternalToolResult` and never raise for the common failure modes
    (missing binary, timeout, non-zero exit, malformed JSON).
    """

    def __init__(
        self,
        name: str,
        *,
        binary: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.name = name
        self.binary = binary or name
        self.timeout = timeout

    # -- detection -------------------------------------------------------
    def resolve(self) -> str | None:
        """Absolute path to the binary on PATH, or None."""
        return shutil.which(self.binary)

    @property
    def available(self) -> bool:
        return self.resolve() is not None

    # -- execution -------------------------------------------------------
    def run(
        self,
        args: list[str],
        *,
        timeout: float | None = None,
        input_text: str | None = None,
        handoff_command: str | None = None,
    ) -> ExternalToolResult:
        """Run ``binary args`` with a timeout. Output is captured as text."""
        result = ExternalToolResult(tool=self.name, handoff_command=handoff_command)
        path = self.resolve()
        if not path:
            result.skipped_reason = f"{self.binary} not found on PATH"
            return result
        result.available = True
        command = [path, *args]
        result.command = command
        try:
            completed = subprocess.run(  # noqa: S603 - args are constructed by PortWise
                command,
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else self.timeout,
                input=input_text,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.error = f"timed out after {timeout if timeout is not None else self.timeout}s"
            return result
        except OSError as exc:
            result.error = f"failed to launch {self.binary}: {exc}"
            return result
        result.ran = True
        result.returncode = completed.returncode
        result.stdout = completed.stdout or ""
        result.stderr = completed.stderr or ""
        return result

    def run_json(
        self,
        args: list[str],
        *,
        jsonl: bool = False,
        timeout: float | None = None,
        input_text: str | None = None,
        handoff_command: str | None = None,
        stdout_path: str | None = None,
    ) -> ExternalToolResult:
        """Run the engine and parse its JSON output into ``records``.

        ``jsonl=True`` parses one JSON object per line (e.g. ``nuclei -jsonl``);
        otherwise a single JSON document (object or array) is parsed. When
        ``stdout_path`` is given, JSON is read from that file instead of stdout
        (for engines that only write JSON to a file, e.g. ``ffuf -of json -o``).
        """
        result = self.run(
            args,
            timeout=timeout,
            input_text=input_text,
            handoff_command=handoff_command,
        )
        if not result.ran:
            return result

        raw = result.stdout
        if stdout_path:
            try:
                with open(stdout_path, encoding="utf-8") as handle:
                    raw = handle.read()
            except OSError as exc:
                result.error = f"could not read JSON output {stdout_path}: {exc}"
                return result

        try:
            result.records = parse_json_output(raw, jsonl=jsonl)
            result.parsed = result.records
        except ValueError as exc:
            result.error = f"could not parse JSON output: {exc}"
        return result


def parse_json_output(raw: str, *, jsonl: bool = False) -> list[Any]:
    """Parse engine output into a list of records.

    - ``jsonl``: one JSON object per non-empty line.
    - otherwise: a single JSON document; a list stays a list, an object becomes a
      one-element list.
    Blank input yields an empty list (a clean "no results" outcome).
    """
    text = (raw or "").strip()
    if not text:
        return []
    if jsonl:
        records: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
        return records
    doc = json.loads(text)
    if isinstance(doc, list):
        return doc
    return [doc]
