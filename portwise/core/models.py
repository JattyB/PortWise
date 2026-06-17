from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Confidence(StrEnum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    POSSIBLE = "Possible"
    INFORMATIONAL = "Informational"
    NEEDS_MANUAL_VALIDATION = "Needs Manual Validation"
    FALSE_POSITIVE_CANDIDATE = "False Positive Candidate"


class FindingCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    BEST_PRACTICE = "best_practice"
    INFORMATION = "information"
    HYGIENE = "hygiene"


@dataclass(slots=True)
class Evidence:
    source: str
    description: str
    strength: int
    data: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        self.strength = max(1, min(5, int(self.strength)))

    @classmethod
    def with_transcript(
        cls,
        source: str,
        description: str,
        strength: int,
        method: str,
        url: str,
        request_headers: dict[str, str],
        response_status: int,
        response_headers: dict[str, str] | list[tuple[str, str]],
        response_body: str | bytes,
        timing_ms: int,
        observed_at: str | None = None,
        request_body: str | bytes | None = None,
        body_cap: int = 2048,
    ) -> "Evidence":
        from portwise.utils.sanitize import build_transcript
        from datetime import datetime, timezone
        ts = observed_at or datetime.now(timezone.utc).isoformat()
        transcript = build_transcript(
            method=method,
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_reason="",
            response_headers=response_headers,
            response_body=response_body,
            timing_ms=timing_ms,
            observed_at=ts,
            body_cap=body_cap,
        )
        return cls(source=source, description=description, strength=strength, data={"transcript": transcript})


@dataclass(slots=True)
class Finding:
    title: str
    severity: Severity
    asset: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    description: str = ""
    recommendation: str = ""
    confidence: Confidence = Confidence.POSSIBLE
    evidence_strength: int = 1
    status: str = "open"
    type: str = "validation"
    module: str | None = None
    priority: str = "P5"
    false_positive_risk: str = "medium"
    manual_validation: bool = False
    cve_id: str | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    kev: bool = False
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    category: str = FindingCategory.VULNERABILITY
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)
    run_id: str | None = None

    @property
    def finding_type(self) -> str:
        return self.type

    def add_evidence(self, item: Evidence) -> None:
        self.evidence.append(item)
        self.evidence_strength = max(self.evidence_strength, item.strength)


@dataclass(slots=True)
class Service:
    host: str
    port: int
    protocol: str
    state: str
    service_name: str = ""
    hostname: str | None = None
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: list[str] = field(default_factory=list)
    reason: str = ""
    scripts: dict[str, Any] = field(default_factory=dict)
    confidence: int | None = None
    method: str | None = None
    tunnel: str | None = None
    source_file: str | None = None

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"

    def script_text(self, script_id: str) -> str:
        entry = self.scripts.get(script_id)
        if isinstance(entry, dict):
            return entry.get("output", "")
        return str(entry) if entry is not None else ""

    def script_data(self, script_id: str) -> dict | list | None:
        entry = self.scripts.get(script_id)
        if isinstance(entry, dict):
            return entry.get("data")
        return None


@dataclass(slots=True)
class Asset:
    ip: str
    status: str = "unknown"
    ipv4: str | None = None
    ipv6: str | None = None
    hostnames: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)

    def add_service(self, service: Service) -> None:
        self.services.append(service)


@dataclass(slots=True)
class CommandResult:
    name: str
    command: list[str]
    started_at: str
    finished_at: str | None = None
    return_code: int | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    skipped: bool = False
    dry_run: bool = False
    error: str | None = None
    warning: str | None = None


@dataclass(slots=True)
class RunResult:
    project: str
    profile: str
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    skipped_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    commands: list[CommandResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def finish(self) -> None:
        self.finished_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ModuleTarget:
    host: str
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""
    cpe: list[str] = field(default_factory=list)
    confidence: int | None = None
    routing_reason: str = ""
    scripts: dict[str, Any] = field(default_factory=dict)
    hostname: str | None = None


@dataclass(slots=True)
class RunState:
    project: str
    profile: str
    targets_loaded: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    dead_hosts: list[str] = field(default_factory=list)
    tcp_open_ports_by_host: dict[str, list[int]] = field(default_factory=dict)
    udp_open_ports_by_host: dict[str, list[int]] = field(default_factory=dict)
    udp_open_filtered_ports_by_host: dict[str, list[int]] = field(default_factory=dict)
    services_by_host: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    module_targets: dict[str, list[ModuleTarget]] = field(default_factory=dict)
    tcp_service_detection_groups: list[dict[str, Any]] = field(default_factory=list)
    udp_service_detection_groups: list[dict[str, Any]] = field(default_factory=list)
    module_runs: list[dict[str, Any]] = field(default_factory=list)
    module_errors: list[str] = field(default_factory=list)
    findings_by_module: dict[str, int] = field(default_factory=dict)
    evidence_by_module: dict[str, int] = field(default_factory=dict)
    commands_executed: list[CommandResult] = field(default_factory=list)
    failed_phases: list[str] = field(default_factory=list)
    skipped_phases: list[str] = field(default_factory=list)
    generated_files: list[str] = field(default_factory=list)
    updated_at: str = field(default_factory=utc_now)

    def touch(self) -> None:
        self.updated_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
