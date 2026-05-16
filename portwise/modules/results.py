from __future__ import annotations

from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any

from portwise.core.models import Evidence, Finding


@dataclass(slots=True)
class ModuleResult:
    module_name: str
    target: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    skipped_reason: str | None = None
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModuleTimer:
    def __enter__(self) -> "ModuleTimer":
        self.started = perf_counter()
        return self

    def __exit__(self, *_: object) -> None:
        self.duration = perf_counter() - self.started

    duration: float
