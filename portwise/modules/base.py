from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from portwise.modules.results import ModuleResult, ModuleTimer


class PortWiseModule(ABC):
    name: str = "base"
    description: str = ""
    supported_target_types: tuple[str, ...] = ()
    read_only: bool = True
    timeout: float = 5.0

    def execute(self, target: dict[str, Any], config: dict[str, Any] | None = None) -> ModuleResult:
        config = config or {}
        result = ModuleResult(module_name=self.name, target=target)
        try:
            with ModuleTimer() as timer:
                output = self.run(target, config)
            result.duration = round(timer.duration, 4)
            result.findings = output.findings
            result.evidence = output.evidence
            result.skipped_reason = output.skipped_reason
            result.errors = output.errors
        except Exception as exc:
            result.errors.append(str(exc))
        return result

    @abstractmethod
    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        ...
