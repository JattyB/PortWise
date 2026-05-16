from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any

from portwise.core.models import Finding, ModuleTarget
from portwise.intelligence.false_positive import apply_false_positive_rules
from portwise.intelligence.risk_scoring import assign_priority
from portwise.modules.registry import available_modules, module_targets_key
from portwise.modules.results import ModuleResult


def execute_safe_modules(
    routes: dict[str, list[ModuleTarget]],
    *,
    config: dict[str, Any],
    enabled_modules: dict[str, bool] | None = None,
    dry_run: bool = False,
    progress_callback: Any | None = None,
) -> tuple[list[ModuleResult], list[Finding]]:
    enabled_modules = enabled_modules or {}
    module_results: list[ModuleResult] = []
    findings: list[Finding] = []
    expanded = _expanded_routes(routes)

    modules = available_modules()
    completed = 0
    total_targets = sum(
        len(expanded.get(module_targets_key(module.name), []))
        for module in modules
        if not enabled_modules or enabled_modules.get(module.name, False)
    )
    for module in modules:
        if enabled_modules and not enabled_modules.get(module.name, False):
            module_results.append(ModuleResult(module.name, {}, skipped_reason="Disabled by profile/config."))
            continue
        target_key = module_targets_key(module.name)
        targets = expanded.get(target_key, [])
        if not targets:
            module_results.append(ModuleResult(module.name, {}, skipped_reason=f"No targets for {target_key}."))
            continue
        for index, target in enumerate(targets, start=1):
            target_dict = asdict(target) if not isinstance(target, dict) else target
            if progress_callback:
                progress_callback(module.name, index - 1, len(targets), len(findings), completed, total_targets)
            if dry_run:
                module_results.append(ModuleResult(module.name, target_dict, skipped_reason=f"Dry-run: would run {module.description}"))
                completed += 1
                if progress_callback:
                    progress_callback(module.name, index, len(targets), len(findings), completed, total_targets)
                continue
            result = module.execute(target_dict, config)
            for finding in result.findings:
                apply_false_positive_rules(finding, context=str(config.get("context", "unknown")))
                assign_priority(finding, context=str(config.get("context", "unknown")), internet_facing=bool(config.get("internet_facing", False)))
            findings.extend(result.findings)
            module_results.append(result)
            completed += 1
            if progress_callback:
                progress_callback(module.name, index, len(targets), len(findings), completed, total_targets)
    return module_results, findings


def module_summary(module_results: list[ModuleResult]) -> dict[str, Any]:
    findings_by_module = Counter()
    evidence_by_module = Counter()
    errors: list[str] = []
    for result in module_results:
        findings_by_module[result.module_name] += len(result.findings)
        evidence_by_module[result.module_name] += len(result.evidence)
        errors.extend(f"{result.module_name}: {error}" for error in result.errors)
    return {
        "module_runs": [result.to_dict() for result in module_results],
        "module_errors": errors,
        "findings_by_module": dict(findings_by_module),
        "evidence_by_module": dict(evidence_by_module),
    }


def _expanded_routes(routes: dict[str, list[ModuleTarget]]) -> dict[str, list[ModuleTarget]]:
    expanded = {key: value[:] for key, value in routes.items()}
    all_targets: list[ModuleTarget] = []
    seen: set[tuple[str, int, str]] = set()
    for targets in routes.values():
        for target in targets:
            identity = (target.host, target.port, target.protocol)
            if identity not in seen:
                seen.add(identity)
                all_targets.append(target)
    expanded["all_services"] = all_targets
    return expanded
