from __future__ import annotations

import threading
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Any, Callable

from portwise.core.models import Finding, ModuleTarget
from portwise.intelligence.false_positive import apply_category_rules, apply_false_positive_rules
from portwise.intelligence.risk_scoring import assign_priority
from portwise.modules.registry import available_modules, module_targets_key
from portwise.modules.results import ModuleResult

# Default bounded concurrency across hosts. Module checks are I/O-bound, so a
# modest pool gives a large speedup without flooding any single host.
DEFAULT_MODULE_CONCURRENCY = 10


def execute_safe_modules(
    routes: dict[str, list[ModuleTarget]],
    *,
    config: dict[str, Any],
    enabled_modules: dict[str, bool] | None = None,
    dry_run: bool = False,
    progress_callback: Any | None = None,
) -> tuple[list[ModuleResult], list[Finding]]:
    """Run enabled modules over their routed targets.

    Work is parallelized **across hosts** with a bounded thread pool while all
    work for a single host runs **sequentially**, so per-host throttle/politeness
    and circuit-breaker behavior are preserved. Output ordering is deterministic:
    results are reassembled in module → target order regardless of completion
    order.
    """
    enabled_modules = enabled_modules or {}
    expanded = _expanded_routes(routes)
    modules = available_modules()
    concurrency = _resolve_concurrency(config)
    context = str(config.get("context", "unknown"))
    internet_facing = bool(config.get("internet_facing", False))

    total_targets = sum(
        len(expanded.get(module_targets_key(module.name), []))
        for module in modules
        if not enabled_modules or enabled_modules.get(module.name, False)
    )

    # ---- Plan: decide per module whether it is disabled, empty, or runnable ----
    # plans preserves module order; runnable plans carry their target list.
    plans: list[tuple[Any, str, list[Any]]] = []
    for module in modules:
        if enabled_modules and not enabled_modules.get(module.name, False):
            plans.append((module, "disabled", []))
            continue
        targets = expanded.get(module_targets_key(module.name), [])
        if not targets:
            plans.append((module, "empty", []))
            continue
        plans.append((module, "run", targets))

    # ---- Build flat work items with stable ids in deterministic order ----
    work: list[tuple[int, Any, dict[str, Any]]] = []
    for module, kind, targets in plans:
        if kind != "run":
            continue
        for target in targets:
            target_dict = asdict(target) if not isinstance(target, dict) else target
            work.append((len(work), module, target_dict))

    def worker(module: Any, target_dict: dict[str, Any]) -> ModuleResult:
        return _execute_one(
            module, target_dict, config, dry_run,
            context=context, internet_facing=internet_facing,
        )

    results_by_id = _dispatch_by_host(
        work,
        concurrency=concurrency,
        worker=worker,
        progress_callback=progress_callback,
        total_targets=total_targets,
    )

    # ---- Reassemble deterministically in module → target order ----
    module_results: list[ModuleResult] = []
    findings: list[Finding] = []
    next_id = 0
    for module, kind, targets in plans:
        if kind == "disabled":
            module_results.append(ModuleResult(module.name, {}, skipped_reason="Disabled by profile/config."))
        elif kind == "empty":
            target_key = module_targets_key(module.name)
            module_results.append(ModuleResult(module.name, {}, skipped_reason=f"No targets for {target_key}."))
        else:
            for _ in targets:
                result = results_by_id[next_id]
                next_id += 1
                module_results.append(result)
                findings.extend(result.findings)
    return module_results, findings


def _execute_one(
    module: Any,
    target_dict: dict[str, Any],
    config: dict[str, Any],
    dry_run: bool,
    *,
    context: str,
    internet_facing: bool,
) -> ModuleResult:
    if dry_run:
        return ModuleResult(module.name, target_dict, skipped_reason=f"Dry-run: would run {module.description}")
    result = module.execute(target_dict, config)
    for finding in result.findings:
        apply_category_rules(finding)
        apply_false_positive_rules(finding, context=context)
        assign_priority(finding, context=context, internet_facing=internet_facing)
    return result


def _dispatch_by_host(
    work: list[tuple[int, Any, dict[str, Any]]],
    *,
    concurrency: int,
    worker: Callable[[Any, dict[str, Any]], ModuleResult],
    progress_callback: Any | None = None,
    total_targets: int = 0,
) -> dict[int, ModuleResult]:
    """Run work items grouped by host.

    All items sharing a host run sequentially inside one worker (preserving
    per-host politeness); different hosts run concurrently under a bounded pool.
    Returns a mapping of work-id → result so the caller can reassemble in any
    order it likes.
    """
    results: dict[int, ModuleResult] = {}
    if not work:
        return results

    by_host: "OrderedDict[str, list[tuple[int, Any, dict[str, Any]]]]" = OrderedDict()
    for item in work:
        host = str(item[2].get("host", ""))
        by_host.setdefault(host, []).append(item)

    lock = threading.Lock()
    progress = {"completed": 0, "findings": 0}

    def process_host(items: list[tuple[int, Any, dict[str, Any]]]) -> dict[int, ModuleResult]:
        local: dict[int, ModuleResult] = {}
        for work_id, module, target_dict in items:
            result = worker(module, target_dict)
            local[work_id] = result
            if progress_callback:
                with lock:
                    progress["completed"] += 1
                    progress["findings"] += len(result.findings)
                    completed = progress["completed"]
                    found = progress["findings"]
                progress_callback(module.name, completed, total_targets, found, completed, total_targets)
        return local

    effective = max(1, min(concurrency, len(by_host)))
    if effective == 1:
        for items in by_host.values():
            results.update(process_host(items))
        return results

    with ThreadPoolExecutor(max_workers=effective, thread_name_prefix="portwise-module") as executor:
        futures = [executor.submit(process_host, items) for items in by_host.values()]
        for future in as_completed(futures):
            results.update(future.result())
    return results


def _resolve_concurrency(config: dict[str, Any]) -> int:
    raw = config.get("module_concurrency", config.get("concurrency", DEFAULT_MODULE_CONCURRENCY))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = DEFAULT_MODULE_CONCURRENCY
    return max(1, value)


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
