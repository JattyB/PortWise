from __future__ import annotations

from pathlib import Path
from dataclasses import asdict
from typing import Any

from portwise.core.config import PortWiseConfig, Profile
from portwise.core.models import Asset, Finding, RunResult, RunState, Service
from portwise.core.module_runner import execute_safe_modules, module_summary
from portwise.core.routing import module_target_counts, route_assets, write_target_files
from portwise.core.service_groups import ServiceDetectionGroup, group_hosts_by_ports, prepare_group_files
from portwise.intelligence.confidence import apply_confidence
from portwise.intelligence.cve_placeholder import enrich_services_with_cves
from portwise.intelligence.false_positive import apply_false_positive_rules
from portwise.modules.exposure.exposure_engine import evaluate_exposure
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.tls.tls_engine import TlsEngine
from portwise.scanners.nmap_parser import parse_nmap_xml
from portwise.scanners.nmap_runner import NmapRunner
from portwise.utils.files import ensure_dir, write_json


PHASE_XML = {
    "discovery": "01_discovery.xml",
    "tcp_top_1000": "02_tcp_top_1000.xml",
    "tcp_full": "03_tcp_full.xml",
    "tcp_services": "04_tcp_services.xml",
    "udp_top_1000": "06_udp_top_1000.xml",
    "udp_services": "07_udp_services.xml",
}


def run_scan(
    workspace: Path,
    config: PortWiseConfig,
    profile: Profile,
    targets_file: Path,
    dry_run: bool = True,
    no_modules: bool = False,
    no_cve: bool = False,
    internet_facing: bool | None = None,
) -> RunResult:
    run = RunResult(project=str(config.project.get("name", workspace.name)), profile=profile.name)
    state = RunState(project=run.project, profile=profile.name, targets_loaded=_load_targets(targets_file))
    timeout = int(config.scanner.get("nmap_timeout_seconds", 1800))
    nmap = NmapRunner(workspace, timeout_seconds=timeout)
    live_hosts_file = workspace / "scans" / "live_hosts.txt"
    latest = workspace / "runs" / "latest.json"

    for step in profile.nmap_steps:
        if step != "discovery" and not state.live_hosts:
            xml_path = workspace / "scans" / PHASE_XML["discovery"]
            if xml_path.exists():
                _merge_discovery(state, parse_nmap_xml(xml_path))
                _write_live_hosts(live_hosts_file, state.live_hosts)
            else:
                _skip(state, step, "No live hosts are available yet; discovery XML is missing.")
                _persist(latest, run, state)
                continue

        if step == "tcp_services" and not _all_ports(state.tcp_open_ports_by_host):
            _skip(state, step, "No open TCP ports discovered; skipping TCP service detection.")
            _persist(latest, run, state)
            continue

        if step == "tcp_services":
            _run_grouped_service_detection(
                protocol="tcp",
                workspace=workspace,
                nmap=nmap,
                state=state,
                run=run,
                dry_run=dry_run,
                latest=latest,
                open_ports_by_host=state.tcp_open_ports_by_host,
            )
            continue

        udp_ports_for_services = _udp_service_ports_by_host(
            state,
            include_open_filtered=bool(config.scanner.get("udp_service_detection_on_open_filtered", False)),
        )
        if step == "udp_services" and not _all_ports(udp_ports_for_services):
            _skip(state, step, "No open UDP ports discovered; skipping UDP service detection.")
            _persist(latest, run, state)
            continue

        if step == "udp_services":
            _run_grouped_service_detection(
                protocol="udp",
                workspace=workspace,
                nmap=nmap,
                state=state,
                run=run,
                dry_run=dry_run,
                latest=latest,
                open_ports_by_host=udp_ports_for_services,
            )
            continue

        command = nmap.run_step(
            step,
            targets_file=targets_file,
            dry_run=dry_run,
            live_hosts_file=live_hosts_file,
            open_tcp_ports=_ports_arg(_all_ports(state.tcp_open_ports_by_host), "tcp"),
            open_udp_ports=_ports_arg(_interesting_udp_ports(state), "udp"),
        )
        run.commands.append(command)
        state.commands_executed.append(command)
        if command.error:
            run.failed_checks.append(f"nmap:{step}:{command.error}")
            state.failed_phases.append(f"{step}: {command.error}")

        xml_path = workspace / "scans" / PHASE_XML.get(step, "")
        if xml_path.exists():
            assets = parse_nmap_xml(xml_path)
            _merge_phase(state, step, assets)
            if step == "discovery":
                _write_live_hosts(live_hosts_file, state.live_hosts)
                state.generated_files.append(str(live_hosts_file))
        elif dry_run:
            _skip(state, step, f"Dry-run only; expected XML not present at {xml_path}.")
        else:
            _skip(state, step, f"Expected XML not found after phase: {xml_path}.")
        _persist(latest, run, state)

    if not state.live_hosts:
        run.skipped_checks.append("No live hosts discovered.")

    routes = route_assets(run.assets, probe_tls=False)
    state.module_targets = routes
    state.generated_files.extend(write_target_files(routes, workspace))
    module_config = _module_config(config, profile, internet_facing=internet_facing)
    if no_modules:
        state.skipped_phases.append("modules: Disabled by --no-modules.")
    else:
        module_results, module_findings = execute_safe_modules(
            routes,
            config=module_config,
            enabled_modules=_enabled_modules(profile),
            dry_run=dry_run,
        )
        run.findings.extend(module_findings)
        run.evidence.extend([evidence for finding in module_findings for evidence in finding.evidence])
        summary = module_summary(module_results)
        state.module_runs = summary["module_runs"]
        state.module_errors = summary["module_errors"]
        state.findings_by_module = summary["findings_by_module"]
        state.evidence_by_module = summary["evidence_by_module"]
    if not no_cve and not dry_run and bool(profile.modules.get("cve_enrichment", False)):
        cve_findings, cve_notes = enrich_services_with_cves(_services_from_assets(run.assets), workspace / "cache" / "cve", enabled=True)
        run.findings.extend(cve_findings)
        run.evidence.extend([evidence for finding in cve_findings for evidence in finding.evidence])
        state.module_errors.extend(cve_notes)
    elif no_cve:
        state.skipped_phases.append("cve: Disabled by --no-cve.")
    elif dry_run and bool(profile.modules.get("cve_enrichment", False)):
        state.skipped_phases.append("cve: Dry-run mode; CVE providers not queried.")
    run.metadata["state"] = state.to_dict()
    run.metadata["module_target_counts"] = module_target_counts(routes)
    run.finish()
    _persist(latest, run, state)
    return run


def analyze_assets(
    assets: list[Asset],
    project: str,
    profile: str,
    context: str = "unknown",
    enable_tls: bool = False,
    enable_http: bool = False,
    enable_exposure: bool = True,
    module_config: dict[str, Any] | None = None,
    dry_run_modules: bool = False,
    no_cve: bool = True,
) -> RunResult:
    run = RunResult(project=project, profile=profile, assets=assets)
    tls_engine = TlsEngine()
    http_engine = HttpEngine()
    findings: list[Finding] = []

    for asset in assets:
        for service in asset.services:
            if service.state not in {"open", "open|filtered"}:
                continue
            if enable_exposure:
                findings.extend(evaluate_exposure(service, context=context))
            if enable_tls and service.state == "open" and tls_engine.should_run(service):
                findings.extend(tls_engine.run(service))
            if enable_http and service.state == "open" and http_engine.should_run(service):
                findings.extend(http_engine.run(service))

    processed: list[Finding] = []
    for finding in findings:
        apply_confidence(finding, safe_active="safe-active" in finding.tags)
        apply_false_positive_rules(finding, context=context)
        processed.append(finding)
        run.evidence.extend(finding.evidence)
    run.findings = processed
    routes = route_assets(assets, probe_tls=False)
    run.metadata["module_targets"] = {key: [asdict(target) for target in value] for key, value in routes.items()}
    run.metadata["module_target_counts"] = module_target_counts(routes)
    enabled = {
        "tls": enable_tls,
        "http": enable_http,
        "exposure": enable_exposure,
    }
    module_results, module_findings = execute_safe_modules(
        routes,
        config=module_config or {"context": context},
        enabled_modules=enabled,
        dry_run=dry_run_modules,
    )
    run.findings.extend(module_findings)
    run.evidence.extend([evidence for finding in module_findings for evidence in finding.evidence])
    run.metadata.update(module_summary(module_results))
    if not no_cve:
        cve_findings, cve_notes = enrich_services_with_cves(_services_from_assets(assets), Path(".portwise_cache") / "cve", enabled=True)
        run.findings.extend(cve_findings)
        run.evidence.extend([evidence for finding in cve_findings for evidence in finding.evidence])
        run.metadata["cve_notes"] = cve_notes
    run.finish()
    return run


def build_run_state_from_assets(assets: list[Asset], project: str, profile: str, targets: list[str] | None = None) -> RunState:
    state = RunState(project=project, profile=profile, targets_loaded=targets or [])
    _merge_discovery(state, assets)
    _merge_ports(state, assets)
    _merge_services(state, assets)
    state.module_targets = route_assets(assets, probe_tls=False)
    state.touch()
    return state


def _module_config(config: PortWiseConfig, profile: Profile, *, internet_facing: bool | None = None) -> dict[str, Any]:
    scanner = dict(config.scanner)
    modules = dict(config.project.get("modules", {}))
    sections = {
        key: config.raw.get(key, {})
        for key in ("http", "tls", "dns", "snmp", "ntp", "database", "mail", "cve", "imports", "safety", "cache")
        if isinstance(config.raw.get(key), dict)
    }
    merged = {**scanner, **modules, **sections}
    if "http" in sections and "safe_paths" in sections["http"]:
        merged["http_paths"] = sections["http"]["safe_paths"]
    merged["context"] = profile.context
    if internet_facing is not None:
        merged["internet_facing"] = internet_facing
    return merged


def _enabled_modules(profile: Profile) -> dict[str, bool]:
    raw = dict(profile.modules)
    aliases = {
        "smb_safe": "smb",
        "confidence_scoring": "",
        "false_positive_scoring": "",
        "cve_enrichment": "",
    }
    enabled: dict[str, bool] = {}
    for key, value in raw.items():
        mapped = aliases.get(key, key)
        if mapped:
            enabled[mapped] = bool(value)
    return enabled


def _persist(path: Path, run: RunResult, state: RunState) -> None:
    state.touch()
    run.metadata["state"] = state.to_dict()
    run.metadata["module_target_counts"] = module_target_counts(state.module_targets)
    write_json(path, run.to_dict())


def _load_targets(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]


def _skip(state: RunState, phase: str, reason: str) -> None:
    state.skipped_phases.append(f"{phase}: {reason}")


def _merge_phase(state: RunState, step: str, assets: list[Asset]) -> None:
    if step == "discovery":
        _merge_discovery(state, assets)
    elif step in {"tcp_top_1000", "tcp_full", "udp_top_1000"}:
        _merge_ports(state, assets)
    elif step in {"tcp_services", "udp_services"}:
        _merge_ports(state, assets)
        _merge_services(state, assets)


def _merge_discovery(state: RunState, assets: list[Asset]) -> None:
    live = set(state.live_hosts)
    dead = set(state.dead_hosts)
    for asset in assets:
        if asset.status == "down":
            dead.add(asset.ip)
        else:
            live.add(asset.ip)
    state.live_hosts = sorted(live)
    state.dead_hosts = sorted(dead - live)


def _merge_ports(state: RunState, assets: list[Asset]) -> None:
    for asset in assets:
        for service in asset.services:
            if service.protocol == "tcp" and service.state == "open":
                _add_port(state.tcp_open_ports_by_host, asset.ip, service.port)
            if service.protocol == "udp" and service.state == "open":
                _add_port(state.udp_open_ports_by_host, asset.ip, service.port)
            if service.protocol == "udp" and service.state == "open|filtered":
                _add_port(state.udp_open_filtered_ports_by_host, asset.ip, service.port)


def _merge_services(state: RunState, assets: list[Asset]) -> None:
    for asset in assets:
        existing = state.services_by_host.setdefault(asset.ip, [])
        for service in asset.services:
            identity = (service.protocol, service.port)
            replacement = asdict(service)
            for index, item in enumerate(existing):
                if (item["protocol"], item["port"]) != identity:
                    continue
                if _service_score(replacement) > _service_score(item):
                    existing[index] = replacement
                break
            else:
                existing.append(replacement)


def _merge_assets(existing: list[Asset], incoming: list[Asset]) -> list[Asset]:
    by_host = {asset.ip: asset for asset in existing}
    for asset in incoming:
        current = by_host.setdefault(asset.ip, Asset(ip=asset.ip, status=asset.status, ipv4=asset.ipv4, ipv6=asset.ipv6, hostnames=asset.hostnames))
        for service in asset.services:
            identity = (service.protocol, service.port)
            for index, existing_service in enumerate(current.services):
                if (existing_service.protocol, existing_service.port) != identity:
                    continue
                if _service_score(asdict(service)) > _service_score(asdict(existing_service)):
                    current.services[index] = service
                break
            else:
                current.add_service(service)
    return list(by_host.values())


def _run_grouped_service_detection(
    *,
    protocol: str,
    workspace: Path,
    nmap: NmapRunner,
    state: RunState,
    run: RunResult,
    dry_run: bool,
    latest: Path,
    open_ports_by_host: dict[str, list[int]],
) -> None:
    groups = group_hosts_by_ports(open_ports_by_host, protocol)
    phase = f"{protocol}_services"
    state_attr = "tcp_service_detection_groups" if protocol == "tcp" else "udp_service_detection_groups"

    if not groups:
        _skip(state, phase, f"No {protocol.upper()} service-detection groups were created.")
        _persist(latest, run, state)
        return

    generated = prepare_group_files(groups, workspace)
    state.generated_files.extend(generated)
    merged_assets: list[Asset] = []

    for group in groups:
        command = nmap.build_service_detection_command(protocol, group)
        result = nmap.run_command(group.group_id, command, dry_run=dry_run)
        run.commands.append(result)
        state.commands_executed.append(result)
        if result.error:
            run.failed_checks.append(f"nmap:{group.group_id}:{result.error}")
            state.failed_phases.append(f"{group.group_id}: {result.error}")

        xml_path = Path(group.parsed_xml_file or "")
        if xml_path.exists():
            assets = parse_nmap_xml(xml_path)
            merged_assets = _merge_assets(merged_assets, assets)
            run.assets = _merge_assets(run.assets, assets)
            _merge_phase(state, phase, assets)
            group.service_count_after_merge = _service_count(run.assets)
        elif dry_run:
            _skip(state, group.group_id, f"Dry-run only; expected XML not present at {xml_path}.")
        else:
            _skip(state, group.group_id, f"Expected grouped service XML not found: {xml_path}.")

    # Parse any existing grouped XML outputs as an offline merge path.
    for xml_path in sorted((workspace / "scans").glob(f"{'04_tcp' if protocol == 'tcp' else '07_udp'}_services_{protocol}_group_*.xml")):
        assets = parse_nmap_xml(xml_path)
        run.assets = _merge_assets(run.assets, assets)
        _merge_phase(state, phase, assets)

    setattr(state, state_attr, [group.to_dict() for group in groups])
    _persist(latest, run, state)


def _udp_service_ports_by_host(state: RunState, *, include_open_filtered: bool) -> dict[str, list[int]]:
    if not include_open_filtered:
        return {host: ports[:] for host, ports in state.udp_open_ports_by_host.items()}
    merged = {host: ports[:] for host, ports in state.udp_open_ports_by_host.items()}
    for host, ports in state.udp_open_filtered_ports_by_host.items():
        current = set(merged.get(host, []))
        current.update(ports)
        merged[host] = sorted(current)
    return merged


def _service_score(service: dict[str, object]) -> int:
    score = 0
    if service.get("product"):
        score += 3
    if service.get("version"):
        score += 3
    if service.get("cpes"):
        score += 4
    scripts = service.get("scripts")
    if isinstance(scripts, dict) and scripts:
        score += 4
    confidence = service.get("confidence")
    if isinstance(confidence, int):
        score += confidence
    if service.get("source_file"):
        score += 1
    return score


def _service_count(assets: list[Asset]) -> int:
    return sum(len(asset.services) for asset in assets)


def _services_from_assets(assets: list[Asset]) -> list[Service]:
    return [service for asset in assets for service in asset.services]


def _add_port(mapping: dict[str, list[int]], host: str, port: int) -> None:
    ports = set(mapping.get(host, []))
    ports.add(port)
    mapping[host] = sorted(ports)


def _all_ports(mapping: dict[str, list[int]]) -> list[int]:
    ports: set[int] = set()
    for values in mapping.values():
        ports.update(values)
    return sorted(ports)


def _interesting_udp_ports(state: RunState) -> list[int]:
    ports = set(_all_ports(state.udp_open_ports_by_host))
    interesting = {53, 69, 123, 137, 161, 500, 514, 1900, 4500}
    return sorted(ports & interesting) or sorted(ports)


def _ports_arg(ports: list[int], protocol: str) -> str:
    if not ports:
        return "T:1-65535" if protocol == "tcp" else "U:53,67,68,69,123,137,161,500,514,520,1900,4500"
    return ",".join(str(port) for port in ports)


def _write_live_hosts(path: Path, hosts: list[str]) -> None:
    ensure_dir(path.parent)
    path.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
