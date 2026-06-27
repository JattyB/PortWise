"""Run native web stages independently with durable telemetry."""
from __future__ import annotations

import argparse
import asyncio
from copy import deepcopy
from pathlib import Path
from typing import Any, Awaitable, Callable

import yaml

from portwise.modules.http.archive_discovery import run_archive_url_discovery_async
from portwise.modules.http.content_fuzzer import run_content_fuzzer_async
from portwise.modules.http.nuclei_engine import run_native_nuclei_async
from portwise.modules.http.param_discovery import run_active_parameter_discovery_async
from portwise.modules.http.stage_metrics import DurableStageRecorder, WebStageMetric, measure_stage
from portwise.modules.http.surface import surface_from_config, surface_key
from portwise.modules.http.web_crawl import run_web_crawl_async
from portwise.utils.http_client import client_from_config

STAGES = ("crawl", "archive", "fuzz", "param", "default_templates", "deep_templates")


async def profile_web_stages(
    host: str,
    *,
    config: dict[str, Any],
    output_path: Path,
    cap_seconds: float = 120.0,
    stages: tuple[str, ...] = STAGES,
) -> list[WebStageMetric]:
    recorder = DurableStageRecorder(output_path)
    target = {"host": host, "port": 80, "protocol": "tcp", "service": "http", "technologies": []}
    for stage in stages:
        stage_config = deepcopy(config)
        stage_config["validation_level"] = "full"
        client = client_from_config(stage_config)
        surface = surface_from_config(stage_config, surface_key(host, 80))
        base_url = f"http://{host}:80/"
        surface.add_url(base_url, "stage-profiler")
        operation = _stage_operation(stage, host, client, target, stage_config, surface, base_url)
        try:
            await measure_stage(
                host=host,
                stage=stage,
                operation=operation,
                request_count=lambda: sum(client._request_count.values()),
                recorder=recorder,
                cap_seconds=cap_seconds,
            )
        finally:
            await client.close()
    return recorder.rows


def _stage_operation(stage, host, client, target, config, surface, base_url) -> Callable[[], Awaitable[Any]]:
    if stage == "crawl":
        return lambda: run_web_crawl_async(
            host, 80, False, 8.0, client, target, config, "",
            validation_level="full",
        )
    if stage == "archive":
        return lambda: run_archive_url_discovery_async(host, client, target, config, surface)
    if stage == "fuzz":
        return lambda: run_content_fuzzer_async(
            base_url=base_url, client=client, target=target, config=config, surface=surface,
        )
    if stage == "param":
        return lambda: run_active_parameter_discovery_async(client, target, config, surface)
    if stage in {"default_templates", "deep_templates"}:
        template_cfg = config.setdefault("web_template_engine", {})
        selection = template_cfg.setdefault("selection", {})
        selection["deep"] = stage == "deep_templates"
        return lambda: run_native_nuclei_async(client, target, config)
    raise ValueError(f"Unknown stage: {stage}")


def _load_config(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    scanner = raw.get("scanner", {}) if isinstance(raw.get("scanner"), dict) else {}
    return {**scanner, **{key: value for key, value in raw.items() if isinstance(value, dict)}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile PortWise native web stages independently.")
    parser.add_argument("host")
    parser.add_argument("--config", type=Path, default=Path("config.example.yaml"))
    parser.add_argument("--output", type=Path, default=Path("live/web-stage-metrics.jsonl"))
    parser.add_argument("--cap", type=float, default=120.0)
    parser.add_argument("--stage", action="append", choices=STAGES)
    args = parser.parse_args(argv)
    stages = tuple(args.stage) if args.stage else STAGES
    asyncio.run(profile_web_stages(
        args.host,
        config=_load_config(args.config),
        output_path=args.output,
        cap_seconds=args.cap,
        stages=stages,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
