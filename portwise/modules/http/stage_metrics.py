"""Durable web-stage performance telemetry.

Each completed or capped stage is appended immediately as JSONL, then printed.
This keeps diagnostic data when a later stage or outer process times out.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import time
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


@dataclass(slots=True)
class WebStageMetric:
    host: str
    stage: str
    status: str
    seconds: float
    requests: int
    req_s: float
    cap_seconds: float | None = None
    error: str = ""


class DurableStageRecorder:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.rows: list[WebStageMetric] = []

    def record(self, row: WebStageMetric) -> None:
        self.rows.append(row)
        payload = asdict(row)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")
                handle.flush()
        print(
            f"[web-stage] {row.stage}: {row.status}; {row.seconds:.2f}s; "
            f"{row.requests} requests; {row.req_s:.2f} req/s",
            flush=True,
        )


async def measure_stage(
    *,
    host: str,
    stage: str,
    operation: Callable[[], Awaitable[T]],
    request_count: Callable[[], int],
    recorder: DurableStageRecorder,
    cap_seconds: float | None = None,
) -> T | None:
    import asyncio

    started = time.perf_counter()
    requests_before = request_count()
    status = "completed"
    error = ""
    value: T | None = None
    try:
        if cap_seconds and cap_seconds > 0:
            async with asyncio.timeout(cap_seconds):
                value = await operation()
        else:
            value = await operation()
    except TimeoutError:
        status = "capped"
        error = f"stage time-budget reached ({cap_seconds:g}s)"
    except Exception as exc:
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.perf_counter() - started
    requests = max(0, request_count() - requests_before)
    recorder.record(WebStageMetric(
        host=host,
        stage=stage,
        status=status,
        seconds=round(elapsed, 4),
        requests=requests,
        req_s=round(requests / elapsed, 4) if elapsed else 0.0,
        cap_seconds=cap_seconds,
        error=error,
    ))
    return value
