from __future__ import annotations

import threading
import time

import portwise.core.module_runner as mr
from portwise.core.models import Finding, ModuleTarget, Severity
from portwise.core.module_runner import _dispatch_by_host, execute_safe_modules
from portwise.modules.results import ModuleResult


# --------------------------------------------------------------------------
# _dispatch_by_host: per-host serialization + cross-host concurrency
# --------------------------------------------------------------------------

def test_dispatch_serializes_per_host_and_parallelizes_across_hosts():
    active: dict[str, int] = {}
    max_concurrent_per_host: dict[str, int] = {}
    max_total_concurrent = [0]
    total_active = [0]
    lock = threading.Lock()

    def worker(module, target):
        host = target["host"]
        with lock:
            active[host] = active.get(host, 0) + 1
            total_active[0] += 1
            max_concurrent_per_host[host] = max(max_concurrent_per_host.get(host, 0), active[host])
            max_total_concurrent[0] = max(max_total_concurrent[0], total_active[0])
        time.sleep(0.02)
        with lock:
            active[host] -= 1
            total_active[0] -= 1
        return ModuleResult(module.name, target, findings=[])

    class _M:
        name = "m"

    work = []
    wid = 0
    for host in ("a", "b", "c"):
        for port in (1, 2, 3):
            work.append((wid, _M(), {"host": host, "port": port, "protocol": "tcp"}))
            wid += 1

    results = _dispatch_by_host(work, concurrency=3, worker=worker, total_targets=len(work))

    assert len(results) == len(work)
    # No host was probed by two workers at once.
    assert all(v == 1 for v in max_concurrent_per_host.values())
    # Different hosts did run concurrently.
    assert max_total_concurrent[0] >= 2


def test_dispatch_empty_work_returns_empty():
    assert _dispatch_by_host([], concurrency=4, worker=lambda m, t: None) == {}


def test_dispatch_single_host_runs_serially_even_with_high_concurrency():
    order: list[int] = []
    lock = threading.Lock()

    def worker(module, target):
        with lock:
            order.append(target["port"])
        return ModuleResult("m", target, findings=[])

    class _M:
        name = "m"

    work = [(i, _M(), {"host": "h", "port": i, "protocol": "tcp"}) for i in range(5)]
    results = _dispatch_by_host(work, concurrency=10, worker=worker, total_targets=5)
    assert len(results) == 5
    # Single host => one worker => sequential order preserved.
    assert order == [0, 1, 2, 3, 4]


# --------------------------------------------------------------------------
# execute_safe_modules: deterministic output regardless of concurrency
# --------------------------------------------------------------------------

class _DeterministicModule:
    description = "fake module"

    def __init__(self, name: str) -> None:
        self.name = name

    def execute(self, target: dict, config: dict) -> ModuleResult:
        # Small sleep to encourage interleaving when run in parallel.
        time.sleep(0.005)
        finding = Finding(
            title=f"{self.name}:{target['host']}:{target['port']}",
            severity=Severity.LOW,
            asset=target["host"],
            port=target["port"],
            protocol=target.get("protocol", "tcp"),
        )
        return ModuleResult(self.name, target, findings=[finding], evidence=[])


def _routes():
    ssh = [ModuleTarget(host=f"10.0.0.{i}", port=22, protocol="tcp", service="ssh") for i in range(6)]
    http = [ModuleTarget(host=f"10.0.0.{i}", port=80, protocol="tcp", service="http") for i in range(6)]
    return {"ssh_targets": ssh, "http_targets": http}


def _run(concurrency: int):
    config = {"context": "internal", "module_concurrency": concurrency}
    return execute_safe_modules(
        _routes(),
        config=config,
        enabled_modules={"ssh": True, "http": True},
    )


def test_parallel_output_matches_serial(monkeypatch):
    fakes = [_DeterministicModule("ssh"), _DeterministicModule("http")]
    monkeypatch.setattr(mr, "available_modules", lambda: fakes)

    serial_results, serial_findings = _run(1)
    serial_titles = [f.title for f in serial_findings]
    serial_modules = [r.module_name for r in serial_results]

    # Run several times at high concurrency; ordering must be identical each time.
    for _ in range(5):
        par_results, par_findings = _run(8)
        assert [f.title for f in par_findings] == serial_titles
        assert [r.module_name for r in par_results] == serial_modules

    # And the content is what we expect: ssh findings first (module order), each in target order.
    assert serial_titles[0] == "ssh:10.0.0.0:22"
    assert serial_titles[6] == "http:10.0.0.0:80"


def test_concurrency_runs_hosts_in_parallel(monkeypatch):
    # 6 distinct hosts, each module sleeps 5ms. Serial would be ~12*5ms; parallel
    # across hosts should be meaningfully faster. We assert correctness + that the
    # parallel run is not dramatically slower (smoke check on the pool).
    fakes = [_DeterministicModule("ssh"), _DeterministicModule("http")]
    monkeypatch.setattr(mr, "available_modules", lambda: fakes)

    start = time.monotonic()
    results, findings = _run(8)
    elapsed = time.monotonic() - start

    assert len(findings) == 12
    # 6 hosts in parallel, 2 items each (~10ms/host) => well under the ~60ms serial floor.
    assert elapsed < 0.05


def test_disabled_and_empty_modules_still_reported(monkeypatch):
    fakes = [_DeterministicModule("ssh"), _DeterministicModule("http"), _DeterministicModule("ftp")]
    monkeypatch.setattr(mr, "available_modules", lambda: fakes)
    results, findings = execute_safe_modules(
        {"ssh_targets": [ModuleTarget(host="10.0.0.1", port=22, protocol="tcp", service="ssh")]},
        config={"context": "internal"},
        enabled_modules={"ssh": True, "http": True, "ftp": False},
    )
    by_name = {r.module_name: r for r in results}
    assert by_name["ftp"].skipped_reason == "Disabled by profile/config."
    assert "No targets" in (by_name["http"].skipped_reason or "")
    assert len(findings) == 1
