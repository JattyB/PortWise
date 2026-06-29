from __future__ import annotations

import time

from portwise.core.models import Service
from portwise.modules.registry import _run_http_engine_with_deadline


class BlockingEngine:
    def run(self, service, config=None):
        time.sleep(1)
        return []


def test_binary_or_nonresponding_http_target_cannot_block_pipeline():
    service = Service(
        host="192.0.2.10",
        port=8009,
        protocol="tcp",
        state="open",
        service_name="ajp13",
        product="Apache Jserv",
    )
    started = time.perf_counter()
    findings, timed_out = _run_http_engine_with_deadline(
        BlockingEngine(), service, {}, timeout=0.05,
    )
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5
    assert timed_out is True
    assert findings[0].title == "HTTP Check Not Completed"
    assert "service-timeout" in findings[0].tags
