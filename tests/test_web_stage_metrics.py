import asyncio
import json

from portwise.modules.http.stage_metrics import DurableStageRecorder, measure_stage


def test_stage_metric_is_written_and_printed(tmp_path, capsys):
    count = 0

    async def operation():
        nonlocal count
        count += 4
        return "done"

    output = tmp_path / "metrics.jsonl"
    recorder = DurableStageRecorder(output)
    result = asyncio.run(measure_stage(
        host="example.test",
        stage="crawl",
        operation=operation,
        request_count=lambda: count,
        recorder=recorder,
        cap_seconds=1,
    ))
    assert result == "done"
    row = json.loads(output.read_text(encoding="utf-8"))
    assert row["status"] == "completed"
    assert row["requests"] == 4
    assert "[web-stage] crawl" in capsys.readouterr().out


def test_capped_stage_persists_partial_request_count(tmp_path):
    count = 0

    async def operation():
        nonlocal count
        count += 3
        await asyncio.sleep(1)

    output = tmp_path / "metrics.jsonl"
    recorder = DurableStageRecorder(output)
    asyncio.run(measure_stage(
        host="example.test",
        stage="fuzz",
        operation=operation,
        request_count=lambda: count,
        recorder=recorder,
        cap_seconds=0.01,
    ))
    row = json.loads(output.read_text(encoding="utf-8"))
    assert row["status"] == "capped"
    assert row["requests"] == 3
    assert "time-budget reached" in row["error"]
