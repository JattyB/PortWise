from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def dataclass_json_default(value: Any) -> Any:
    return make_json_safe(value)


def ensure_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def make_json_safe(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return ensure_text(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, BaseException):
        return ensure_text(obj)
    if is_dataclass(obj):
        return make_json_safe(asdict(obj))
    if isinstance(obj, dict):
        return {ensure_text(key): make_json_safe(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [make_json_safe(value) for value in obj]
    if hasattr(obj, "model_dump"):
        try:
            return make_json_safe(obj.model_dump())
        except Exception:
            return ensure_text(obj)
    if hasattr(obj, "dict"):
        try:
            return make_json_safe(obj.dict())
        except Exception:
            return ensure_text(obj)
    return ensure_text(obj)


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(make_json_safe(data), handle, indent=2, sort_keys=True, default=dataclass_json_default)
        handle.write("\n")
