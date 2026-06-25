from __future__ import annotations

import tomllib
from pathlib import Path


def test_impacket_is_ad_extra_not_base_dependency():
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    base_deps = {dep.split(">=", 1)[0].lower() for dep in data["project"]["dependencies"]}
    ad_deps = {dep.split(">=", 1)[0].lower() for dep in data["project"]["optional-dependencies"]["ad"]}

    assert "impacket" not in base_deps
    assert "impacket" in ad_deps
