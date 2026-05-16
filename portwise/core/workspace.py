from __future__ import annotations

from pathlib import Path
from shutil import copyfile


WORKSPACE_DIRS = ("scans", "evidence", "reports", "runs", "logs")


def create_workspace(project_name: str, base_dir: Path | str = ".") -> Path:
    root = Path(base_dir) / project_name
    root.mkdir(parents=True, exist_ok=True)
    for name in WORKSPACE_DIRS:
        (root / name).mkdir(exist_ok=True)

    targets = root / "targets.txt"
    if not targets.exists():
        targets.write_text("# Authorized targets only.\n", encoding="utf-8")

    config = root / "config.yaml"
    if not config.exists():
        source = Path(__file__).resolve().parents[2] / "config.example.yaml"
        if source.exists():
            copyfile(source, config)
        else:
            config.write_text("profiles: {}\n", encoding="utf-8")

    return root
