from __future__ import annotations

import argparse
import json
import subprocess
import shutil
from collections import Counter
from pathlib import Path

from portwise.modules.http.nuclei_engine import _load_template

DEFAULT_DIRS = [
    "http/technologies",
    "http/exposures",
    "http/misconfiguration",
    "http/exposed-panels",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync runnable nuclei HTTP templates into PortWise package data.")
    parser.add_argument("--repo-dir", required=True, help="Path to a checked-out nuclei-templates repository.")
    parser.add_argument("--output-dir", required=True, help="Destination portwise/data/nuclei directory.")
    parser.add_argument("--source-url", default="https://github.com/projectdiscovery/nuclei-templates")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--include-dir", action="append", dest="include_dirs", default=[])
    args = parser.parse_args()

    repo_dir = Path(args.repo_dir)
    output_dir = Path(args.output_dir)
    templates_dir = output_dir / "templates"
    include_dirs = args.include_dirs or DEFAULT_DIRS

    if templates_dir.exists():
        shutil.rmtree(templates_dir)
    templates_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {
        "source_url": args.source_url,
        "commit": args.commit,
        "include_dirs": include_dirs,
        "license": "MIT",
        "templates": [],
        "counts": {},
        "skipped_reasons": {},
    }
    skipped = Counter()
    candidates = 0
    runnable = 0
    seen_names: set[str] = set()

    for include_dir in include_dirs:
        root = repo_dir / include_dir
        for candidate in root.rglob("*.yaml"):
            candidates += 1
            parsed = _load_template(candidate)
            if parsed is None:
                skipped["parse-error"] += 1
                continue
            template, reasons = parsed
            if not template.http:
                skipped["no-supported-http"] += 1
                continue
            if reasons:
                for reason in reasons:
                    skipped[reason.split(":")[-1]] += 1
                continue
            relative = candidate.relative_to(repo_dir).as_posix()
            filename = relative.replace("/", "__")
            if filename in seen_names:
                skipped["name-collision"] += 1
                continue
            seen_names.add(filename)
            shutil.copy2(candidate, templates_dir / filename)
            runnable += 1
            manifest["templates"].append({
                "id": template.template_id,
                "name": template.name,
                "severity": template.severity,
                "tags": template.tags,
                "source_path": relative,
                "local_file": f"templates/{filename}",
            })

    manifest["counts"] = {
        "candidates": candidates,
        "runnable": runnable,
        "skipped": candidates - runnable,
    }
    manifest["skipped_reasons"] = dict(sorted(skipped.items()))
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / "SOURCE.md").write_text(
        "\n".join([
            "Curated nuclei templates synced from ProjectDiscovery nuclei-templates.",
            "",
            f"Source: {args.source_url}",
            f"Commit: {args.commit}",
            f"Included directories: {', '.join(include_dirs)}",
            "License: MIT (see LICENSE.upstream.md).",
            "",
            f"Candidates scanned: {candidates}",
            f"Runnable synced templates: {runnable}",
            f"Skipped templates: {candidates - runnable}",
        ]) + "\n",
        encoding="utf-8",
    )

    license_path = repo_dir / "LICENSE.md"
    if license_path.exists():
        license_text = license_path.read_text(encoding="utf-8")
    else:
        license_text = subprocess.check_output(
            ["git", "-C", str(repo_dir), "show", f"{args.commit}:LICENSE.md"],
            text=True,
        )
    (output_dir / "LICENSE.upstream.md").write_text(license_text, encoding="utf-8")
    print(json.dumps(manifest["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
