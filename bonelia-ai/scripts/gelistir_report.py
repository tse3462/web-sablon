"""Report of the "Geliştir" job (07.11.2026): one small JSON file BONELIA AI downloads from the job.

Inputs come from the workflow as environment variables: GELISTIR_STAGE (ran / no_key), GELISTIR_CHANGED, GELISTIR_VERIFIED,
GELISTIR_BRANCH, RUN_URL. Claude's own words are read from .gelistir/summary.md (shortened, never trusted as status).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def build(env: dict[str, str], folder: Path) -> dict:
    stage = env.get("GELISTIR_STAGE", "")
    changed = env.get("GELISTIR_CHANGED") == "true"
    verified = env.get("GELISTIR_VERIFIED") == "true"
    branch = env.get("GELISTIR_BRANCH", "")
    try:
        summary = (folder / "summary.md").read_text(encoding="utf-8").strip()[:1500]
    except OSError:
        summary = ""
    if stage == "no_key":
        status = "no_key"
    elif stage != "ran":
        status = "failed"
    elif not changed:
        status = "no_change"
    elif not verified:
        status = "tests_failed"
    else:
        status = "ready" if branch else "failed"
    return {"status": status, "summary": summary, "branch": branch or None,
            "tests": "none" if not changed else ("passed" if verified else "failed"), "run_url": env.get("RUN_URL", "")}


def main() -> int:
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else ".gelistir")
    folder.mkdir(parents=True, exist_ok=True)
    rep = build(dict(os.environ), folder)
    (folder / "report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(rep, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
