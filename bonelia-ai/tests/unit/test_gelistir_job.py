"""The GitHub side of "Geliştir" (07.11.2026): the job's report, and safety properties of the workflow file."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WF = ROOT.parent / ".github" / "workflows" / "claude-gelistir.yml"


def report_mod():
    spec = importlib.util.spec_from_file_location("gelistir_report", ROOT / "scripts" / "gelistir_report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_report_status_comes_from_git_and_tests_not_from_claudes_words(tmp_path):
    m = report_mod()
    (tmp_path / "summary.md").write_text("Hazır! Her şey mükemmel.\n" + "x" * 3000, encoding="utf-8")
    base = {"GELISTIR_STAGE": "ran", "RUN_URL": "https://github.com/run/1"}
    assert m.build({**base, "GELISTIR_CHANGED": "true", "GELISTIR_VERIFIED": "true", "GELISTIR_BRANCH": "claude/gelistir-1"}, tmp_path)["status"] == "ready"
    r = m.build({**base, "GELISTIR_CHANGED": "true", "GELISTIR_VERIFIED": "false"}, tmp_path)
    assert r["status"] == "tests_failed" and r["tests"] == "failed" and len(r["summary"]) == 1500
    assert m.build({**base, "GELISTIR_CHANGED": "false"}, tmp_path)["status"] == "no_change"
    assert m.build({"GELISTIR_STAGE": "no_key"}, tmp_path)["status"] == "no_key"
    assert m.build({**base, "GELISTIR_CHANGED": "true", "GELISTIR_VERIFIED": "true", "GELISTIR_BRANCH": ""}, tmp_path)["status"] == "failed"


def test_workflow_never_merges_and_keeps_the_wish_out_of_shell_code():
    text = WF.read_text(encoding="utf-8")
    assert "run-name: Gelistir ${{ inputs.request_id }}" in text
    assert "permissions:\n  contents: write\n\n" in text
    assert "persist-credentials: false" in text  # Claude's step has no push rights
    assert text.count("${{ inputs.request }}") == 1 and "REQUEST: ${{ inputs.request }}" in text  # only via a variable
    assert 'git checkout "$(cat .gelistir/start-sha)" -- .github' in text  # Claude cannot change workflows
    assert "claude/gelistir-${GITHUB_RUN_ID}" in text and "git merge" not in text and "/merges" not in text
    assert "CLAUDE_CODE_OAUTH_TOKEN" in text and "ANTHROPIC_API_KEY" in text
    assert (ROOT / "scripts" / "gelistir-prompt.md").is_file()
