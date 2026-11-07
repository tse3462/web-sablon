"""BONELIA updates itself (07.11.2026): only to code whose tests passed on GitHub, never over local edits, and
the outcome reaches the owner once."""

import json
from pathlib import Path

import httpx

from bonelia.server.self_update import EXIT, decide, github_repo, report, take_note, write_note
from bonelia.server.store import Store

OLD, NEW, TESTED = "a" * 40, "b" * 40, "c" * 40
ROOT = Path(__file__).resolve().parents[2]


class Git:
    def __init__(self, over=None):
        self.calls = []
        self.answers = {
            ("fetch", "--quiet"): (0, ""), ("rev-parse", "HEAD"): (0, OLD), ("rev-parse", "@{u}"): (0, NEW),
            ("merge-base", "--is-ancestor", "HEAD", "@{u}"): (0, ""), ("status", "--porcelain", "--untracked-files=no"): (0, ""),
            ("log", "-1", "--format=%H", "@{u}", "--", "."): (0, TESTED),
            ("merge-base", "--is-ancestor", TESTED, "HEAD"): (1, ""),
            ("remote", "get-url", "origin"): (0, "https://github.com/tse3462/web-sablon.git")}
        self.answers.update(over or {})

    def __call__(self, args):
        self.calls.append(tuple(args))
        return self.answers[tuple(args)]


def gh(runs):
    seen = []

    def handle(req):
        seen.append(req)
        assert req.url.path == "/repos/tse3462/web-sablon/actions/workflows/bonelia-ai.yml/runs"
        assert req.url.params["head_sha"] == TESTED and "authorization" not in req.headers  # public repository
        return httpx.Response(200, json={"workflow_runs": runs})
    return httpx.MockTransport(handle), seen


def test_updates_only_to_code_whose_tests_passed():
    t, _ = gh([{"head_sha": TESTED, "status": "completed", "conclusion": "success"}])
    assert decide(Git(), t) == {"action": "update", "from": OLD, "to": NEW, "tests": "passed"}
    t, _ = gh([{"head_sha": TESTED, "status": "in_progress", "conclusion": None}])
    assert decide(Git(), t)["action"] == "wait"
    t, _ = gh([])
    assert decide(Git(), t) == {"action": "wait", "reason": "tests_running", "from": OLD, "to": NEW}
    t, _ = gh([{"head_sha": TESTED, "status": "completed", "conclusion": "failure"}])
    assert decide(Git(), t)["reason"] == "tests_failed"


def test_nothing_new_local_edits_or_a_split_branch_leave_everything_alone():
    t, seen = gh([])
    assert decide(Git({("rev-parse", "@{u}"): (0, OLD)}), t) == {"action": "none"}
    assert decide(Git({("status", "--porcelain", "--untracked-files=no"): (0, " M src/x.py")}), t)["reason"] == "local_changes"
    assert decide(Git({("merge-base", "--is-ancestor", "HEAD", "@{u}"): (1, "")}), t)["reason"] == "diverged"
    assert decide(Git({("rev-parse", "@{u}"): (128, "fatal: no upstream")}), t)["reason"] == "no_upstream"
    assert decide(Git({("fetch", "--quiet"): (1, "")}), t) == {"action": "wait", "reason": "fetch_failed"}
    assert seen == []
    # newer commits elsewhere in the repository only: nothing of BONELIA to test
    git = Git({("merge-base", "--is-ancestor", TESTED, "HEAD"): (0, "")})
    assert decide(git, t)["tests"] == "not_needed" and seen == []
    assert {EXIT[a] for a in ("none", "wait", "blocked")} >= {10, 11, 12} and EXIT["update"] == 0
    assert github_repo("git@github.com:tse3462/web-sablon.git") == "tse3462/web-sablon"


class Sent:
    def __init__(self):
        self.notes = []

    def self_update(self, note):
        self.notes.append(note)


def test_the_outcome_is_reported_once(tmp_path):
    store, sent = Store(tmp_path / "db.sqlite"), Sent()
    write_note(tmp_path, {"result": "rolled_back", "from": OLD, "to": NEW})
    assert report(store, tmp_path, sent)["result"] == "rolled_back" and len(sent.notes) == 1
    assert report(store, tmp_path, sent) is None and len(sent.notes) == 1
    (tmp_path / "last_update.json").write_text(json.dumps({"result": "rm -rf"}))
    assert take_note(tmp_path) is None


def test_notifier_words_and_the_cli(tmp_path, capsys):
    from bonelia.server.cli import main
    from bonelia.server.notify import Notifier

    class Ch:
        name, msgs = "t", []

        def send(self, title, body):
            self.msgs.append((title, body))
            return True
    ch = Ch()
    n = Notifier(Store(tmp_path / "n.sqlite"), [ch])
    n.self_update({"result": "ok", "from": OLD, "to": NEW})
    n.self_update({"result": "rolled_back", "from": OLD, "to": NEW})
    n.self_update({"result": "blocked", "reason": "tests_failed", "to": NEW})
    n.self_update({"result": "blocked", "reason": "tests_failed", "to": NEW})  # same commit: once
    assert len(ch.msgs) == 3 and "bbbbbbb" in ch.msgs[0][1] and "eski" in ch.msgs[1][1]
    assert main(["--data-dir", str(tmp_path), "update-note", "--result", "ok", "--from", OLD, "--to", NEW]) == 0
    assert take_note(tmp_path)["to"] == NEW


def test_the_scripts_use_it():
    upd = (ROOT / "deployment/windows/BONELIA-Server-Guncelle.bat").read_text(encoding="utf-8")
    for s in ('"/auto"', "update-check", "merge --ff-only", "rolled_back", "update-note", "BONELIA-Ajan-Onar.bat\" /auto"):
        assert s in upd, s
    onar = (ROOT / "deployment/windows/BONELIA-Ajan-Onar.bat").read_text(encoding="utf-8")
    assert "BONELIA AI Guncelle" in onar and "RepetitionInterval" in onar and '"/auto"' in onar
