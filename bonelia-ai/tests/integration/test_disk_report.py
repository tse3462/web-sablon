"""Disk report from the agent, history and alerts on the server, cleanup only as the owner picked it."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from bonelia.agent.agent import Agent, AgentState
from bonelia.server.dashboard import create_dashboard_app
from bonelia.server.disk_store import DiskStore
from bonelia.server.store import Store
from tests.integration.test_agent import FakePC
from tests.integration.test_server_e2e import env, usb  # noqa: F401  (fixture + helper)

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}
GB = 1024 ** 3


def report(free=12 * GB, total=237 * GB):
    return {"at": int(time.time()), "partial": False, "drives": [{"name": "C:\\", "total": total, "free": free}],
            "categories": [{"key": "temp", "kind": "safe", "bytes": 3 * GB}, {"key": "recycle", "kind": "safe", "bytes": GB},
                           {"key": "ai_models", "kind": "info", "bytes": 21 * GB}],
            "largest": [{"id": "d" * 16, "path": "C:\\Users\\anna\\Downloads", "bytes": 40 * GB, "deletable": False, "note": "folder",
                         "children": [{"id": "e" * 16, "path": "C:\\Users\\anna\\Downloads\\Alt", "bytes": 9 * GB, "deletable": True,
                                       "note": "", "children": []}]},
                        {"id": "f" * 16, "path": "C:\\Users\\anna\\AppData\\Local\\Docker", "bytes": 30 * GB, "deletable": False,
                         "note": "docker", "children": []}],
            "backup_drives": [{"name": "D:\\", "free": 400 * GB, "total": 931 * GB, "label": "YEDEK"}],
            "advice": [{"id": "e" * 16, "path": "C:\\Users\\anna\\Downloads\\Alt", "bytes": 9 * GB, "why": "unused", "days": 200, "last_write": 1}],
            "suggestions": [
                {"id": "a" * 16, "path": "C:\\Users\\anna\\Downloads\\shop-backup-2026-10-01.zip", "bytes": 3 * GB, "mtime": 1, "reason": "old_backup", "group": "shop backup"},
                {"id": "b" * 16, "path": "C:\\Users\\anna\\Downloads\\film (1).mp4", "bytes": 2 * GB, "mtime": 2, "reason": "duplicate", "group": "abc"},
            ]}


class FakeDisk:
    def __init__(self):
        self.scans = 0
        self.cleaned: list[dict] = []
        self.rep = report()

    def scan(self, progress=None):
        self.scans += 1
        if progress:
            progress(10); progress(60)
        return dict(self.rep)

    def clean(self, req, progress=None):
        if progress:
            progress(40)
        self.cleaned.append(req)
        return {"id": req["id"], "safe": {k: GB for k in req.get("safe", [])}, "files": [{"path": f["path"], "status": "deleted"} for f in req.get("files", [])],
                "freed": 3 * GB + GB * len(req.get("safe", []))}


def test_report_reaches_panel_and_cleanup_runs_only_as_picked(tmp_path, env):  # noqa: F811
    store = env["store"]
    store.update_tenant(env["a"], max_auto_level=1)
    dash = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)
    s = usb(tmp_path, env, "LAPTOP", env["a"], scopes=("diagnose", "repair:windows"))
    dev = s.creds.device_id
    pc, fd = FakePC(), FakeDisk()
    agent = Agent(s.client, AgentState(tmp_path / "d.json"), executors=pc.executors(), scan=pc.scan, maintenance_tools=(),
                  remote=lambda: None, disk_scan=fd.scan, disk_clean=fd.clean)
    agent.cycle()
    assert fd.scans == 1
    d = dash.get(f"/api/disk/{dev}").json()
    assert d["report"]["drives"][0]["free"] == 12 * GB and [h["free"] for h in d["history"]] == [12 * GB]
    assert dash.get("/api/overview").json()["devices"][-1]["disk"] == {"free": 12 * GB, "total": 237 * GB, "at": d["report"]["at"]}
    agent.cycle()
    assert fd.scans == 1  # once a day, not every cycle

    # Picking: only reported suggestions and safe categories; nothing else is accepted.
    assert dash.post(f"/api/disk/{dev}/clean", json={"safe": ["temp"], "items": ["z" * 16]}).status_code == 422
    assert dash.post(f"/api/disk/{dev}/clean", json={"safe": ["ai_models"], "items": []}).status_code == 422
    assert dash.post(f"/api/disk/{dev}/clean", json={"safe": [], "items": []}).status_code == 422
    r = dash.post(f"/api/disk/{dev}/clean", json={"safe": ["temp", "recycle"], "items": ["a" * 16]})
    assert r.status_code == 200 and r.json()["pending"]["files"] == 1
    agent.cycle()  # the heartbeat reply delivers the request ...
    agent.cycle()  # ... and the agent carries it out, then reports again
    assert len(fd.cleaned) == 1
    req = fd.cleaned[0]
    assert req["safe"] == ["temp", "recycle"]
    assert req["files"] == [{"path": "C:\\Users\\anna\\Downloads\\shop-backup-2026-10-01.zip", "bytes": 3 * GB, "mtime": 1}]
    d = dash.get(f"/api/disk/{dev}").json()
    assert d["pending"] is None and d["report"]["cleanup_result"]["freed"] == 5 * GB
    agent.cycle()
    assert len(fd.cleaned) == 1  # done once
    acts = [a["action"] for a in store.audit_log(env["a"])]
    assert "disk.cleanup_requested" in acts

    # "Scan now" in the panel: a fresh report on the next cycles, even within the day, with progress.
    v = dash.post(f"/api/disk/{dev}/scan").json()
    assert v["scan_pending"] is True and v["progress"] is None  # waiting for the PC to pick it up
    seen = []
    real = fd.scan

    def watched(progress=None):
        def spy(pct):
            progress(pct)
            seen.append(dash.get(f"/api/disk/{dev}").json()["progress"])
        return real(progress=spy)
    agent.disk_scan = watched
    agent.cycle(); agent.cycle()
    assert fd.scans >= 3
    assert [p["pct"] for p in seen] == [10, 60]  # the panel saw the bar move while the PC was scanning
    v = dash.get(f"/api/disk/{dev}").json()
    assert v["scan_pending"] is False and v["progress"] is None  # done: the new report is there


def test_no_cleanup_without_repair_consent(tmp_path, env):  # noqa: F811
    store = env["store"]
    store.update_tenant(env["a"], max_auto_level=0)
    dash = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)
    s = usb(tmp_path, env, "KASSE", env["a"], scopes=("diagnose", "repair:windows"))
    pc, fd = FakePC(), FakeDisk()
    Agent(s.client, AgentState(tmp_path / "k.json"), executors=pc.executors(), scan=pc.scan, maintenance_tools=(),
          remote=lambda: None, disk_scan=fd.scan, disk_clean=fd.clean).cycle()
    r = dash.post(f"/api/disk/{s.creds.device_id}/clean", json={"safe": ["temp"], "items": []})
    assert r.status_code == 409 and r.json()["detail"] == "consent_needed"
    assert dash.get("/api/disk/nope").status_code == 404


def test_alerts_low_space_and_a_big_drop(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    disks = DiskStore(store)
    t0 = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
    assert disks.accept("dev1", report(free=80 * GB), now=t0) == []
    alerts = disks.accept("dev1", report(free=60 * GB), now=t0 + timedelta(days=5))
    assert alerts == [("disk_drop", 20 * GB, 5)]
    alerts = disks.accept("dev1", report(free=12 * GB), now=t0 + timedelta(days=6))
    assert ("disk_low", 12 * GB, 237 * GB) in alerts
    # Garbage is trimmed, not stored.
    bad = report()
    bad["suggestions"] = [{"id": "x", "path": 5}] * 3 + bad["suggestions"]
    bad["evil"] = "x" * 10
    disks.accept("dev2", bad, now=t0)
    kept = disks.latest("dev2")
    assert "evil" not in kept and len(kept["suggestions"]) == 2


def test_a_folder_is_deleted_only_if_the_pc_marked_it_deletable(tmp_path, env):  # noqa: F811
    store = env["store"]
    store.update_tenant(env["a"], max_auto_level=1)
    dash = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)
    s = usb(tmp_path, env, "LAPTOP2", env["a"], scopes=("diagnose", "repair:windows"))
    dev = s.creds.device_id
    pc, fd = FakePC(), FakeDisk()
    agent = Agent(s.client, AgentState(tmp_path / "f.json"), executors=pc.executors(), scan=pc.scan, maintenance_tools=(),
                  remote=lambda: None, disk_scan=fd.scan, disk_clean=fd.clean)
    agent.cycle()
    largest = dash.get(f"/api/disk/{dev}").json()["report"]["largest"]
    assert largest[0]["children"][0]["deletable"] is True and largest[1]["note"] == "docker"
    for bad in ("d" * 16, "f" * 16, "0" * 16):  # Downloads itself, Docker, unknown
        assert dash.post(f"/api/disk/{dev}/clean", json={"folders": [bad]}).status_code == 422
    r = dash.post(f"/api/disk/{dev}/clean", json={"folders": ["e" * 16]})
    assert r.status_code == 200 and r.json()["pending"]["folders"] == 1 and r.json()["pending"]["bytes"] == 9 * GB
    agent.cycle(); agent.cycle()
    assert fd.cleaned[-1]["folders"] == [{"path": "C:\\Users\\anna\\Downloads\\Alt", "bytes": 9 * GB}]


def test_move_to_backup_drive_only_to_a_drive_the_pc_reported(tmp_path, env):  # noqa: F811
    store = env["store"]
    store.update_tenant(env["a"], max_auto_level=1)
    dash = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)
    s = usb(tmp_path, env, "LAPTOP3", env["a"], scopes=("diagnose", "repair:windows"))
    dev = s.creds.device_id
    pc, fd = FakePC(), FakeDisk()
    agent = Agent(s.client, AgentState(tmp_path / "m.json"), executors=pc.executors(), scan=pc.scan, maintenance_tools=(),
                  remote=lambda: None, disk_scan=fd.scan, disk_clean=fd.clean)
    agent.cycle()
    v = dash.get(f"/api/disk/{dev}").json()
    assert v["report"]["advice"][0]["why"] == "unused" and v["report"]["backup_drives"][0]["label"] == "YEDEK"
    assert dash.post(f"/api/disk/{dev}/clean", json={"moves": ["e" * 16], "drive": "Z:\\"}).status_code == 422
    assert dash.post(f"/api/disk/{dev}/clean", json={"moves": ["f" * 16], "drive": "D:\\"}).status_code == 422  # Docker: never
    r = dash.post(f"/api/disk/{dev}/clean", json={"moves": ["e" * 16], "drive": "D:\\"})
    assert r.status_code == 200 and r.json()["pending"]["moves"] == 1
    seen = []
    real = fd.clean

    def watched(req, progress=None):
        def spy(pct):
            progress(pct)
            seen.append(dash.get(f"/api/disk/{dev}").json()["pending"]["progress"])
        return real(req, progress=spy)
    agent.disk_clean = watched
    agent.cycle(); agent.cycle()
    assert fd.cleaned[-1]["moves"] == [{"path": "C:\\Users\\anna\\Downloads\\Alt", "bytes": 9 * GB, "drive": "D:\\"}]
    assert seen == [40]  # the panel saw how far the copy got
