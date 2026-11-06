"""Unattended agent: detects, reports, self-repairs within the customer's consent level."""

from __future__ import annotations

import json
import time

from bonelia.agent.agent import Agent, AgentState
from bonelia.contracts import AppIdentity, DiagnosticEvent, Evidence, ScanResult, Severity, SystemSnapshot, Triage
from bonelia.repair.tools import ExecResult
from tests.integration.test_server_e2e import env, usb  # noqa: F401  (fixture + helper)


FIXED = __import__("datetime").datetime(2026, 11, 4, 10, 0, tzinfo=__import__("datetime").timezone.utc)


def _ev(fp, title, triage, repair=None, params=None, source="windows_services"):
    return DiagnosticEvent(app=AppIdentity(app_id="x", name=title), title=title, fingerprint=fp, severity=Severity.error,
                           occurred_at=FIXED,
                           triage=triage, repair_tool=repair, repair_params=params or {},
                           evidence=[Evidence(source=source, kind="state", code="BONELIA:services/0")])


class FakePC:
    """A customer PC: one service keeps stopping, one service crashes repeatedly, plus routine noise."""

    def __init__(self):
        self.sync_running = False
        self.calls: list[str] = []

    def scan(self, **kw):
        events = [_ev("noise", "Win32k 700", Triage.harmless),
                  _ev("crash", "Druckwarteschlange abgestürzt", Triage.important, "windows.restart_service",
                      {"service_name": "Spooler"}, source="windows_event_log:System")]
        if not self.sync_running:
            events.insert(0, _ev("svc", "Hizmet durmuş: PosKasse Sync", Triage.important, "windows.start_service",
                                 {"service_name": "PosKasseSync"}))
        return ScanResult(system=SystemSnapshot(hostname_ref="ref_pc", os="Windows", os_version="11"), events=events)

    def executors(self):
        def start(p, d):
            self.calls.append(f"start:{p['service_name']}")
            self.sync_running = True
            return ExecResult(True, {})

        def restart(p, d):
            self.calls.append(f"restart:{p['service_name']}")
            return ExecResult(True, {})

        return {"windows.start_service": (start, lambda p, r: self.sync_running),
                "windows.restart_service": (restart, lambda p, r: True)}


class FakePCWithCleanup(FakePC):
    """Same PC, but the temp-file cleaner is wired up (as it is on a real Windows client)."""

    def executors(self):
        ex = super().executors()

        def clean(p, d):
            self.calls.append("clean_temp")
            return ExecResult(True, {"files": 3, "freed_mb": 12.0})

        ex["windows.clean_temp"] = (clean, lambda p, r: True)
        return ex


def test_agent_level1_repairs_and_level2_needs_level2_consent(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-PC1", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=["windows.start_service"])
    pc = FakePC()
    agent = Agent(s.client, AgentState(tmp_path / "state.json"), lang="tr", executors=pc.executors(), scan=pc.scan)

    first = agent.cycle()
    assert first["sent"] and first["new_findings"] == 2  # harmless noise is never reported
    by_tool = {r["tool_id"]: r for r in first["repairs"]}
    assert by_tool["windows.start_service"]["outcome"] == "executed_verified"  # fixed with nobody at the PC
    assert by_tool["windows.restart_service"]["outcome"] == "denied"  # customer allowed only level 1
    assert pc.calls == ["start:PosKasseSync"]

    second = agent.cycle()  # nothing new: no duplicate reports, no repeated repair, denied not retried
    assert second["new_findings"] == 0 and not second["sent"] and second["repairs"] == []
    assert pc.calls == ["start:PosKasseSync"]
    assert sum(1 for a in env["store"].audit_log(env["a"]) if a["action"] == "tool.denied") == 1
    assert json.loads((tmp_path / "state.json").read_text())["cycles"] == 2


def test_agent_runs_routine_disk_cleanup_on_a_schedule(tmp_path, env):  # noqa: F811
    """Unattended "the computer cleans its own disk": a daily temp-file cleanup that runs
    on a schedule, not only when the disk is already full."""
    s = usb(tmp_path, env, "AGENT-MNT", env["a"], scopes=("diagnose", "repair:windows"))
    # consent given at level 1 before clean_temp was ever listed: the vetted safe tool is still covered
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=["windows.start_service"])
    pc = FakePCWithCleanup()
    state = AgentState(tmp_path / "m.json")
    agent = Agent(s.client, state, executors=pc.executors(), scan=pc.scan)

    first = agent.cycle()
    mnt = [r for r in first["repairs"] if r.get("maintenance")]
    assert len(mnt) == 1 and mnt[0]["tool_id"] == "windows.clean_temp"
    assert mnt[0]["outcome"] == "executed_verified"  # ran unattended, nobody at the PC
    assert pc.calls.count("clean_temp") == 1
    assert state.data["last_maintenance"] > 0

    second = agent.cycle()  # within the interval: housekeeping is not repeated
    assert [r for r in second["repairs"] if r.get("maintenance")] == []
    assert pc.calls.count("clean_temp") == 1

    state.data["last_maintenance"] = 0  # a day later
    state.save()
    third = agent.cycle()
    assert [r for r in third["repairs"] if r.get("maintenance")]  # the schedule triggers the pass again
    assert state.data["last_maintenance"] > 0  # and the clock is reset for the next day


def test_routine_disk_cleanup_needs_customer_consent(tmp_path, env):  # noqa: F811
    """No per-click approval, but still no action without the customer's one-time consent."""
    s = usb(tmp_path, env, "AGENT-MNT2", env["a"], scopes=("diagnose", "repair:windows"))
    pc = FakePCWithCleanup()  # tenant left at the default read-only level
    out = Agent(s.client, AgentState(tmp_path / "m2.json"), executors=pc.executors(), scan=pc.scan).cycle()
    mnt = [r for r in out["repairs"] if r.get("maintenance")]
    assert len(mnt) == 1 and mnt[0]["outcome"] == "denied"
    assert "clean_temp" not in pc.calls  # never executed without consent


def test_agent_level2_restarts_crashed_service_once_per_crash(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-PC4", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=2, auto_tools=["windows.start_service"])
    pc = FakePC()
    agent = Agent(s.client, AgentState(tmp_path / "state.json"), executors=pc.executors(), scan=pc.scan,
                  maintenance_tools=())  # this test isolates finding-driven repairs; see maintenance tests below
    out = agent.cycle()
    assert {r["tool_id"]: r["outcome"] for r in out["repairs"]} == {
        "windows.start_service": "executed_verified", "windows.restart_service": "executed_verified"}
    agent.cycle()  # the same crash entry is still in the last hour of the log: no second restart
    assert pc.calls.count("restart:Spooler") == 1


def test_agent_without_server_repairs_nothing_and_survives(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-PC2", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=["windows.start_service"])
    pc = FakePC()
    env["srv"].__exit__(None, None, None)  # home server unreachable
    out = Agent(s.client, AgentState(tmp_path / "s.json"), executors=pc.executors(), scan=pc.scan).cycle()
    assert out["offline"] and pc.calls == []


def test_agent_needs_customer_consent(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-PC3", env["a"], scopes=("diagnose", "repair:windows"))
    pc = FakePC()  # tenant left at the default read-only level
    out = Agent(s.client, AgentState(tmp_path / "s.json"), executors=pc.executors(), scan=pc.scan).cycle()
    assert pc.calls == [] and all(r["outcome"] == "denied" for r in out["repairs"])


def test_one_click_agent_install_authorised_by_the_usb(tmp_path, env):  # noqa: F811
    """No enrollment code on site: an authorised USB enrolls the PC's agent into the same customer."""
    import pytest

    from bonelia.monitor.client import ServerClient, ServerError

    s = usb(tmp_path, env, "USB-OWNER", env["a"], scopes=("diagnose", "install:agent"))
    creds = s.client.enroll_agent("Kasse 1 - Filiale Ehrenfeld")
    assert creds.tenant_id == env["a"] and set(creds.scopes) == {"agent", "repair:windows"}
    assert creds.device_id != s.creds.device_id and creds.private_key != s.creds.private_key
    assert ServerClient(creds).health()["status"] == "ok"  # the agent has its own working identity
    assert "agent.enrolled_by_usb" in [a["action"] for a in env["store"].audit_log(env["a"])]
    plain = usb(tmp_path, env, "USB-PLAIN", env["a"], scopes=("diagnose",))
    with pytest.raises(ServerError) as e:
        plain.client.enroll_agent("x")
    assert e.value.status == 403  # only USBs allowed to install agents can do it


def test_install_key_allows_silent_installs_but_nothing_else(tmp_path, env):  # noqa: F811
    """The key stored unencrypted on the USB can only enroll agents; agents cannot read customer data."""
    import pytest

    from bonelia.monitor.client import ServerClient, ServerError

    full = usb(tmp_path, env, "USB-OWNER", env["a"], scopes=("diagnose", "install:agent"))
    ik = ServerClient(full.client.create_install_key("Install key"))
    assert ik.creds.scopes == ["install:agent"]
    agent = ServerClient(ik.enroll_agent("Kasse 2"))  # silent install path
    assert set(agent.creds.scopes) == {"agent", "repair:windows"}
    for call in (lambda: ik.events(), lambda: ik.chat("x", "tr"), lambda: ik.create_install_key("again"),
                 lambda: agent.events(), lambda: agent.chat("x", "tr"), lambda: agent.create_install_key("x"),
                 lambda: agent.enroll_agent("x")):
        with pytest.raises(ServerError) as e:
            call()
        assert e.value.status == 403
    assert agent.analyze([], None, False, "tr").diagnoses == []  # agents may report findings
    # a lost USB: revoke the install key -> no more installs, existing agents keep working
    env["store"].revoke_device(ik.creds.device_id)
    with pytest.raises(ServerError):
        ik.enroll_agent("Kasse 3")
    assert agent.health()["status"] == "ok"


def test_usb_asks_password_only_the_first_time(tmp_path, env, monkeypatch):  # noqa: F811
    import argparse

    import bonelia.monitor.cli as cli

    full = usb(tmp_path, env, "USB-OWNER", env["a"], scopes=("diagnose", "install:agent"))
    args = argparse.Namespace(home=str(full.home.root), lang="tr", ca=None, server=None, no_install_key=False)
    monkeypatch.setattr(cli, "_passphrase", lambda confirm=False: "test passphrase 123")
    first = cli._enroll_agent_from_usb(args, "PC-1")
    assert first and (full.home.root / "config" / "install.key").is_file()

    def no_password(confirm=False):
        raise AssertionError("password must not be asked again")

    monkeypatch.setattr(cli, "_passphrase", no_password)
    second = cli._enroll_agent_from_usb(args, "PC-2")
    assert second.device_id != first.device_id and second.tenant_id == env["a"]
    # agents can be pointed at the home server's Tailscale address
    args.server = "http://100.101.102.103:8742"
    assert cli._enroll_agent_from_usb(args, "PC-3").server_url == "http://100.101.102.103:8742"


def test_agent_heartbeat_and_vetted_safe_tools_covered_by_level1(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-HB", env["a"], scopes=("diagnose", "repair:windows"))
    # consent given before new safe tools existed: auto_tools lists only start_service
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=["windows.start_service"])
    g = s.client.authorize_tool("windows.flush_dns", {})
    assert g["allowed"] and g["grant_id"]  # vetted built-in safe tool is covered by the level-1 consent
    pc = FakePC()
    Agent(s.client, AgentState(tmp_path / "hb.json"), executors=pc.executors(), scan=pc.scan).cycle()
    dev = env["store"].device(s.creds.device_id)
    assert dev["last_seen_at"] and '"cycles": 1' in (dev["last_status"] or "")


def _publish(env, data: bytes, key=None):
    import hashlib

    from bonelia.security.crypto import sign_update

    d = env["cfg"].data_dir / "agent_update"
    d.mkdir(parents=True, exist_ok=True)
    (d / "BoneliaAI-Agent.exe").write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    (d / "manifest.json").write_text(json.dumps({"sha256": sha, "size": len(data),
                                                 "signature": sign_update(key or env["key"], sha, len(data))}))


def test_agent_self_update_only_accepts_server_signed_programs(tmp_path, env):  # noqa: F811
    import pytest

    from bonelia.monitor.client import ServerClient, ServerError
    from bonelia.security import crypto

    owner = usb(tmp_path, env, "USB-OWNER", env["a"], scopes=("diagnose", "install:agent"))
    agent_client = ServerClient(owner.client.enroll_agent("KASSE-1"))
    own = tmp_path / "BoneliaAI-Agent.exe"
    own.write_bytes(b"agent v1")
    agent = Agent(agent_client, AgentState(tmp_path / "s.json"))
    applied = []
    apply = lambda p: (applied.append(p.read_bytes()) or True, "ok")  # noqa: E731

    assert agent.check_update(own, apply) == {"update": "none_published"}
    _publish(env, b"agent v1")
    assert agent.check_update(own, apply) == {"update": "up_to_date"}
    _publish(env, b"agent v2")
    assert agent.check_update(own, apply)["update"] == "scheduled" and applied == [b"agent v2"]
    # a forged update (signed by another key) is refused before anything is downloaded or installed
    _publish(env, b"evil program", key=crypto.generate_keypair())
    with pytest.raises(ValueError):
        agent.check_update(own, apply)
    assert applied == [b"agent v2"]
    # only agents may download the agent program
    with pytest.raises(ServerError) as e:
        owner.client.agent_update_info()
    assert e.value.status == 403


def test_publish_agent_command(tmp_path):
    import os
    import subprocess
    import sys

    exe = tmp_path / "BoneliaAI-Konsol.exe"
    exe.write_bytes(b"MZ new agent")
    p = subprocess.run([sys.executable, "-m", "bonelia.server.cli", "--data-dir", str(tmp_path / "d"), "publish-agent", str(exe)],
                       capture_output=True, text=True, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert p.returncode == 0, p.stderr
    m = json.loads((tmp_path / "d" / "agent_update" / "manifest.json").read_text())
    assert m["size"] == len(b"MZ new agent") and m["signature"]


def test_backup_policy_from_the_panel_reaches_the_agent(tmp_path, env):  # noqa: F811
    """Owner sets a backup folder in the panel -> heartbeat reply -> next scan checks it."""
    s = usb(tmp_path, env, "AGENT-POL", env["a"], scopes=("diagnose", "repair:windows"))
    calls: list[dict] = []

    def scan(**kw):
        calls.append(kw)
        return ScanResult(system=SystemSnapshot(hostname_ref="ref_pc", os="Windows", os_version="11"), events=[])

    agent = Agent(s.client, AgentState(tmp_path / "p.json"), scan=scan, maintenance_tools=())
    agent.cycle()
    assert calls[-1]["backup_policy"] is None  # nothing configured yet
    pol = {"backup": {"paths": ["D:\\Kasa\\Yedek"], "max_age_days": 3}}
    assert env["store"].set_device_policy(s.creds.device_id, pol)
    agent.cycle()  # heartbeat reply delivers the policy ...
    assert agent.state.data["policy"] == pol
    agent.cycle()  # ... and the next scan uses it
    assert calls[-1]["backup_policy"] == pol["backup"]
    assert "device.policy_changed" in [a["action"] for a in env["store"].audit_log(env["a"])]


def test_solved_problem_that_returns_is_reported_again(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-RE", env["a"], scopes=("diagnose", "repair:windows"))
    present = {"on": True}

    def scan(**kw):
        evs = [_ev("bak", "Yedek eski: D:\\Yedek", Triage.important, source="backup_check")] if present["on"] else []
        return ScanResult(system=SystemSnapshot(hostname_ref="ref_pc", os="Windows", os_version="11"), events=evs)

    agent = Agent(s.client, AgentState(tmp_path / "r.json"), scan=scan, maintenance_tools=())
    assert agent.cycle()["new_findings"] == 1
    assert agent.cycle()["new_findings"] == 0  # still the same problem: no repeat
    present["on"] = False
    assert agent.cycle()["new_findings"] == 0  # solved
    present["on"] = True
    assert agent.cycle()["new_findings"] == 1  # it came back -> reported again


def test_upgrade_keeps_already_reported_states_quiet(tmp_path, env):  # noqa: F811
    """An older agent state (no 'states' list yet) must not re-report everything after the update."""
    s = usb(tmp_path, env, "AGENT-UPG", env["a"], scopes=("diagnose", "repair:windows"))
    p = tmp_path / "u.json"
    p.write_text(json.dumps({"salt": "x", "seen": {"bak": FIXED.isoformat()}, "cycles": 7}))

    def scan(**kw):
        return ScanResult(system=SystemSnapshot(hostname_ref="ref_pc", os="Windows", os_version="11"),
                          events=[_ev("bak", "Yedek eski", Triage.important, source="backup_check")])

    assert Agent(s.client, AgentState(p), scan=scan, maintenance_tools=()).cycle()["new_findings"] == 0


def test_rate_limited_cleanup_is_retried_in_an_hour_not_tomorrow(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-RL", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=["windows.start_service"])
    env["store"].record_tool_run(env["a"], "windows.clean_temp")  # e.g. another agent instance just cleaned
    pc = FakePCWithCleanup()
    state = AgentState(tmp_path / "rl.json")
    out = Agent(s.client, state, executors=pc.executors(), scan=pc.scan).cycle()
    mnt = [r for r in out["repairs"] if r.get("maintenance")]
    assert mnt[0]["outcome"] == "denied" and "rate_limited" in mnt[0]["reasons"] and "clean_temp" not in pc.calls
    wait = state.data["last_maintenance"] + 24 * 3600 - time.time()
    assert 3500 < wait <= 3600  # next attempt in about an hour


def test_rustdesk_id_reaches_the_panel_and_nothing_else_slips_through(tmp_path, env):  # noqa: F811
    """The ID gets its own checked field: the general clean-up would otherwise hide it as [number]."""
    s = usb(tmp_path, env, "AGENT-RD", env["a"], scopes=("diagnose", "repair:windows"))
    pc = FakePC()
    agent = Agent(s.client, AgentState(tmp_path / "rd.json"), executors=pc.executors(), scan=pc.scan,
                  remote=lambda: {"installed": True, "rustdesk_id": "123456789", "service": "running"})
    agent.cycle()
    status = json.loads(env["store"].device(s.creds.device_id)["last_status"])
    assert status["remote"] == {"installed": True, "rustdesk_id": "123456789", "service": "running"}
    s.client.heartbeat({"cycles": 2, "remote": {"installed": True, "rustdesk_id": "123; rm -rf /", "service": "<b>x</b>"}})
    status = json.loads(env["store"].device(s.creds.device_id)["last_status"])
    assert status["remote"] == {"installed": True, "rustdesk_id": None, "service": "unknown"}


def test_agent_retries_within_a_minute_while_the_server_is_unreachable():
    """Seen 06.11.2026 after a restart: the agent came up before the server and stayed silent for 5-minute rounds."""
    from bonelia.agent.agent import pause_after
    assert pause_after({"offline": True}, 300) == 60
    assert pause_after({"offline": False}, 300) == 300
    assert pause_after(None, 300) == 60  # a failed cycle is retried soon, too


class FrozenPC:
    """A PC where the till program hangs and the browser eats the memory (user request 06.11.2026)."""

    def __init__(self):
        self.t = 2_000_000.0
        self.calls: list[str] = []
        self.procs = [{"pid": 10, "name": "Kasse.exe", "mb": 400, "hung": True, "started": 1.0},
                      {"pid": 11, "name": "chrome.exe", "mb": 5200, "hung": False, "started": 2.0}]
        self.mem = 95.0

    def probe(self):
        return {"mem_pct": self.mem, "total_mb": 8000, "procs": [dict(p) for p in self.procs]}

    def executors(self):
        def restart(p, d):
            self.calls.append(f"restart:{p['name']}")
            self.procs[0]["hung"] = False
            return ExecResult(True, {"before": "hung", "after": "restarted", "new_pid": 20})

        def close(p, d):
            self.calls.append(f"close:{p['name']}:{p.get('restart')}")
            return ExecResult(True, {"before": "open", "after": "reopened" if p.get("restart") else "closed", "new_pid": 21})

        return {"windows.restart_hung_app": (restart, lambda p, r: True), "windows.close_program": (close, lambda p, r: True)}


def _empty_scan(**kw):
    return ScanResult(system=SystemSnapshot(hostname_ref="ref_pc", os="Windows", os_version="11"), events=[])


def test_agent_restarts_a_frozen_program_and_frees_memory_by_itself(tmp_path, env):  # noqa: F811
    from bonelia.agent.rescue import HUNG_AFTER_S, MEM_HIGH_FOR_S

    s = usb(tmp_path, env, "AGENT-RESCUE", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=["windows.start_service"])  # older level-1 consent
    pc = FrozenPC()
    agent = Agent(s.client, AgentState(tmp_path / "r.json"), executors=pc.executors(), scan=_empty_scan, maintenance_tools=(),
                  rescue_probe=pc.probe, rescue_clock=lambda: pc.t)
    agent.rescue_tick()
    pc.t += max(HUNG_AFTER_S, MEM_HIGH_FOR_S) + 1
    agent.rescue_tick()
    assert pc.calls == ["restart:Kasse.exe", "close:chrome.exe:True"]
    runs = [a for a in env["store"].audit_log(env["a"]) if a["action"] == "tool.executed"]
    assert {json.loads(a["detail"])["tool_id"] for a in runs} >= {"windows.restart_hung_app", "windows.close_program"}
    agent.cycle()  # the heartbeat carries memory, biggest programs and what was done to the panel
    st = json.loads(env["store"].device(s.creds.device_id)["last_status"])["rescue"]
    assert st["mem_pct"] == 95.0 and st["top"][0] == {"pid": 11, "name": "chrome.exe", "mb": 5200}
    assert [e["kind"] for e in st["events"]] == ["hung", "memory"] and st["events"][0]["outcome"] == "executed_verified"


def test_rescue_settings_and_close_request_from_the_panel_reach_the_agent(tmp_path, env):  # noqa: F811
    from bonelia.agent.rescue import HUNG_AFTER_S

    s = usb(tmp_path, env, "AGENT-RESCUE2", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=1, auto_tools=[])
    env["store"].set_setting("rescue_settings", {"hung": False, "memory": True})
    pc = FrozenPC()
    pc.mem = 50.0
    agent = Agent(s.client, AgentState(tmp_path / "r2.json"), executors=pc.executors(), scan=_empty_scan, maintenance_tools=(),
                  rescue_probe=pc.probe, rescue_clock=lambda: pc.t)
    agent.cycle()  # heartbeat reply: the owner switched "restart frozen programs" off
    assert agent.state.data["rescue_settings"] == {"hung": False, "memory": True}
    agent.rescue_tick()
    pc.t += HUNG_AFTER_S + 1
    agent.rescue_tick()
    assert pc.calls == []
    env["store"].set_device_policy(s.creds.device_id, {"close_request": {"id": "r1", "pid": 11, "name": "chrome.exe", "restart": False}})
    agent.cycle()
    agent.rescue_tick()
    assert pc.calls == ["close:chrome.exe:False"]
    agent.cycle()  # reported as done -> the server drops the request
    assert "close_request" not in env["store"].device_policy(s.creds.device_id)
