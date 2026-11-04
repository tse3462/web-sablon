"""Unattended agent: detects, reports, self-repairs within the customer's consent level."""

from __future__ import annotations

import json

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


def test_agent_level2_restarts_crashed_service_once_per_crash(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-PC4", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=2, auto_tools=["windows.start_service"])
    pc = FakePC()
    agent = Agent(s.client, AgentState(tmp_path / "state.json"), executors=pc.executors(), scan=pc.scan)
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
