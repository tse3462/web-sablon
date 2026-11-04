"""Unattended agent: detects, reports, self-repairs level-1 issues, never self-confirms level 2."""

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


def test_agent_self_repairs_level1_reports_and_does_not_self_confirm_level2(tmp_path, env):  # noqa: F811
    s = usb(tmp_path, env, "AGENT-PC1", env["a"], scopes=("diagnose", "repair:windows"))
    env["store"].update_tenant(env["a"], max_auto_level=2, auto_tools=["windows.start_service"])
    pc = FakePC()
    agent = Agent(s.client, AgentState(tmp_path / "state.json"), lang="tr", executors=pc.executors(), scan=pc.scan)

    first = agent.cycle()
    assert first["sent"] and first["new_findings"] == 2  # harmless noise is never reported
    by_tool = {r["tool_id"]: r for r in first["repairs"]}
    assert by_tool["windows.start_service"]["outcome"] == "executed_verified"  # fixed with nobody at the PC
    assert by_tool["windows.restart_service"]["outcome"] == "denied"  # level 2 needs a technician's click
    assert pc.calls == ["start:PosKasseSync"]

    second = agent.cycle()  # nothing new: no duplicate reports, no repeated repair, denied level 2 not retried
    assert second["new_findings"] == 0 and not second["sent"] and second["repairs"] == []
    assert pc.calls == ["start:PosKasseSync"]
    assert sum(1 for a in env["store"].audit_log(env["a"]) if a["action"] == "tool.denied") == 1

    actions = [a["action"] for a in env["store"].audit_log(env["a"])]
    assert "tool.executed" in actions and "tool.denied" in actions
    assert json.loads((tmp_path / "state.json").read_text())["cycles"] == 2


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
    assert creds.tenant_id == env["a"] and set(creds.scopes) == {"diagnose", "repair:windows"}
    assert creds.device_id != s.creds.device_id and creds.private_key != s.creds.private_key
    assert ServerClient(creds).health()["status"] == "ok"  # the agent has its own working identity
    assert "agent.enrolled_by_usb" in [a["action"] for a in env["store"].audit_log(env["a"])]
    plain = usb(tmp_path, env, "USB-PLAIN", env["a"], scopes=("diagnose",))
    with pytest.raises(ServerError) as e:
        plain.client.enroll_agent("x")
    assert e.value.status == 403  # only USBs allowed to install agents can do it
