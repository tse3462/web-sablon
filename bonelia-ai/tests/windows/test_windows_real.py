"""Tests that only prove something on a REAL Windows host (GitHub windows-latest runner or a test PC)."""

import subprocess
import sys

import pytest

pytestmark = [pytest.mark.windows, pytest.mark.skipif(sys.platform != "win32", reason="requires real Windows")]


def test_real_event_log_is_readable():
    from bonelia.collectors.windows_events import collect

    events, status = collect(hours=24 * 7, max_events=50)
    assert status["eventlog:Application"].startswith("ok:"), status
    assert status["eventlog:System"].startswith("ok:"), status
    assert all(e.event_id >= 0 for e in events)


def test_controlled_error_is_detected_in_event_log():
    from bonelia.collectors.windows_events import collect
    from bonelia.diagnostics.engine import event_from_raw

    from tests.conftest import write_test_event

    write_test_event("BoneliaAIWinTest", 998, "BONELIA AI windows test error mail test@example.com")
    events, _ = collect(hours=1, logs=("Application",), max_events=100)
    hit = [e for e in events if e.provider == "BoneliaAIWinTest" and e.event_id == 998]
    assert hit, "controlled event not found"
    ev = event_from_raw(hit[0], "tr")
    assert ev is not None and "test@example.com" not in ev.evidence[0].text


def test_installed_apps_and_services():
    from bonelia.collectors.system import installed_apps, services

    apps, st = installed_apps()
    assert st.startswith("ok:") and apps
    svcs, st2 = services()
    assert st2.startswith("ok:") and any(s["name"].lower() == "eventlog" for s in svcs)


def test_security_log_is_never_read():
    from bonelia.collectors.windows_events import collect

    _, status = collect(hours=1, logs=("Security",))
    assert status["eventlog:Security"] == "denied:not_allowed"


def test_full_scan_on_windows():
    from bonelia.monitor.scan import run_scan

    res = run_scan(mode="quick", salt="s", lang="de")
    assert res.system.is_windows and res.collector_status["installed_apps"].startswith("ok:")


def test_german_umlauts_survive_event_log_reading():
    """Regression (owner's German Windows): 'Gerätezuordnung' was read as 'Ger�tezuordnung'."""
    from bonelia.collectors.windows_events import collect

    from tests.conftest import write_test_event

    write_test_event("BoneliaAIUmlaut", 996, "Fehler bei der Gerätezuordnung: Größe Ä Ö Ü ß")
    events, status = collect(hours=1, logs=("Application",), max_events=100)
    assert status["eventlog:Application"].startswith("ok:"), status
    hit = [e for e in events if e.provider == "BoneliaAIUmlaut"]
    assert hit and "Gerätezuordnung" in hit[0].message and "�" not in hit[0].message, hit[0].message if hit else events[:3]


def test_start_and_restart_a_real_windows_service():
    """Real repair on real Windows: stop the print spooler, start it with the tool, verify independently."""
    import time

    import psutil

    from bonelia.repair import windows_tools as wt

    name = "Spooler"
    try:
        psutil.win_service_get(name)
    except Exception:
        pytest.skip("print spooler not present on this host")
    subprocess.run(["sc", "stop", name], capture_output=True)
    for _ in range(30):
        if psutil.win_service_get(name).status() == "stopped":
            break
        time.sleep(0.5)
    assert psutil.win_service_get(name).status() == "stopped"
    res = wt.start_service({"service_name": name}, False)
    assert res.ok, res.detail
    assert wt.verify_running({"service_name": name}, res), res.detail
    res = wt.restart_service({"service_name": name}, False)
    assert res.ok, res.detail
    assert wt.verify_running({"service_name": name}, res), res.detail


def test_real_scan_has_triage_and_service_state():
    from bonelia.monitor.scan import run_scan

    res = run_scan(mode="quick", salt="s", lang="tr")
    assert res.collector_status["services"].startswith("ok:")
    assert all(e.triage_reason for e in res.events)


def test_agent_install_self_repair_and_uninstall_on_real_windows(tmp_path, monkeypatch):
    """Install the agent (DPAPI + SYSTEM task), let one cycle repair a really stopped service, uninstall."""
    import json
    import os
    import sys
    import time

    import psutil

    from bonelia.security import crypto
    from bonelia.server.app import create_app
    from bonelia.server.config import ServerConfig
    from bonelia.server.store import Store
    from tests.conftest import ServerThread

    cfg = ServerConfig(data_dir=tmp_path / "srv", ollama_url=None)
    cfg.data_dir.mkdir()
    store = Store(cfg.db_path)
    tenant = store.create_tenant("Agent test")
    store.update_tenant(tenant, max_auto_level=1, auto_tools=["windows.start_service"], production_writes_allowed=1)
    code = store.create_enrollment_code(tenant, ["diagnose", "repair:windows"])
    env = {**os.environ, "BONELIA_AGENT_DIR": str(tmp_path / "agent"), "PYTHONIOENCODING": "utf-8"}
    with ServerThread(create_app(cfg, store=store, adapters={}, server_key=crypto.generate_keypair())) as srv:
        p = subprocess.run([sys.executable, "-m", "bonelia", "agent-install", "--server", srv.url, "--code", code, "--yes",
                            "--no-start"], capture_output=True, text=True, env=env, timeout=120)
        try:
            assert p.returncode == 0, p.stderr + p.stdout
            raw = (tmp_path / "agent" / "agent.cred").read_bytes()
            assert b"device_id" not in raw and b"private_key" not in raw  # DPAPI-protected
            assert subprocess.run(["schtasks", "/Query", "/TN", "BONELIA AI Agent"], capture_output=True).returncode == 0

            # a service that should run automatically is stopped -> the agent fixes it on its own
            subprocess.run(["sc", "config", "Spooler", "start=", "auto"], capture_output=True)
            subprocess.run(["sc", "stop", "Spooler"], capture_output=True)
            for _ in range(30):
                if psutil.win_service_get("Spooler").status() == "stopped":
                    break
                time.sleep(0.5)
            c = subprocess.run([sys.executable, "-m", "bonelia", "agent", "--once"], capture_output=True, text=True,
                               env=env, timeout=600)
            assert c.returncode == 0, c.stderr
            out = json.loads(c.stdout)
            fixed = [r for r in out["repairs"] if r["tool_id"] == "windows.start_service" and r["params"] == {"service_name": "Spooler"}]
            assert fixed and fixed[0]["outcome"] == "executed_verified", out
            assert psutil.win_service_get("Spooler").status() == "running"
            assert "tool.executed" in [a["action"] for a in store.audit_log(tenant)]
        finally:
            u = subprocess.run([sys.executable, "-m", "bonelia", "agent-uninstall"], capture_output=True, text=True, env=env, timeout=120)
    assert u.returncode == 0, u.stderr
    assert subprocess.run(["schtasks", "/Query", "/TN", "BONELIA AI Agent"], capture_output=True).returncode != 0
    assert not (tmp_path / "agent" / "agent.cred").exists()
