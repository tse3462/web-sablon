"""End-to-end through the real command-line programs (server CLI + monitor CLI).

On Windows CI this additionally writes a REAL, controlled error into the Windows
Application event log (eventcreate) and checks that the portable monitor finds it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from tests.conftest import free_port

PY = sys.executable
PASS = "e2e passphrase 1234"


def run(args, env, check=True, timeout=120):
    p = subprocess.run([PY, *args], capture_output=True, text=True, env=env, timeout=timeout, encoding="utf-8")
    if check and p.returncode != 0:
        raise AssertionError(f"{args} failed ({p.returncode}):\n{p.stdout}\n{p.stderr}")
    return p


@pytest.fixture
def server(tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    data = tmp_path / "srv"
    cfg = tmp_path / "server.toml"
    cfg.write_text(f'[server]\ndata_dir = "{data.as_posix()}"\n[ai]\nollama_url = "http://127.0.0.1:{free_port()}"\n', encoding="utf-8")
    port = free_port()
    proc = subprocess.Popen([PY, "-m", "bonelia.server.cli", "--config", str(cfg), "serve", "--port", str(port)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{url}/v1/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError(proc.stdout.read().decode(errors="replace"))
    yield {"url": url, "cfg": cfg, "env": env}
    proc.terminate()
    proc.wait(timeout=10)


def test_cli_enroll_scan_analyze(tmp_path, server):
    env = {**server["env"], "BONELIA_PASSPHRASE": PASS}
    srv = ["-m", "bonelia.server.cli", "--config", str(server["cfg"])]
    tenant = run([*srv, "tenant-add", "Pilot Kunde"], env).stdout.strip()
    code = run([*srv, "enroll-code", tenant, "--scopes", "diagnose"], env).stdout.strip()
    usb = tmp_path / "BONELIA-AI-Portable"
    mon = ["-m", "bonelia", "--home", str(usb), "--lang", "de"]
    out = json.loads(run([*mon, "enroll", "--server", server["url"], "--code", code, "--label", "USB 05"], env).stdout)
    assert out["tenant_id"] == tenant and (usb / "config" / "device.vault").is_file()

    log = tmp_path / "app.log"
    log.write_text("2026-11-04 ERROR Verbindung zum Server abgelehnt (connection refused) kunde@example.de\n", encoding="utf-8")
    controlled_source = None
    if sys.platform == "win32":
        controlled_source = "BoneliaAITest"
        from tests.conftest import write_test_event

        write_test_event(controlled_source, 999, "BONELIA AI controlled test error: export failed (connection refused)")
    rep = json.loads(run([*mon, "analyze", "--mode", "recent", "--log", str(log), "--json"], env).stdout)
    assert rep["customer_ref"] == tenant and rep["ai_mode"] in ("rules", "rules+cache", "cache+rules")
    assert any("connection refused" in f["evidence"][0]["text"] for f in rep["findings"])
    assert "kunde@example.de" not in json.dumps(rep)
    assert any("KI-Modell nicht verfügbar" in n for n in rep["notices"])  # no model configured => stated honestly
    if controlled_source:
        assert any(controlled_source in (f["evidence"][0]["code"] or "") for f in rep["findings"]), rep["checks_performed"]
        assert rep["checks_performed"]["eventlog:Application"].startswith("ok:")

    status = json.loads(run([*mon, "status"], env).stdout)
    assert status["server"]["connected"] is True

    devices = json.loads(run([*srv, "devices"], env).stdout)
    run([*srv, "revoke", devices[0]["id"]], env)
    revoked = run([*mon, "tools"], env, check=False)
    assert revoked.returncode == 4 and "device_revoked" in revoked.stderr
    assert "audit chain OK" in run([*srv, "audit", "--verify"], env).stdout


def test_server_refuses_public_bind_without_tls(tmp_path):
    env = {**os.environ}
    p = run(["-m", "bonelia.server.cli", "--data-dir", str(tmp_path / "d"), "serve", "--host", "0.0.0.0"], env, check=False, timeout=30)
    assert p.returncode == 2 and "TLS" in p.stderr


def test_hw_check_outputs_recommendation(tmp_path):
    out = json.loads(run(["-m", "bonelia.server.cli", "--data-dir", str(tmp_path), "hw-check"], {**os.environ}).stdout)
    assert out["recommended_local_model"] and "not guaranteed" in out["disclaimer"]


def test_build_script_imports_and_parses_arguments():
    """Guards the release script against API renames (it is only executed in the Windows CI job)."""
    root = Path(__file__).resolve().parents[2]
    p = subprocess.run([PY, str(root / "scripts" / "build_portable.py"), "--help"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr


def test_enroll_with_placeholder_code_gives_friendly_message(tmp_path):
    """Regression (seen in the owner's first real USB test): a typo printed a Python traceback."""
    p = run(["-m", "bonelia", "--home", str(tmp_path / "usb"), "enroll", "--server", "http://127.0.0.1:9",
             "--code", "KODUNUZ", "--label", "USB 01"], {**os.environ, "PYTHONIOENCODING": "utf-8"}, check=False)
    assert p.returncode == 2 and "Traceback" not in p.stderr and "ABCD-EFGH" in p.stderr
    p = run(["-m", "bonelia", "--home", str(tmp_path / "usb"), "enroll", "--server", "http://127.0.0.1:9",
             "--code", "AAAA-BBBB-CCCC-DDDD-EEEE", "--label", "USB 01"], {**os.environ, "PYTHONIOENCODING": "utf-8"}, check=False)
    assert p.returncode == 3 and "Traceback" not in p.stderr


def test_allow_repairs_and_device_scopes_commands(tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    srv = ["-m", "bonelia.server.cli", "--data-dir", str(tmp_path / "d")]
    tenant = run([*srv, "tenant-add", "Kunde"], env).stdout.strip()
    out = json.loads(run([*srv, "allow-repairs", tenant, "--level", "1"], env).stdout)
    assert out["repair_level"] == 1
    assert out["one_click_tools"] == ["windows.start_service", "windows.flush_dns", "windows.clean_temp"]
    assert json.loads(run([*srv, "tenants"], env).stdout)[0]["max_auto_level"] == 1
    from bonelia.server.store import Store

    store = Store(tmp_path / "d" / "bonelia.db")
    dev = store.redeem_enrollment(store.create_enrollment_code(tenant, ["diagnose"]), "USB", "pk")["device_id"]
    out = json.loads(run([*srv, "device-scopes", dev, "--add", "repair:windows"], env).stdout)
    assert out["scopes"] == ["diagnose", "repair:windows"]
    out = json.loads(run([*srv, "allow-repairs", tenant, "--level", "1", "--include-devices"], env).stdout)
    assert out["devices_updated"] == [dev]
    assert set(store.device(dev)["scopes"]) == {"diagnose", "repair:windows", "install:agent"}


def test_dashboard_refuses_unsafe_bind(tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    p = run(["-m", "bonelia.server.cli", "--data-dir", str(tmp_path / "d"), "dashboard", "--host", "192.168.1.10", "--no-browser"],
            env, check=False, timeout=30)
    assert p.returncode == 2 and ("Tailscale" in p.stdout or "Tailscale" in p.stderr)

