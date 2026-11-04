import shutil
import threading

from bonelia.monitor.portable import PortableHome, watch_removal


def test_layout_and_salt(tmp_path):
    h = PortableHome(tmp_path / "BONELIA-AI-Portable").ensure()
    for d in ("config", "adapters", "resources", "reports", "manifests", "queue"):
        assert (h.root / d).is_dir()
    assert h.salt() == h.salt() and len(h.salt()) == 32
    assert h.settings()["language"] == "tr"


def test_usb_removal_triggers_shutdown(tmp_path):
    root = PortableHome(tmp_path / "usb").ensure().root
    fired = threading.Event()
    watch_removal(root, fired.set, interval_s=0.05)
    assert not fired.wait(0.2)
    shutil.rmtree(root)
    assert fired.wait(2)


def test_offline_queue_never_overwrites_entries_in_the_same_clock_tick(tmp_path, monkeypatch):
    """Regression (found on real Windows CI): coarse clock => identical names => silent data loss."""
    import time

    from bonelia.contracts import AppIdentity, DiagnosticEvent
    from bonelia.monitor.offline_queue import OfflineQueue
    from bonelia.security.crypto import DataKey

    monkeypatch.setattr(time, "time_ns", lambda: 1_700_000_000_000_000_000)
    q = OfflineQueue(tmp_path / "q", DataKey(b"k" * 32))
    ev = DiagnosticEvent(app=AppIdentity(app_id="a", name="a"), title="t", fingerprint="f")
    for _ in range(10):
        q.push([ev])
    assert q.size() == 10


def test_cli_survives_windows_legacy_console_encoding(tmp_path):
    """Regression (found on real Windows CI): cp1252 console cannot encode 'İ', '≥' etc."""
    import os
    import subprocess
    import sys

    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    p = subprocess.run([sys.executable, "-m", "bonelia", "--home", str(tmp_path / "usb"), "--lang", "tr", "scan", "--no-unlock"],
                       capture_output=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    assert "BONEL" in p.stdout.decode("utf-8", errors="replace")
