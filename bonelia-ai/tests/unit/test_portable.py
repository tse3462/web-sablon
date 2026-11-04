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
