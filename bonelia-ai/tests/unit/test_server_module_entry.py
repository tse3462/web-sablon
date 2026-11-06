"""The Windows scripts start the server with `python -m bonelia.server` (Smart App Control blocks
pip's unsigned bonelia-server.exe); that entry must behave like the console script."""

import subprocess
import sys
from pathlib import Path

WIN = Path(__file__).resolve().parents[2] / "deployment" / "windows"


def test_python_dash_m_runs_the_server_cli():
    out = subprocess.run([sys.executable, "-m", "bonelia.server", "--help"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "publish-agent" in out.stdout and "dashboard" in out.stdout


def test_scripts_no_longer_start_the_unsigned_exe():
    for name in ("BONELIA-Server-Baslat.bat", "BONELIA-Panel-Baslat.bat", "BONELIA-Kontrol-Paneli.bat", "BONELIA-Ajanlari-Guncelle.bat"):
        text = (WIN / name).read_text(encoding="ascii")
        assert "-m bonelia.server" in text or "'-m','bonelia.server'" in text, name
        assert "Scripts\\bonelia-server.exe" not in text, name
    stop = (WIN / "BONELIA-Server-Durdur.bat").read_text(encoding="ascii")
    assert "bonelia.server" in stop and "bonelia-server.exe" in stop  # stops new and old style
