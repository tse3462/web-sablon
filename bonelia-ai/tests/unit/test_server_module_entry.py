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


def test_stop_script_asks_for_admin_when_the_server_runs_elevated():
    """Seen 06.11.2026: BONELIA-Ajan-Onar starts the server with admin rights; the update's plain stop
    could not end it, so pip could not replace the program ('Der Prozess kann nicht auf die Datei zugreifen')."""
    stop = (WIN / "BONELIA-Server-Durdur.bat").read_text(encoding="ascii")
    assert "net session" in stop and "-Verb RunAs -Wait" in stop and ":alive" in stop


def test_usb_preparation_downloads_only_checked_installers_and_saves_the_key():
    bat = (WIN / "BONELIA-USB-Hazirla.bat").read_text(encoding="ascii")
    assert "#==PS==" in bat and "Get-AuthenticodeSignature" in bat and "-notmatch 'Tailscale'" in bat
    assert "Get-FileHash" in bat and "sha256:" in bat  # RustDesk checked against GitHub's published SHA-256
    assert "https://login.tailscale.com/admin/settings/keys" in bat and "tskey-auth-" in bat
    assert "config\\tailscale-authkey.txt" in bat


def test_backup_and_one_click_reinstall_scripts():
    """06.11.2026: before a format one double-click copies what is not on GitHub; after it, one double-click on the
    stick brings everything back (checked backup, same Tailscale identity, same server key, own agent re-registered)."""
    bk = (WIN / "BONELIA-Yedekle.bat").read_text(encoding="ascii")
    assert "#==PS==" in bk and "bonelia.server.backup" in bk and "tailscale/server-state.conf=" in bk
    assert "agent_device_id=" in bk and "BONELIA-Format-Sonrasi-Kur.bat" in bk and "net session" in bk
    rs = (WIN / "BONELIA-Format-Sonrasi-Kur.bat").read_text(encoding="ascii")
    assert "#==PS==" in rs and "Get-FileHash -Algorithm SHA256" in rs and "Yedek bozuk" in rs
    for pkg in ("Git.Git", "Python.Python.3.14", "Tailscale.Tailscale", "RustDesk.RustDesk", "Ollama.Ollama"):
        assert f"'{pkg}'" in rs
    assert "server-state.conf" in rs and "replace-agent" in rs and "agent-install --code" in rs
    assert "BONELIA-Kur-Otomatik.bat" in rs and "BONELIA-Ajan-Onar.bat" in rs and ".onceki-" in rs
    # the data is put back BEFORE the server starts, so it never makes a new key of its own
    assert rs.index("RestoreData\n$cfg") < rs.index("BONELIA-Kur-Otomatik.bat")
    assert "BONELIA-Yedekle.bat" in rs  # the weekly backup is set up again after a reinstall


def test_backup_runs_by_itself_once_a_week_while_the_stick_is_plugged_in():
    bk = (WIN / "BONELIA-Yedekle.bat").read_text(encoding="ascii")
    assert '"%~1"=="/auto"' in bk and "BONELIA_AUTO" in bk and "--record" in bk
    assert "Register-ScheduledTask -TaskName 'BONELIA AI Yedek'" in bk and "-Daily" in bk and "-StartWhenAvailable" in bk
    assert "age_days" in bk and "-lt 7" in bk  # daily look, a new backup only when the newest is a week old
    vbs = (WIN / "gizli-calistir.vbs").read_text(encoding="ascii")
    assert "WScript.Arguments" in vbs and ", 0, True" in vbs  # no window at all


def test_update_fetches_first_and_never_leaves_the_server_stopped():
    """Seen 07.11.2026: 'git pull' failed (GitHub not reachable) after the server had already been stopped, so BONELIA
    stayed off. Now the code is fetched first (3 tries), the server is only stopped after that, and on failure the
    whole answer of git is shown with the likely reason and the server is (re)started."""
    up = (WIN / "BONELIA-Server-Guncelle.bat").read_text(encoding="ascii")
    assert up.index("git pull") < up.index("BONELIA-Server-Durdur.bat")
    assert "if %TRY% geq 3 goto pullfailed" in up and 'type "%PULLOUT%"' in up
    fail = up[up.index(":pullfailed"):up.index(":pulled\n")]
    assert "Durdur" not in fail and "BONELIA-Server-Baslat.bat" in fail and "resolve host" in fail
    assert "exit /b 1" in fail
