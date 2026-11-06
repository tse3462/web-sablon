"""USB install script: RustDesk is installed together with the agent (user request 06.11.2026)."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_portable", ROOT / "scripts" / "build_portable.py")
bp = importlib.util.module_from_spec(spec); spec.loader.exec_module(bp)  # type: ignore[union-attr]


def test_install_script_sets_up_rustdesk_before_the_agent():
    bat = bp.BAT_FILES["Bu-Bilgisayara-Kur.bat"]
    bat.encode("ascii")  # written to the USB as plain ASCII
    order = [bat.index(x) for x in (":ts_join", ":rustdesk", ":rd_setup", ":agent", "agent-install")]
    assert order == sorted(order)
    assert 'if exist "%RD%" goto rd_setup' in bat  # already installed: skipped
    assert 'msiexec /i "%%~f" /qn /norestart' in bat and '--silent-install' in bat
    assert '"%RD%" --password "%RDPW%"' in bat and 'set "RDPW="' in bat  # the password is not kept in the session
    assert "goto agent" in bat and "goto rustdesk" in bat  # Tailscale missing no longer skips RustDesk
    assert "RustDesk ID: %RDID%" in bat and "('call \"%RD%\" --get-id" in bat
    assert "rustdesk-password.txt" in bp.RUSTDESK_NOTE and "sunucuya gonderilmez" in bp.RUSTDESK_NOTE
