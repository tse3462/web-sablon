"""Build the BONELIA-AI-Portable distribution folder.

    python scripts/build_portable.py [--out dist]

Produces:
  dist/BONELIA-AI-Portable/
    BoneliaAI.exe            double-click: opens the UI, no console window
    BoneliaAI-Konsol.exe     command line (enroll, scan --json, ...)
    config/  adapters/  resources/  reports/  manifests/  queue/
    manifests/build-manifest.json   SHA-256 of every shipped file
    LIESMICH-BENIOKU.txt

Code signing (Authenticode) is NOT performed here: it requires the company's
code-signing certificate, which must be configured separately (docs/RELEASE.md).
The build manifest is not a substitute for a signature.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "bonelia"
sys.path.insert(0, str(ROOT / "src"))
from bonelia import __version__  # noqa: E402
from bonelia.adapters import core_manifests  # noqa: E402

README = """BONELİA AI Portable Monitor {version}

TR — Kullanım
  1. USB belleği takın. Program otomatik başlamaz.
  2. BoneliaAI.exe dosyasını işletmenin izniyle çift tıklayarak açın (siyah pencere açılmaz; "Kapat" ile kapanır).
  3. Tarayıcıda yerel BONELİA AI ekranı açılır (yalnızca bu bilgisayar, 127.0.0.1).
  4. İlk kullanımda cihaz kaydı: BoneliaAI-Konsol.exe enroll --server <adres> --code <kod> --label "USB 01"
  5. Kalıcı kurulum: Bu-Bilgisayara-Kur.bat — Tailscale ve RustDesk (klasörlerine kurulum dosyası koyduysanız) ve
     BONELİA AI ajanı birlikte kurulur. RustDesk şifresi: config\rustdesk-password.txt (rustdesk klasöründeki nota bakın).
  Bu sürüm salt okunurdur; hiçbir ticari kayıt değiştirilmez.

DE — Verwendung
  1. USB-Stick einstecken. Das Programm startet nicht automatisch.
  2. BoneliaAI.exe mit Erlaubnis des Betriebs per Doppelklick öffnen (kein schwarzes Fenster; "Schließen" beendet).
  3. Im Browser öffnet sich die lokale BONELİA-AI-Oberfläche (nur dieser Rechner, 127.0.0.1).
  4. Erstregistrierung: BoneliaAI-Konsol.exe enroll --server <Adresse> --code <Code> --label "USB 01"
  5. Dauerhafte Installation: Bu-Bilgisayara-Kur.bat — installiert Tailscale und RustDesk (wenn der Installer im
     jeweiligen Ordner liegt) zusammen mit dem BONELİA-AI-Agenten. RustDesk-Passwort: config\rustdesk-password.txt.
  Diese Version arbeitet nur lesend; es werden keine Geschäftsdaten verändert.
"""


# Double-click helpers on the USB: they ask Windows for admin rights themselves (UAC).
_INSTALL_BAT = r"""@echo off
rem BONELIA AI: silent install of continuous monitoring + safe self-repair on THIS PC
net session >nul 2>&1 || (powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
setlocal
cd /d "%~dp0"
title BONELIA AI

rem 1) Tailscale: only if not installed yet and the installer was put on the USB (folder "tailscale")
set "TS=%ProgramFiles%\Tailscale\tailscale.exe"
if exist "%TS%" goto ts_join
for %%f in ("%~dp0tailscale\*.msi") do msiexec /i "%%~f" /quiet /norestart TS_UNATTENDEDMODE=always
:ts_join
if not exist "%TS%" goto rustdesk
if not exist "%~dp0config\tailscale-authkey.txt" goto rustdesk
set /p TSKEY=<"%~dp0config\tailscale-authkey.txt"
"%TS%" up --authkey=%TSKEY% --unattended >nul 2>&1

:rustdesk
rem 2) RustDesk remote access: only if not installed yet and the installer was put on the USB (folder "rustdesk")
set "RD=%ProgramFiles%\RustDesk\rustdesk.exe"
if exist "%RD%" goto rd_setup
for %%f in ("%~dp0rustdesk\*.msi") do msiexec /i "%%~f" /qn /norestart
if exist "%RD%" goto rd_setup
for %%f in ("%~dp0rustdesk\*.exe") do start "" "%%~f" --silent-install
rem the .exe installs in the background: wait up to 90 seconds
for /l %%i in (1,1,45) do if not exist "%RD%" timeout /t 2 /nobreak >nul
:rd_setup
if not exist "%RD%" goto agent
rem own RustDesk server (optional): config\rustdesk-config.txt holds the configuration string
set "RDCFG="
if exist "%~dp0config\rustdesk-config.txt" set /p RDCFG=<"%~dp0config\rustdesk-config.txt"
if defined RDCFG "%RD%" --config "%RDCFG%" >nul 2>&1
rem permanent password from config\rustdesk-password.txt; it stays on the USB and in RustDesk, never on the server
set "RDPW="
if exist "%~dp0config\rustdesk-password.txt" set /p RDPW=<"%~dp0config\rustdesk-password.txt"
if defined RDPW "%RD%" --password "%RDPW%" >nul 2>&1
set "RDPW="
timeout /t 3 /nobreak >nul
set "RDID="
rem "call" keeps the quotes around the path (for /f strips a leading quote otherwise)
for /f "delims=" %%i in ('call "%RD%" --get-id 2^>nul') do set "RDID=%%i"

:agent
rem 3) BONELIA AI agent (silent with the install key; the USB password is asked only the very first time)
"%~dp0BoneliaAI-Konsol.exe" agent-install --yes --label "%COMPUTERNAME%"
if errorlevel 1 (
  echo.
  echo KURULUM BASARISIZ / INSTALLATION FEHLGESCHLAGEN
  pause
  exit /b 1
)
set "RDMSG="
if defined RDID set "RDMSG= RustDesk ID: %RDID%"
powershell -NoProfile -WindowStyle Hidden -Command "Add-Type -AssemblyName PresentationFramework; [void][System.Windows.MessageBox]::Show('BONELIA AI kuruldu ve arka planda calisiyor. USB cikarilabilir.' + [Environment]::NewLine + 'BONELIA AI ist installiert und laeuft im Hintergrund.' + [Environment]::NewLine + '%RDMSG%', 'BONELIA AI')"
exit /b 0
"""

_UNINSTALL_BAT = r"""@echo off
rem BONELIA AI: remove the agent from THIS PC
net session >nul 2>&1 || (powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
cd /d "%~dp0"
"%~dp0BoneliaAI-Konsol.exe" agent-uninstall
pause
"""

_RECOVER_BAT = r"""@echo off
rem BONELIA AI: guided Windows recovery on THIS PC (open as administrator for the repair steps)
net session >nul 2>&1 || (powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
cd /d "%~dp0"
"%~dp0BoneliaAI-Konsol.exe" recovery
"""

RUSTDESK_NOTE = (
    "RustDesk (uzaktan baglanti / Fernzugriff)\n"
    "1) Windows kurulum dosyasini (x86_64 .msi veya .exe) bu klasore koyun: https://github.com/rustdesk/rustdesk/releases\n"
    "   Windows-Installer (x86_64 .msi oder .exe) in diesen Ordner legen.\n"
    "2) Kalici sifre / festes Passwort: config\\rustdesk-password.txt (tek satir; sadece harf ve rakam).\n"
    "   Sifre sadece USB'de ve RustDesk'te kalir, sunucuya gonderilmez. USB'yi guvenli saklayin.\n"
    "3) Kendi RustDesk sunucunuz varsa (istege bagli): config\\rustdesk-config.txt\n"
    "Bu-Bilgisayara-Kur.bat RustDesk'i sessiz kurar (zaten kuruluysa atlar) ve sifreyi ayarlar.\n")

BAT_FILES = {"Bu-Bilgisayara-Kur.bat": _INSTALL_BAT, "Bu-Bilgisayardan-Kaldir.bat": _UNINSTALL_BAT,
             "Bu-Bilgisayari-Kurtar.bat": _RECOVER_BAT}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    args = ap.parse_args()
    work = args.out / "_build"
    sep = ";" if sys.platform == "win32" else ":"
    suffix = ".exe" if sys.platform == "win32" else ""
    # Two builds of the same code: windowed for double-click, console for commands.
    for name, extra in (("BoneliaAI", ["--windowed"]), ("BoneliaAI-Konsol", [])):
        cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--name", name, *extra,
               "--distpath", str(work / "bin"), "--workpath", str(work / "tmp" / name), "--specpath", str(work),
               "--paths", str(ROOT / "src"),
               "--add-data", f"{SRC / 'monitor' / 'static'}{sep}bonelia/monitor/static",
               "--add-data", f"{SRC / 'resources'}{sep}bonelia/resources",
               "--add-data", f"{SRC / 'server' / 'static'}{sep}bonelia/server/static",
               "--add-data", f"{SRC / 'recovery' / 'static'}{sep}bonelia/recovery/static",
               "--collect-submodules", "uvicorn", "--collect-submodules", "bonelia",
               "--exclude-module", "tkinter", str(ROOT / "scripts" / "boneliaai_entry.py")]
        print(" ".join(cmd))
        subprocess.run(cmd, check=True)
    pkg = args.out / "BONELIA-AI-Portable"
    if pkg.exists():
        shutil.rmtree(pkg)
    for d in ("config", "adapters", "resources", "reports", "manifests", "queue"):
        (pkg / d).mkdir(parents=True)
    for name in ("BoneliaAI", "BoneliaAI-Konsol"):
        shutil.copy2(work / "bin" / f"{name}{suffix}", pkg / f"{name}{suffix}")
    for m in core_manifests():  # only core + planned manifests ship on the USB
        (pkg / "adapters" / f"{m.adapter_id}.json").write_text(json.dumps(m.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    (pkg / "config" / "settings.json").write_text(json.dumps({"language": "tr", "allow_cloud_default": False, "log_paths": []}, indent=2),
                                                  encoding="utf-8")
    (pkg / "LIESMICH-BENIOKU.txt").write_text(README.format(version=__version__), encoding="utf-8")
    for name, body in BAT_FILES.items():
        (pkg / name).write_bytes(body.replace("\n", "\r\n").encode("ascii"))
    (pkg / "tailscale").mkdir()
    (pkg / "tailscale" / "BURAYA-TAILSCALE-MSI-KOYUN.txt").write_text(
        "Tailscale Windows MSI kurulum dosyasini bu klasore koyun (https://pkgs.tailscale.com/stable/#windows).\n"
        "Auth key: config\\tailscale-authkey.txt (yeniden kullanilabilir, etiketli anahtar).\n", encoding="utf-8")
    (pkg / "rustdesk").mkdir()
    (pkg / "rustdesk" / "BURAYA-RUSTDESK-KURULUMU-KOYUN.txt").write_text(RUSTDESK_NOTE, encoding="utf-8")
    files = {str(p.relative_to(pkg)).replace("\\", "/"): sha256(p) for p in sorted(pkg.rglob("*")) if p.is_file()}
    manifest = {"product": "BONELİA AI Portable Monitor", "version": __version__, "built_at": datetime.now(timezone.utc).isoformat(),
                "build_platform": f"{platform.system()} {platform.release()} {platform.machine()}", "python": platform.python_version(),
                "signed": False, "files": files}
    (pkg / "manifests" / "build-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"built {pkg} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
