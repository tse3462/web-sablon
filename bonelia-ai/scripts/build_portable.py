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
  Bu sürüm salt okunurdur; hiçbir ticari kayıt değiştirilmez.

DE — Verwendung
  1. USB-Stick einstecken. Das Programm startet nicht automatisch.
  2. BoneliaAI.exe mit Erlaubnis des Betriebs per Doppelklick öffnen (kein schwarzes Fenster; "Schließen" beendet).
  3. Im Browser öffnet sich die lokale BONELİA-AI-Oberfläche (nur dieser Rechner, 127.0.0.1).
  4. Erstregistrierung: BoneliaAI-Konsol.exe enroll --server <Adresse> --code <Code> --label "USB 01"
  Diese Version arbeitet nur lesend; es werden keine Geschäftsdaten verändert.
"""


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
    files = {str(p.relative_to(pkg)).replace("\\", "/"): sha256(p) for p in sorted(pkg.rglob("*")) if p.is_file()}
    manifest = {"product": "BONELİA AI Portable Monitor", "version": __version__, "built_at": datetime.now(timezone.utc).isoformat(),
                "build_platform": f"{platform.system()} {platform.release()} {platform.machine()}", "python": platform.python_version(),
                "signed": False, "files": files}
    (pkg / "manifests" / "build-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"built {pkg} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
