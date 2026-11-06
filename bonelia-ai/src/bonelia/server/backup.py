"""Backup and restore of the home server for a reinstall (user request 06.11.2026).

The program is on GitHub; what is not: the server key every agent trusts (lost = every customer PC must be
installed again), the database (customers, PCs, vault boxes, settings) and the phone panel's token. A backup
is a folder <dest>/sunucu-YYYYMMDD-HHMMSS with data/, optional extras/ (e.g. Tailscale's identity, the local
server.home.toml) and manifest.json holding the SHA-256 of every file; it is written under a temporary name
and renamed only when complete. The database is copied with SQLite's online backup, so the server may run.

    python -m bonelia.server.backup make --config deployment\\server.home.toml --dest E:\\BONELIA-Yedek
    python -m bonelia.server.backup latest --root E:\\BONELIA-Yedek
    python -m bonelia.server.backup restore --from E:\\BONELIA-Yedek\\sunucu-... --config ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

KEY, DB, TOKEN = "server_ed25519.key", "bonelia.db", "dashboard.token"
PREFIX = "sunucu-"


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_backup(data_dir: Path, dest_root: Path, extras: dict[str, Path] | None = None, info: dict[str, str] | None = None,
                now: datetime | None = None, keep: int = 5) -> Path:
    data_dir, dest_root = Path(data_dir), Path(dest_root)
    if not (data_dir / KEY).is_file():
        raise FileNotFoundError(f"{data_dir / KEY} not found -- wrong server folder?")
    now = now or datetime.now()
    final = dest_root / f"{PREFIX}{now:%Y%m%d-%H%M%S}"
    tmp = dest_root / (final.name + ".yaziliyor")
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "data").mkdir(parents=True)
    shutil.copy2(data_dir / KEY, tmp / "data" / KEY)
    if (data_dir / TOKEN).is_file():
        shutil.copy2(data_dir / TOKEN, tmp / "data" / TOKEN)
    if (data_dir / DB).is_file():
        src, dst = sqlite3.connect(data_dir / DB), sqlite3.connect(tmp / "data" / DB)
        try:
            src.backup(dst)  # consistent copy even while the server writes
        finally:
            dst.close()
            src.close()
    for rel, path in (extras or {}).items():
        if Path(path).is_file():
            target = tmp / "extras" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    files = {p.relative_to(tmp).as_posix(): _sha(p) for p in sorted(tmp.rglob("*")) if p.is_file()}
    (tmp / "manifest.json").write_text(json.dumps({"version": 1, "created": now.isoformat(timespec="seconds"),
                                                   "files": files, "info": info or {}}, indent=1), encoding="utf-8")
    os.replace(tmp, final)
    done = sorted(p for p in dest_root.iterdir() if p.is_dir() and p.name.startswith(PREFIX) and (p / "manifest.json").is_file())
    for old in done[:-keep] if keep else []:
        shutil.rmtree(old, ignore_errors=True)
    return final


def verify(folder: Path | str) -> list[str]:
    """Files whose content differs from the manifest (or are missing); empty = the backup is intact."""
    folder = Path(folder)
    m = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    return [rel for rel, sha in m["files"].items() if not (folder / rel).is_file() or _sha(folder / rel) != sha]


def latest(root: Path | str) -> Path | None:
    root = Path(root)
    if not root.is_dir():
        return None
    done = sorted(p for p in root.iterdir() if p.is_dir() and p.name.startswith(PREFIX) and (p / "manifest.json").is_file())
    return done[-1] if done else None


def restore(folder: Path | str, data_dir: Path | str, now: datetime | None = None) -> dict[str, Any]:
    """Put the server data back. A server folder that holds another key is moved aside, never overwritten."""
    folder, data_dir = Path(folder), Path(data_dir)
    bad = verify(folder)
    if bad:
        raise ValueError(f"backup damaged: {', '.join(bad)}")
    moved = None
    if (data_dir / KEY).is_file() and _sha(data_dir / KEY) != _sha(folder / "data" / KEY):
        moved = data_dir.with_name(f"{data_dir.name}.onceki-{(now or datetime.now()):%Y%m%d-%H%M%S}")
        os.replace(data_dir, moved)
    data_dir.mkdir(parents=True, exist_ok=True)
    restored = []
    for p in sorted((folder / "data").iterdir()):
        shutil.copy2(p, data_dir / p.name)
        restored.append(p.name)
    return {"restored": restored, "moved_aside": str(moved) if moved else None}


def _data_dir(args) -> Path:
    if args.data_dir:
        return Path(args.data_dir)
    from .config import ServerConfig
    return ServerConfig.load(Path(args.config) if args.config else None).data_dir


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m bonelia.server.backup")
    sub = p.add_subparsers(dest="cmd", required=True)
    mk = sub.add_parser("make")
    mk.add_argument("--config")
    mk.add_argument("--data-dir")
    mk.add_argument("--dest", required=True)
    mk.add_argument("--extra", action="append", default=[], help="name=path, e.g. tailscale/server-state.conf=C:\\...")
    mk.add_argument("--info", action="append", default=[], help="key=value kept in the manifest")
    mk.add_argument("--keep", type=int, default=5)
    lt = sub.add_parser("latest")
    lt.add_argument("--root", required=True)
    rs = sub.add_parser("restore")
    rs.add_argument("--from", dest="src", required=True)
    rs.add_argument("--config")
    rs.add_argument("--data-dir")
    args = p.parse_args(argv)
    out: dict[str, Any]
    try:
        if args.cmd == "make":
            extras = dict(x.split("=", 1) for x in args.extra if "=" in x)
            info = dict(x.split("=", 1) for x in args.info if "=" in x)
            folder = make_backup(_data_dir(args), Path(args.dest), {k: Path(v) for k, v in extras.items()}, info, keep=args.keep)
            out = {"ok": not verify(folder), "folder": str(folder)}
        elif args.cmd == "latest":
            f = latest(args.root)
            out = {"ok": f is not None, "folder": str(f) if f else None}
        else:
            out = {"ok": True, **restore(args.src, _data_dir(args))}
    except (OSError, ValueError, sqlite3.Error) as exc:
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
