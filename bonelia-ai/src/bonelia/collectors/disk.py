"""Disk space: what fills the disk, and an approved cleanup (user request 06.11.2026).

`scan` reports free space, known space hogs, the largest folders and SUGGESTIONS:
- old backups: in Downloads, backups of the same series (same name apart from dates, numbers and
  "(1)" copy marks); the newest KEEP_BACKUPS of each series are never suggested;
- duplicates: files with identical content (backups in Downloads at any size, others from dup_min);
  one copy always stays (preferably the one outside Downloads, else the newest);
- old downloads: big files in Downloads not touched for OLD_DAYS.

`clean` deletes only what the owner picked in the panel: files that are inside the users' own folders,
still have the size and time from the report, and are no links; plus the "safe" categories asked
for (temp files older than a day, recycle bin, pip/npm/browser caches). AI models, WSL/Docker disks
and Windows Update files are reported only; they are never deleted here.
Everything stops at a time budget and skips links/junctions, so a scan never runs away.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

KEEP_BACKUPS = 2
OLD_DAYS = 90
OLD_MIN = 100 * 1024 * 1024
DUP_MIN = 50 * 1024 * 1024
MAX_SUGGESTIONS = 300
USER_FOLDERS = ("Downloads", "Desktop", "Documents", "Videos", "Pictures", "Music")
SKIP_PROFILES = {"default", "default user", "public", "all users", "defaultapppool"}
BACKUP_WORDS = ("backup", "yedek", "sicherung", "dump", "export", "bak")
BACKUP_EXT = (".bak", ".sql", ".dump", ".backup", ".bkp")
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz")

# (key, kind, paths relative to a user profile); "safe" may be cleaned on request, "info" is reported only.
PROFILE_PLACES = [
    ("temp", "safe", [("AppData", "Local", "Temp")]),
    ("pip_cache", "safe", [("AppData", "Local", "pip", "Cache")]),
    ("npm_cache", "safe", [("AppData", "Local", "npm-cache")]),
    ("browser_cache", "safe", [("AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"),
                               ("AppData", "Local", "Google", "Chrome", "User Data", "Default", "Code Cache"),
                               ("AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"),
                               ("AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Code Cache")]),
    ("ai_models", "info", [(".ollama", "models"), (".cache", "huggingface"), (".cache", "lm-studio"), (".lmstudio", "models")]),
    ("docker_wsl", "info", [("AppData", "Local", "Docker", "wsl"), ("AppData", "Local", "wsl")]),
]


@dataclass
class Layout:
    drive: Path                 # e.g. C:\
    users_root: Path            # C:\Users
    system_root: Path           # C:\Windows
    recycle_root: Path          # C:\$Recycle.Bin

    @classmethod
    def windows(cls) -> "Layout":
        drive = Path(os.environ.get("SystemDrive", "C:") + "\\")
        return cls(drive=drive, users_root=drive / "Users", system_root=Path(os.environ.get("SystemRoot", r"C:\Windows")),
                   recycle_root=drive / "$Recycle.Bin")

    def profiles(self) -> list[Path]:
        try:
            return sorted(p for p in self.users_root.iterdir()
                          if p.is_dir() and not _is_link(p) and p.name.lower() not in SKIP_PROFILES)
        except OSError:
            return []

    def safe_dirs(self, key: str) -> list[Path]:
        if key == "recycle":
            return [self.recycle_root]
        out = [p.joinpath(*rel) for p in self.profiles() for k, kind, rels in PROFILE_PLACES if k == key and kind == "safe" for rel in rels]
        if key == "temp":
            out.append(self.system_root / "Temp")
        return out

    def user_roots(self) -> list[Path]:
        return [p / f for p in self.profiles() for f in USER_FOLDERS]


class Budget:
    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds
        self.hit = False

    def over(self) -> bool:
        if time.monotonic() >= self.deadline:
            self.hit = True
        return self.hit


def _is_link(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return True
    reparse = getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(st.st_mode) or bool(reparse)


def _files(root: Path, budget: Budget) -> Iterator[os.DirEntry]:
    stack = [str(root)]
    while stack:
        if budget.over():
            return
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if e.is_symlink() or _is_link(Path(e.path)):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            yield e
                    except OSError:
                        continue
        except OSError:
            continue


def dir_size(root: Path, budget: Budget) -> int:
    total = 0
    for e in _files(root, budget):
        try:
            total += e.stat(follow_symlinks=False).st_size
        except OSError:
            pass
    return total


# ---------------------------------------------------------------------------------------- backups
_DATE = re.compile(r"\d{4}[-_.]?\d{2}[-_.]?\d{2}|\d{2}[-_.]\d{2}[-_.]\d{4}")
_COPY = re.compile(r"\s*\(\d+\)$")


def _split_ext(name: str) -> tuple[str, str]:
    low = name.lower()
    for double in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if low.endswith(double):
            return name[: -len(double)], double
    stem, ext = os.path.splitext(name)
    return stem, ext.lower()


def is_backup(name: str) -> bool:
    stem, ext = _split_ext(name)
    low = stem.lower()
    return ext in BACKUP_EXT or (ext in ARCHIVE_EXT and any(w in low for w in BACKUP_WORDS))


def series_key(name: str) -> str:
    """Same series = same name apart from dates, times, numbers and "(1)" copy marks, same extension."""
    stem, ext = _split_ext(name)
    s = _COPY.sub("", stem.lower())
    s = _DATE.sub(" ", s)
    s = re.sub(r"\d+", "#", s)
    s = re.sub(r"[\s_.\-#]+", " ", s).strip()
    return f"{s}|{ext}"


def _sha256(path: str, budget: Budget) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if budget.over():
                    return None
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _item(path: str, st: os.stat_result, reason: str, group: str) -> dict[str, Any]:
    mtime = int(st.st_mtime)
    return {"id": hashlib.sha256(f"{path}|{st.st_size}|{mtime}".encode()).hexdigest()[:16], "path": path,
            "bytes": st.st_size, "mtime": mtime, "reason": reason, "group": group}


# ---------------------------------------------------------------------------------------- scan
def scan(layout: Layout, budget_s: float = 90.0, old_min: int = OLD_MIN, dup_min: int = DUP_MIN,
         now: float | None = None) -> dict[str, Any]:
    budget = Budget(budget_s)
    now = time.time() if now is None else now
    report: dict[str, Any] = {"at": int(now), "drives": [], "categories": [], "largest": [], "suggestions": [], "partial": False}
    try:
        u = shutil.disk_usage(layout.drive)
        report["drives"].append({"name": str(layout.drive), "total": u.total, "free": u.free})
    except OSError:
        pass

    # Known space hogs
    cats: dict[str, dict[str, Any]] = {}
    for key, kind, rels in PROFILE_PLACES:
        cats[key] = {"key": key, "kind": kind, "bytes": sum(dir_size(p.joinpath(*rel), budget) for p in layout.profiles() for rel in rels)}
    cats["temp"]["bytes"] += dir_size(layout.system_root / "Temp", budget)
    cats["recycle"] = {"key": "recycle", "kind": "safe", "bytes": dir_size(layout.recycle_root, budget)}
    cats["update_cache"] = {"key": "update_cache", "kind": "info",
                            "bytes": dir_size(layout.system_root / "SoftwareDistribution" / "Download", budget)}
    report["categories"] = [c for c in cats.values() if c["bytes"] > 0]

    # Largest folders: each profile's top level, and AppData\Local's children
    sizes = []
    for prof in layout.profiles():
        for parent in (prof, prof / "AppData" / "Local"):
            try:
                children = [c for c in parent.iterdir() if c.is_dir() and not _is_link(c)]
            except OSError:
                continue
            for c in children:
                if c.name == "AppData" and parent == prof:
                    continue
                sizes.append({"path": str(c), "bytes": dir_size(c, budget)})
    report["largest"] = sorted((s for s in sizes if s["bytes"] > 0), key=lambda s: -s["bytes"])[:15]

    # Suggestions from the users' own folders
    files: list[tuple[str, os.stat_result, bool]] = []  # path, stat, in Downloads
    for prof in layout.profiles():
        for folder in USER_FOLDERS:
            root = prof / folder
            for e in _files(root, budget):
                try:
                    files.append((e.path, e.stat(follow_symlinks=False), folder == "Downloads"))
                except OSError:
                    continue
    taken: set[str] = set()
    suggestions: list[dict[str, Any]] = []

    # 1) identical content: backups in Downloads at any size, everything else from dup_min
    by_size: dict[int, list[tuple[str, os.stat_result, bool]]] = {}
    for f in files:
        if f[1].st_size > 0 and (f[1].st_size >= dup_min or (f[2] and is_backup(os.path.basename(f[0])))):
            by_size.setdefault(f[1].st_size, []).append(f)
    for group in by_size.values():
        if len(group) < 2:
            continue
        by_hash: dict[str, list[tuple[str, os.stat_result, bool]]] = {}
        for f in group:
            h = _sha256(f[0], budget)
            if h:
                by_hash.setdefault(h, []).append(f)
        for h, same in by_hash.items():
            if len(same) < 2:
                continue
            # keep one: outside Downloads first, then the oldest (the original download)
            keep = sorted(same, key=lambda f: (f[2], f[1].st_mtime))[0]
            for f in same:
                if f is not keep:
                    suggestions.append(_item(f[0], f[1], "duplicate", h[:12]))
                    taken.add(f[0])

    # 2) backup series in Downloads: keep the newest KEEP_BACKUPS
    series: dict[tuple[str, str], list[tuple[str, os.stat_result, bool]]] = {}
    for f in files:
        name = os.path.basename(f[0])
        if f[2] and f[0] not in taken and is_backup(name):
            series.setdefault((os.path.dirname(f[0]), series_key(name)), []).append(f)
    for (_, key), items in series.items():
        items.sort(key=lambda f: -f[1].st_mtime)
        for f in items[KEEP_BACKUPS:]:
            suggestions.append(_item(f[0], f[1], "old_backup", key.split("|")[0]))
            taken.add(f[0])

    # 3) big old downloads
    for f in files:
        if f[2] and f[0] not in taken and f[1].st_size >= old_min and now - f[1].st_mtime >= OLD_DAYS * 86400:
            suggestions.append(_item(f[0], f[1], "old_download", ""))
            taken.add(f[0])

    report["suggestions"] = sorted(suggestions, key=lambda s: -s["bytes"])[:MAX_SUGGESTIONS]
    report["partial"] = budget.hit
    return report


# ---------------------------------------------------------------------------------------- cleanup
def _inside(path: Path, roots: list[Path]) -> bool:
    try:
        rp = path.resolve()
    except OSError:
        return False
    for r in roots:
        try:
            rp.relative_to(r.resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def _empty(root: Path, older_than_s: float, budget: Budget) -> int:
    freed, now = 0, time.time()
    for e in _files(root, budget):
        try:
            st = e.stat(follow_symlinks=False)
            if now - st.st_mtime < older_than_s:
                continue
            os.remove(e.path)
            freed += st.st_size
        except OSError:
            continue  # in use or protected: left alone
    return freed


def clean(layout: Layout, request: dict[str, Any], budget_s: float = 600.0) -> dict[str, Any]:
    budget = Budget(budget_s)
    result: dict[str, Any] = {"id": str(request.get("id") or ""), "safe": {}, "files": [], "freed": 0}
    roots = layout.user_roots()
    for item in request.get("files") or []:
        path = Path(str(item.get("path") or ""))
        status = "deleted"
        if not path.name or not _inside(path, roots):
            status = "not_allowed"
        elif _is_link(path) or not path.is_file():
            status = "missing"
        else:
            try:
                st = os.stat(path)
                if st.st_size != int(item.get("bytes", -1)) or int(st.st_mtime) != int(item.get("mtime", -1)):
                    status = "changed"  # different from what the owner saw: leave it
                else:
                    os.remove(path)
                    result["freed"] += st.st_size
            except (OSError, ValueError, TypeError):
                status = "error"
        result["files"].append({"path": str(path), "status": status})
    safe_keys = {k for k, kind, _ in PROFILE_PLACES if kind == "safe"} | {"recycle"}
    for key in request.get("safe") or []:
        if key not in safe_keys:
            continue
        freed = sum(_empty(d, 86400 if key == "temp" else 0, budget) for d in layout.safe_dirs(key))
        result["safe"][key] = freed
        result["freed"] += freed
    return result
