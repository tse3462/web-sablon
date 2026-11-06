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
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

KEEP_BACKUPS = 2
OLD_DAYS = 90
OLD_MIN = 100 * 1024 * 1024
DUP_MIN = 50 * 1024 * 1024
MAX_SUGGESTIONS = 300
MIN_ITEM = 1024 * 1024  # smaller files free nothing worth a decision
RECENT_DAYS = 30   # changed within: "in use"
UNUSED_DAYS = 90   # unchanged for longer: "unused" (advice)
BACKUP_DIR = "BONELIA-Yedek"
MIN_SHOW = 500 * 1024 * 1024  # folders/files below this are not listed in the open-up view (user request 06.11.2026)

# What may be deleted from the open-up folder view, relative to a user profile (lower case), longest match wins:
#   "root"   the folder itself and anything inside it
#   "inside" anything inside, but not the folder itself (Downloads, Documents, ...)
#   "system" never shown; "<note>" shown with its note, never deleted
FOLDER_RULES: list[tuple[tuple[str, ...], str]] = [
    (("downloads",), "inside"), (("desktop",), "inside"), (("documents",), "inside"),
    (("videos",), "inside"), (("pictures",), "inside"), (("music",), "inside"),
    ((".lmstudio", "models"), "root"), ((".cache", "huggingface"), "root"), ((".cache", "lm-studio"), "root"),
    ((".codex",), "inside"),
    ((".ollama",), "bonelia_model"),
    (("appdata", "local", "docker"), "docker"),
    (("appdata", "local", "microsoft"), "system"), (("appdata", "local", "packages"), "system"),
    (("appdata", "roaming", "microsoft"), "system"), (("appdata", "locallow"), "system"),
    (("appdata",), "app"),
]
# Folders of code projects and tools: their files are not the owner's backups or copies (seen 06.11.2026:
# two identical Supabase migrations of a project in Downloads were offered as copies).
PROJECT_DIRS = {".git", ".svn", ".hg", "node_modules", "migrations", "supabase", ".venv", "venv", "site-packages",
                "__pycache__", "vendor", "dist", "build", ".next", ".idea", ".vscode", "target", "packages"}
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
    backup_drives: list[Path] = field(default_factory=list)  # other disks (e.g. YEDEK D:) for "move instead of delete"

    @classmethod
    def windows(cls) -> "Layout":
        drive = Path(os.environ.get("SystemDrive", "C:") + "\\")
        others = []
        for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
            d = Path(f"{letter}:\\")
            try:
                if str(d).lower() != str(drive).lower() and d.is_dir():
                    shutil.disk_usage(d)
                    others.append(d)
            except OSError:
                continue
        return cls(drive=drive, users_root=drive / "Users", system_root=Path(os.environ.get("SystemRoot", r"C:\Windows")),
                   recycle_root=drive / "$Recycle.Bin", backup_drives=others)

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


_NEWEST: dict[str, float] = {}


def dir_size(root: Path, budget: Budget, memo: dict[str, int] | None = None) -> int:
    key = str(root)
    if memo is not None and key in memo:
        return memo[key]
    total, newest = 0, 0.0
    for e in _files(root, budget):
        try:
            st = e.stat(follow_symlinks=False)
            total += st.st_size
            newest = max(newest, st.st_mtime)
        except OSError:
            pass
    _NEWEST[key] = newest
    if memo is not None and not budget.hit:
        memo[key] = total
    return total


def classify(path: Path, layout: "Layout") -> tuple[bool, str]:
    """(may be deleted from the folder view, note). Links are judged by where they are, never followed."""
    ap = os.path.normcase(os.path.abspath(str(path)))
    for prof in layout.profiles():
        base = os.path.normcase(os.path.abspath(str(prof)))
        if ap == base:
            return False, "system"
        if not ap.startswith(base + os.sep):
            continue
        rel = tuple(x.lower() for x in Path(ap[len(base) + 1:]).parts)
        if any("bonelia" in x for x in rel):
            return False, "bonelia"
        for parts, mode in sorted(FOLDER_RULES, key=lambda r: -len(r[0])):
            if rel[:len(parts)] != parts:
                continue
            if mode == "root":
                return True, ""
            if mode == "inside":
                return (True, "") if len(rel) > len(parts) else (False, "folder")
            return False, mode
        return False, "other"
    return False, "system"


def _tree(path: Path, budget: Budget, memo: dict[str, int], depth: int, min_show: int, cache: dict[str, dict]) -> dict[str, Any]:
    """Size of a folder in one walk, with its sub-folders (and big files) down to `depth` levels."""
    key = str(path)
    if key in cache and not budget.hit:
        return cache[key]
    size, kids, newest = 0, [], 0.0
    try:
        entries = list(os.scandir(path))
    except OSError:
        entries = []
    for e in entries:
        if budget.over():
            break
        try:
            if e.is_symlink() or _is_link(Path(e.path)):
                continue
            if e.is_dir(follow_symlinks=False):
                if depth > 0:
                    sub = _tree(Path(e.path), budget, memo, depth - 1, min_show, cache)
                    kids.append(sub)
                    size += sub["bytes"]
                    newest = max(newest, sub["mtime"])
                else:
                    size += dir_size(Path(e.path), budget, memo)
                    newest = max(newest, _NEWEST.get(e.path, 0.0))
            elif e.is_file(follow_symlinks=False):
                st = e.stat(follow_symlinks=False)
                size += st.st_size
                newest = max(newest, st.st_mtime)
                if depth > 0 and st.st_size >= min_show:
                    kids.append({"path": e.path, "bytes": st.st_size, "mtime": st.st_mtime, "children": []})
        except OSError:
            continue
    node = {"path": key, "bytes": size, "mtime": newest, "children": kids}
    if not budget.hit:
        memo[key] = size
        cache[key] = node
    return node


def _decorate(node: dict[str, Any], layout: "Layout", min_show: int, now: float | None = None) -> dict[str, Any] | None:
    """Add id, deletable, note and use ("in_use" / "unused" by the newest change inside); drop system places and
    what is too small to matter."""
    now = time.time() if now is None else now
    ok, note = classify(Path(node["path"]), layout)
    if note == "system" or node["bytes"] < min_show:
        return None
    kids = [k for k in (_decorate(c, layout, min_show, now) for c in node.get("children") or []) if k]
    kids.sort(key=lambda k: -k["bytes"])
    mtime = float(node.get("mtime") or 0)
    age = (now - mtime) / 86400 if mtime else None
    use = "" if age is None else "in_use" if age <= RECENT_DAYS else "unused" if age >= UNUSED_DAYS else ""
    return {"id": hashlib.sha256(f"{node['path']}|{node['bytes']}".encode()).hexdigest()[:16], "path": node["path"],
            "bytes": node["bytes"], "deletable": ok, "note": note, "last_write": int(mtime), "use": use, "children": kids[:8]}


def _backup_index(drives: list[Path], budget: Budget, depth: int = 4, limit: int = 50000) -> dict[str, list[Path]]:
    """Names on the backup drives (a few levels deep), to find copies of what fills the system disk."""
    index: dict[str, list[Path]] = {}
    count = 0
    for drive in drives:
        level = [drive]
        for _ in range(depth):
            nxt = []
            for d in level:
                if budget.over() or count > limit:
                    return index
                try:
                    with os.scandir(d) as it:
                        for e in it:
                            if e.name.lower() in ("$recycle.bin", "system volume information") or e.is_symlink():
                                continue
                            index.setdefault(e.name.lower(), []).append(Path(e.path))
                            count += 1
                            if e.is_dir(follow_symlinks=False):
                                nxt.append(Path(e.path))
                except OSError:
                    continue
            level = nxt
    return index


def _find_backup(node: dict[str, Any], index: dict[str, list[Path]], budget: Budget, memo: dict[str, int]) -> str | None:
    """A copy elsewhere with the same name and (within 2 %) the same size."""
    for cand in index.get(Path(node["path"]).name.lower(), []):
        try:
            size = cand.stat().st_size if cand.is_file() else dir_size(cand, budget, memo)
        except OSError:
            continue
        if node["bytes"] and abs(size - node["bytes"]) <= 0.02 * node["bytes"]:
            return str(cand)
    return None


def _advise(nodes: list[dict[str, Any]], index: dict[str, list[Path]], budget: Budget, now: float) -> list[dict[str, Any]]:
    """What could go, highest level first (a folder is advised as a whole, its contents not again)."""
    advice, memo, seen = [], {}, set()
    stack = list(nodes)
    while stack:
        n = stack.pop(0)
        if n["path"] in seen:
            continue
        seen.add(n["path"])
        if n.get("deletable"):
            backup = _find_backup(n, index, budget, memo) if index else None
            if backup:
                n["backup"] = backup
                advice.append({"id": n["id"], "path": n["path"], "bytes": n["bytes"], "why": "has_backup", "backup": backup,
                               "last_write": n.get("last_write", 0)})
                continue
            if n.get("use") == "unused":
                advice.append({"id": n["id"], "path": n["path"], "bytes": n["bytes"], "why": "unused",
                               "days": int((now - n.get("last_write", now)) / 86400), "last_write": n.get("last_write", 0)})
                continue
        elif n.get("note") == "docker" and n.get("use") == "unused":
            advice.append({"id": n["id"], "path": n["path"], "bytes": n["bytes"], "why": "docker_unused",
                           "days": int((now - n.get("last_write", now)) / 86400), "last_write": n.get("last_write", 0)})
            continue
        stack.extend(n.get("children") or [])
    return sorted(advice, key=lambda a: -a["bytes"])


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
def scan(layout: Layout, budget_s: float = 180.0, old_min: int = OLD_MIN, dup_min: int = DUP_MIN,
         now: float | None = None, progress: Callable[[int], Any] | None = None, min_item: int = MIN_ITEM,
         min_show: int = MIN_SHOW) -> dict[str, Any]:
    # Each part gets its own share of the time, the users' own files first: measuring big folders such as
    # Docker or AppData must never use up the time before backups and copies are found (seen 06.11.2026).
    now = time.time() if now is None else now
    report: dict[str, Any] = {"at": int(now), "drives": [], "categories": [], "largest": [], "suggestions": [], "partial": False}
    try:
        u = shutil.disk_usage(layout.drive)
        report["drives"].append({"name": str(layout.drive), "total": u.total, "free": u.free})
    except OSError:
        pass
    memo: dict[str, int] = {}
    trees: dict[str, dict] = {}
    budgets = []

    def step(pct: int) -> None:  # for the progress bar in the panel; never allowed to stop the scan
        if progress:
            try:
                progress(pct)
            except Exception:
                pass
    step(5)

    # Suggestions from the users' own folders
    budget = Budget(budget_s * 0.5)
    budgets.append(budget)
    files: list[tuple[str, os.stat_result, bool]] = []  # path, stat, in Downloads
    for prof in layout.profiles():
        for folder in USER_FOLDERS:
            root = prof / folder
            for e in _files(root, budget):
                try:
                    rel = Path(e.path).relative_to(root).parts[:-1]
                    if any(part.lower() in PROJECT_DIRS for part in rel):
                        continue
                    st = e.stat(follow_symlinks=False)
                    if st.st_size >= min_item:
                        files.append((e.path, st, folder == "Downloads"))
                except (OSError, ValueError):
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

    step(50)
    # Known space hogs
    budget = Budget(budget_s * 0.2)
    budgets.append(budget)
    cats: dict[str, dict[str, Any]] = {}
    for key, kind, rels in PROFILE_PLACES:
        parts = []
        for p in layout.profiles():
            for rel in rels:
                place = p.joinpath(*rel)
                if kind == "info" and place.is_dir():
                    node = _tree(place, budget, memo, 2, min_show, trees)
                    shown = _decorate(node, layout, min_show, now) or {"path": str(place), "bytes": node["bytes"], "deletable": False,
                                                                  "note": "", "children": []}
                    parts.append(shown)
                else:
                    parts.append({"path": str(place), "bytes": dir_size(place, budget, memo)})
        parts = sorted((x for x in parts if x["bytes"] > 0), key=lambda x: -x["bytes"])
        cats[key] = {"key": key, "kind": kind, "bytes": sum(x["bytes"] for x in parts), "parts": parts[:8]}
    cats["temp"]["bytes"] += dir_size(layout.system_root / "Temp", budget, memo)
    cats["recycle"] = {"key": "recycle", "kind": "safe", "bytes": dir_size(layout.recycle_root, budget, memo)}
    cats["update_cache"] = {"key": "update_cache", "kind": "info",
                            "bytes": dir_size(layout.system_root / "SoftwareDistribution" / "Download", budget, memo)}
    report["categories"] = [c for c in cats.values() if c["bytes"] > 0]

    step(70)
    # Largest folders: each profile's top level, and AppData\Local's children
    budget = Budget(budget_s * 0.3)
    budgets.append(budget)
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
                if classify(c, layout)[1] == "system":
                    continue  # Windows' own places are not shown at all
                node = _decorate(_tree(c, budget, memo, 3, min_show, trees), layout, min_show, now)
                if node:
                    sizes.append(node)
    report["largest"] = sorted(sizes, key=lambda s: -s["bytes"])[:15]
    # Advice: backed up elsewhere, or unchanged for months (each folder once, the biggest view first)
    budget = Budget(budget_s * 0.15)
    budgets.append(budget)
    index = _backup_index(layout.backup_drives, budget)
    parts = [p for c in report["categories"] for p in c.get("parts") or [] if "id" in p]
    report["advice"] = _advise(report["largest"] + parts, index, budget, now)[:20]
    report["backup_drives"] = []
    for d in layout.backup_drives:
        try:
            u = shutil.disk_usage(d)
            report["backup_drives"].append({"name": str(d), "free": u.free, "total": u.total, "label": _label(d)})
        except OSError:
            continue
    report["suggestions"] = sorted(suggestions, key=lambda s: -s["bytes"])[:MAX_SUGGESTIONS]
    report["partial"] = any(b.hit for b in budgets)
    step(100)
    return report


# ---------------------------------------------------------------------------------------- cleanup
def _label(drive: Path) -> str:
    if sys.platform != "win32":
        return ""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(261)
        ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(str(drive)), buf, 261, None, None, None, None, 0)
        return buf.value[:40]
    except Exception:
        return ""


def _sha(path: str, budget: Budget) -> str | None:
    return _sha256(path, budget)


def _same_content(a: str, b: str, budget: Budget) -> bool:
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
    except OSError:
        return False
    ha, hb = _sha(a, budget), _sha(b, budget)
    return ha is not None and ha == hb


def _move(src: Path, dest: Path, budget: Budget, report_bytes) -> tuple[str, int]:
    """Copy, check every file byte by byte (SHA-256), and only then delete the original."""
    files = []
    if src.is_file():
        files.append((src, dest))
    else:
        for top, dirs, names in os.walk(src, followlinks=False):
            dirs[:] = [d for d in dirs if not _is_link(Path(top) / d)]
            for n in names:
                f = Path(top) / n
                if not _is_link(f):
                    files.append((f, dest / f.relative_to(src)))
    total = sum(f.stat().st_size for f, _ in files)
    for f, d in files:
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, d)
        if not _same_content(str(f), str(d), budget):
            return "verify_failed", 0
        report_bytes(f.stat().st_size)
    freed, complete = _remove(src)
    return ("moved" if complete else "partial"), total


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


def _remove(path: Path) -> tuple[int, bool]:
    """Delete a file or a folder tree. Links inside are removed as links; what they point to is never touched."""
    freed = 0
    if path.is_file():
        size = path.stat().st_size
        os.remove(path)
        return size, True
    for top, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            f = os.path.join(top, name)
            try:
                size = 0 if os.path.islink(f) else os.lstat(f).st_size
                os.remove(f)
                freed += size
            except OSError:
                pass  # in use: left alone
        for name in dirs:
            d = os.path.join(top, name)
            try:
                if _is_link(Path(d)):
                    try:
                        os.unlink(d)
                    except OSError:
                        os.rmdir(d)  # a Windows junction: removes the junction, not its target
                else:
                    os.rmdir(d)
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        pass
    return freed, not path.exists()


def clean(layout: Layout, request: dict[str, Any], budget_s: float = 7200.0,
          progress: Callable[[int], Any] | None = None) -> dict[str, Any]:
    budget = Budget(budget_s)
    result: dict[str, Any] = {"id": str(request.get("id") or ""), "safe": {}, "files": [], "folders": [], "moves": [], "freed": 0}
    moves = request.get("moves") or []
    planned = sum(int(m.get("bytes") or 0) for m in moves) or 1
    done = [0]

    def step(n: int) -> None:
        done[0] += n
        if progress:
            try:
                progress(min(99, int(100 * done[0] / planned)))
            except Exception:
                pass
    drives = {os.path.normcase(os.path.abspath(str(d))): d for d in layout.backup_drives}
    for item in moves:
        path, drive = Path(str(item.get("path") or "")), Path(str(item.get("drive") or ""))
        ok, _note = classify(path, layout) if path.name else (False, "")
        out: dict[str, Any] = {"path": str(path)}
        if not ok or _is_link(path) or os.path.normcase(os.path.abspath(str(drive))) not in drives:
            out["status"] = "not_allowed"
        elif not path.exists():
            out["status"] = "missing"
        else:
            prof = next(p for p in layout.profiles() if os.path.normcase(os.path.abspath(str(path))).startswith(
                os.path.normcase(os.path.abspath(str(p))) + os.sep))
            dest = drive / BACKUP_DIR / prof.name / path.relative_to(prof)
            need = path.stat().st_size if path.is_file() else dir_size(path, Budget(600))
            if shutil.disk_usage(drive).free < need * 1.02 + 100 * 1024 * 1024 * 0:
                out["status"] = "no_space"
            else:
                status, moved = _move(path, dest, budget, step)
                out.update(status=status, dest=str(dest))
                if status in ("moved", "partial"):
                    result["freed"] += moved
        result["moves"].append(out)
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
    for item in request.get("folders") or []:
        path = Path(str(item.get("path") or ""))
        ok, _note = classify(path, layout) if path.name else (False, "")
        if not ok or _is_link(path):
            status = "not_allowed"
        elif not path.exists():
            status = "missing"
        else:
            freed, complete = _remove(path)
            result["freed"] += freed
            status = "deleted" if complete else "partial"
        result.setdefault("folders", []).append({"path": str(path), "status": status})
    safe_keys = {k for k, kind, _ in PROFILE_PLACES if kind == "safe"} | {"recycle"}
    for key in request.get("safe") or []:
        if key not in safe_keys:
            continue
        freed = sum(_empty(d, 86400 if key == "temp" else 0, budget) for d in layout.safe_dirs(key))
        result["safe"][key] = freed
        result["freed"] += freed
    if progress:
        try:
            progress(100)
        except Exception:
            pass
    return result
