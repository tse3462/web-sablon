"""Disk space report and approved cleanup (user request 06.11.2026: 80-90 GB free became 11-13 GB).

Nothing of the user's own is deleted unless the owner picked it in the panel; safe categories (temp,
recycle bin, caches) are cleaned only when asked, too."""

import os
import time
from pathlib import Path

from bonelia.collectors import disk

MB = 1024  # small scale for the test; the real thresholds are passed in the same unit
LIMITS = {"old_min": 100 * MB, "dup_min": 50 * MB}
DAY = 86400


def make(p: Path, size: int, age_days: float = 0, content: bytes | None = None) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content if content is not None else os.urandom(min(size, 512)) + b"\0" * max(0, size - 512))
    t = time.time() - age_days * DAY
    os.utime(p, (t, t))
    return p


def pc(tmp_path: Path) -> disk.Layout:
    users = tmp_path / "Users"
    anna = users / "anna"
    dl = anna / "Downloads"
    # Backups of the same shop, one per day: only the newest two are kept.
    for i, day in enumerate(("2026-10-01", "2026-10-15", "2026-11-01", "2026-11-05")):
        make(dl / f"veedelkorb-backup-{day}.zip", 30 * MB, age_days=40 - i * 10)
    make(dl / "veedelkorb-backup-2026-11-05 (1).zip", 30 * MB, age_days=1,
         content=(dl / "veedelkorb-backup-2026-11-05.zip").read_bytes())  # downloaded twice
    make(dl / "yedek_kasa_01.sql", 2 * MB, age_days=30); make(dl / "yedek_kasa_02.sql", 2 * MB, age_days=2)
    make(dl / "film.mp4", 200 * MB, age_days=120)          # old big download
    make(dl / "neu.mp4", 200 * MB, age_days=5)             # recent: not suggested
    big = os.urandom(512) + b"x" * (60 * MB)
    make(anna / "Documents" / "modell.bin", 0, age_days=10, content=big)
    make(dl / "modell-kopie.bin", 0, age_days=3, content=big)  # same content elsewhere: the Documents one stays
    make(anna / "AppData" / "Local" / "Temp" / "old.tmp", 5 * MB, age_days=3)
    make(anna / "AppData" / "Local" / "Temp" / "fresh.tmp", 1 * MB, age_days=0)
    make(anna / "AppData" / "Local" / "pip" / "Cache" / "wheels" / "a.whl", 8 * MB)
    make(anna / ".ollama" / "models" / "blobs" / "sha256-1", 40 * MB)
    make(tmp_path / "Recycle" / "S-1-5-21" / "$RABC.zip", 12 * MB)
    make(tmp_path / "Windows" / "Temp" / "w.tmp", 3 * MB, age_days=2)
    return disk.Layout(drive=tmp_path, users_root=users, system_root=tmp_path / "Windows", recycle_root=tmp_path / "Recycle")


def test_report_names_the_space_hogs_and_safe_suggestions(tmp_path):
    rep = disk.scan(pc(tmp_path), budget_s=30, **LIMITS)
    assert rep["drives"][0]["total"] > 0 and rep["drives"][0]["free"] > 0
    cats = {c["key"]: c for c in rep["categories"]}
    assert cats["temp"]["kind"] == "safe" and cats["temp"]["bytes"] >= 9 * MB
    assert cats["recycle"]["kind"] == "safe" and cats["recycle"]["bytes"] >= 12 * MB
    assert cats["pip_cache"]["bytes"] >= 8 * MB
    assert cats["ai_models"]["kind"] == "info" and cats["ai_models"]["bytes"] >= 40 * MB
    assert any(f["path"].endswith("Downloads") for f in rep["largest"])

    by_reason: dict[str, list[str]] = {}
    for s in rep["suggestions"]:
        by_reason.setdefault(s["reason"], []).append(Path(s["path"]).name)
    # Same backup series: the two newest stay; the duplicate download of the newest is a copy.
    assert sorted(by_reason["old_backup"]) == ["veedelkorb-backup-2026-10-01.zip", "veedelkorb-backup-2026-10-15.zip"]
    assert sorted(by_reason["duplicate"]) == ["modell-kopie.bin", "veedelkorb-backup-2026-11-05 (1).zip"]
    assert by_reason["old_download"] == ["film.mp4"]
    assert "yedek_kasa_02.sql" not in sum(by_reason.values(), []) and "neu.mp4" not in sum(by_reason.values(), [])
    assert all(len(s["id"]) == 16 and s["bytes"] > 0 for s in rep["suggestions"])
    assert len({s["path"] for s in rep["suggestions"]}) == len(rep["suggestions"])  # each file once


def test_backup_series_keys_ignore_dates_numbers_and_copy_marks():
    k = disk.series_key
    assert k("veedelkorb-backup-2026-11-01.zip") == k("veedelkorb-backup-2026-10-15 (2).zip")
    assert k("yedek_kasa_01.sql") == k("yedek_kasa_02.sql")
    assert k("Sicherung 05.11.2026 1430.tar.gz") == k("Sicherung 01.10.2026 0900.tar.gz")
    assert k("veedelkorb-backup.zip") != k("finanz-backup.zip")
    assert disk.is_backup("db_dump.sql") and disk.is_backup("Sicherung.zip") and not disk.is_backup("urlaub.zip")


def test_cleanup_deletes_only_what_was_picked_and_is_unchanged(tmp_path):
    layout = pc(tmp_path)
    rep = disk.scan(layout, budget_s=30, **LIMITS)
    pick = [s for s in rep["suggestions"] if s["reason"] in ("old_backup", "old_download")]
    changed = next(s for s in rep["suggestions"] if s["reason"] == "duplicate")
    Path(changed["path"]).write_bytes(b"changed since the report")       # must not be deleted now
    outside = {"path": str(tmp_path / "Windows" / "Temp" / "w.tmp"), "bytes": 3 * MB, "mtime": 0}
    result = disk.clean(layout, {"id": "c1", "safe": ["temp", "recycle"],
                                 "files": [{k: s[k] for k in ("path", "bytes", "mtime")} for s in pick + [changed]] + [outside]})
    assert result["id"] == "c1"
    st = {Path(r["path"]).name: r["status"] for r in result["files"]}
    assert all(st[Path(s["path"]).name] == "deleted" for s in pick)
    assert st[Path(changed["path"]).name] == "changed" and Path(changed["path"]).exists()
    assert st["w.tmp"] == "not_allowed"  # only user folders, never system places by file list
    assert not any(Path(s["path"]).exists() for s in pick)
    # Safe categories: temp files older than a day, and the recycle bin.
    assert not (tmp_path / "Users" / "anna" / "AppData" / "Local" / "Temp" / "old.tmp").exists()
    assert (tmp_path / "Users" / "anna" / "AppData" / "Local" / "Temp" / "fresh.tmp").exists()
    assert not list((tmp_path / "Recycle").rglob("*.zip"))
    assert result["freed"] >= (2 * 30 + 200 + 5 + 12) * MB
    # Things not asked for stay: AI models, pip cache, the newest backups.
    assert (tmp_path / "Users" / "anna" / ".ollama" / "models" / "blobs" / "sha256-1").exists()
    assert (tmp_path / "Users" / "anna" / "AppData" / "Local" / "pip" / "Cache" / "wheels" / "a.whl").exists()
    assert (tmp_path / "Users" / "anna" / "Downloads" / "veedelkorb-backup-2026-11-05.zip").exists()


def test_scan_respects_its_time_budget(tmp_path):
    layout = pc(tmp_path)
    rep = disk.scan(layout, budget_s=0, **LIMITS)
    assert rep["partial"] is True and "drives" in rep
