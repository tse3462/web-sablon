"""Disk space report and approved cleanup (user request 06.11.2026: 80-90 GB free became 11-13 GB).

Nothing of the user's own is deleted unless the owner picked it in the panel; safe categories (temp,
recycle bin, caches) are cleaned only when asked, too."""

import os
import time
from pathlib import Path

from bonelia.collectors import disk

MB = 1024  # small scale for the test; the real thresholds are passed in the same unit
LIMITS = {"old_min": 100 * MB, "dup_min": 50 * MB, "min_item": 1 * MB, "min_show": 500 * MB}
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
    # Which folder the size comes from (seen 06.11.2026: "AI models 18 GB" with one 2 GB Ollama model).
    parts = {Path(x["path"]).name: x["bytes"] for x in cats["ai_models"]["parts"]}
    assert parts == {"models": cats["ai_models"]["bytes"]} and cats["ai_models"]["parts"][0]["path"].endswith(".ollama" + os.sep + "models")
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


def test_backups_are_found_even_when_measuring_big_folders_runs_out_of_time(tmp_path, monkeypatch):
    """Seen 06.11.2026 on the owner's laptop: the scan spent its time on Docker/AppData and never reached
    the backups in Downloads. Suggestions now have their own share of the time and run first."""
    layout = pc(tmp_path)

    def exhausted(root, budget, memo=None):
        budget.hit = True  # as if the folder sizes took all their time
        return 0
    monkeypatch.setattr(disk, "dir_size", exhausted)
    rep = disk.scan(layout, budget_s=30, **LIMITS)
    assert rep["partial"] is True
    assert {s["reason"] for s in rep["suggestions"]} == {"old_backup", "duplicate", "old_download"}


def test_scan_reports_its_progress_step_by_step(tmp_path):
    """The panel shows a progress bar while a requested scan runs (user request 06.11.2026)."""
    seen = []
    disk.scan(pc(tmp_path), budget_s=30, progress=seen.append, **LIMITS)
    assert seen == sorted(seen) and seen[0] < 50 <= seen[-2] and seen[-1] == 100


def test_project_files_and_tiny_files_are_never_offered(tmp_path):
    """Seen 06.11.2026: two identical Supabase migration .sql files of a project in Downloads were offered
    as copies. Code and project folders are not the owner's backups; tiny files free nothing."""
    layout = pc(tmp_path)
    dl = tmp_path / "Users" / "anna" / "Downloads"
    mig = b"create table vault_snapshots(id int);" * 10
    for proj in ("shop-main", "shop-main (1)"):
        make(dl / proj / "supabase" / "migrations" / "20261018160000_create_vault_snapshots.sql", 0, age_days=20, content=mig)
    big = os.urandom(512) + b"y" * (80 * MB)
    make(dl / "repo" / ".git" / "objects" / "pack.bin", 0, age_days=5, content=big)
    make(dl / "repo-copy" / "pack.bin", 0, age_days=4, content=big)  # same content, but one side is inside a repo
    make(dl / "a" / "notiz.txt", 0, age_days=3, content=b"x" * 100)
    make(dl / "b" / "notiz.txt", 0, age_days=2, content=b"x" * 100)
    rep = disk.scan(layout, budget_s=30, **LIMITS)
    names = {Path(s["path"]).name for s in rep["suggestions"]}
    assert "20261018160000_create_vault_snapshots.sql" not in names and "notiz.txt" not in names
    assert "pack.bin" not in names
    assert "veedelkorb-backup-2026-10-01.zip" in names  # real backups are still offered


# --------------------------------------------------------------------- folders: look inside, delete one by one
def big_pc(tmp_path):
    layout = pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    make(home / ".lmstudio" / "models" / "lmstudio-community" / "Qwen-14B" / "q.gguf", 900 * MB)
    make(home / ".lmstudio" / "models" / "lmstudio-community" / "Llama-8B" / "l.gguf", 600 * MB)
    make(home / ".lmstudio" / "models" / "tiny" / "t.gguf", 10 * MB)                     # under 500 MB: not shown
    make(home / ".codex" / "sessions" / "2026" / "s.jsonl", 700 * MB)
    make(home / ".codex" / "auth.json", 1 * MB)
    make(home / "AppData" / "Local" / "Docker" / "wsl" / "disk" / "docker_data.vhdx", 1200 * MB)
    make(home / "AppData" / "Local" / "Claude-Data" / "vm" / "rootfs.img", 800 * MB)
    make(home / "AppData" / "Local" / "Microsoft" / "Edge" / "x.bin", 700 * MB)            # system: never shown
    make(home / "Downloads" / "Projekte-Archiv" / "alt.iso", 650 * MB)
    return layout


def walk(items):
    for it in items:
        yield it
        yield from walk(it.get("children") or [])


def test_folders_open_up_hide_small_and_system_ones_and_say_what_may_go(tmp_path):
    rep = disk.scan(big_pc(tmp_path), budget_s=30, **LIMITS)
    by_name = {Path(i["path"]).name: i for i in walk(rep["largest"])}
    assert "Microsoft" not in by_name and "Packages" not in by_name          # system folders are not shown
    assert "tiny" not in by_name and all(i["bytes"] >= 500 * MB for i in by_name.values())
    lm = by_name[".lmstudio"]
    assert lm["deletable"] is False                                          # the app's own folder stays
    assert by_name["models"]["deletable"] is True                            # its models may go, all or one by one
    assert by_name["Qwen-14B"]["deletable"] is True and by_name["Qwen-14B"]["bytes"] >= 900 * MB
    assert by_name["Docker"]["deletable"] is False and by_name["Docker"]["note"] == "docker"
    assert by_name["Claude-Data"]["deletable"] is False and by_name["Claude-Data"]["note"] == "app"
    assert by_name[".codex"]["deletable"] is False and by_name["sessions"]["deletable"] is True
    assert by_name["Downloads"]["deletable"] is False and by_name["Projekte-Archiv"]["deletable"] is True
    assert all(len(i["id"]) == 16 for i in by_name.values())
    # The AI models category says where its size is, with the same open-up details.
    ai = next(c for c in rep["categories"] if c["key"] == "ai_models")
    assert any(Path(p["path"]).name == "models" and p["deletable"] for p in ai["parts"])


def test_folder_cleanup_deletes_only_allowed_places_and_never_follows_links(tmp_path):
    layout = big_pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    qwen = home / ".lmstudio" / "models" / "lmstudio-community" / "Qwen-14B"
    req = {"id": "f1", "folders": [{"path": str(qwen), "bytes": 900 * MB},
                                   {"path": str(home / ".ollama"), "bytes": 40 * MB},
                                   {"path": str(home / "AppData" / "Local" / "Docker"), "bytes": 1200 * MB},
                                   {"path": str(home / "Downloads"), "bytes": 1},
                                   {"path": str(tmp_path / "Windows"), "bytes": 1}]}
    res = disk.clean(layout, req)
    st = {Path(r["path"]).name: r["status"] for r in res["folders"]}
    assert st == {"Qwen-14B": "deleted", ".ollama": "not_allowed", "Docker": "not_allowed", "Downloads": "not_allowed",
                  "Windows": "not_allowed"}
    assert not qwen.exists() and (home / ".lmstudio" / "models" / "lmstudio-community" / "Llama-8B").exists()
    assert res["freed"] >= 900 * MB
    assert (home / ".ollama" / "models" / "blobs" / "sha256-1").exists()


def test_folder_cleanup_removes_a_link_but_not_what_it_points_to(tmp_path):
    layout = big_pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    keep = tmp_path / "elsewhere"
    make(keep / "important.doc", 2 * MB)
    target = home / "Downloads" / "Projekte-Archiv"
    try:
        os.symlink(keep, target / "link-to-elsewhere", target_is_directory=True)
    except (OSError, NotImplementedError):
        return  # no symlinks allowed here (e.g. Windows without developer mode)
    res = disk.clean(layout, {"id": "f2", "folders": [{"path": str(target), "bytes": 650 * MB}]})
    assert res["folders"][0]["status"] == "deleted" and not target.exists()
    assert (keep / "important.doc").exists()


# --------------------------------------------------------------------- advice and "move to the backup drive"
def advice_pc(tmp_path):
    layout = big_pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    models = home / ".lmstudio" / "models"
    for f in models.rglob("*"):
        if f.is_file():
            t = time.time() - 200 * DAY
            os.utime(f, (t, t))                                          # LM Studio models untouched for 200 days
    make(home / ".codex" / "sessions" / "2026" / "s.jsonl", 700 * MB, age_days=1)  # Codex used yesterday
    backup = tmp_path / "D"
    backup.mkdir()
    src = home / "Downloads" / "Projekte-Archiv" / "alt.iso"
    (backup / "AI-Proje-Yedekleri" / "Projekte-Archiv").mkdir(parents=True)
    (backup / "AI-Proje-Yedekleri" / "Projekte-Archiv" / "alt.iso").write_bytes(src.read_bytes())  # already backed up
    layout.backup_drives = [backup]
    return layout


def test_advice_says_what_is_backed_up_unused_or_in_use(tmp_path):
    rep = disk.scan(advice_pc(tmp_path), budget_s=30, **LIMITS)
    adv = {Path(a["path"]).name: a for a in rep["advice"]}
    assert adv["Projekte-Archiv"]["why"] == "has_backup" and adv["Projekte-Archiv"]["backup"].endswith("Projekte-Archiv")
    assert adv["models"]["why"] == "unused" and adv["models"]["days"] >= 199  # the whole models folder, not each model again
    assert "Qwen-14B" not in adv and "sessions" not in adv                   # in use: no advice
    assert rep["backup_drives"][0]["name"] == str(tmp_path / "D")
    nodes = {Path(n["path"]).name: n for n in walk(rep["largest"])}
    assert nodes["sessions"]["use"] == "in_use" and nodes["Qwen-14B"]["use"] == "unused"


def test_move_copies_checks_every_byte_then_deletes_the_original(tmp_path):
    layout = advice_pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    qwen = home / ".lmstudio" / "models" / "lmstudio-community" / "Qwen-14B"
    original = (qwen / "q.gguf").read_bytes()
    seen = []
    res = disk.clean(layout, {"id": "m1", "moves": [{"path": str(qwen), "bytes": 900 * MB, "drive": str(tmp_path / "D")}]},
                     progress=seen.append)
    [m] = res["moves"]
    assert m["status"] == "moved" and not qwen.exists()
    dest = Path(m["dest"])
    assert dest == tmp_path / "D" / "BONELIA-Yedek" / "anna" / ".lmstudio" / "models" / "lmstudio-community" / "Qwen-14B"
    assert (dest / "q.gguf").read_bytes() == original
    assert res["freed"] >= 900 * MB and seen and seen[-1] == 100


def test_move_keeps_the_original_when_space_is_short_or_a_copy_differs(tmp_path, monkeypatch):
    layout = advice_pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    llama = home / ".lmstudio" / "models" / "lmstudio-community" / "Llama-8B"
    real_usage = disk.shutil.disk_usage
    monkeypatch.setattr(disk.shutil, "disk_usage", lambda p: real_usage(p)._replace(free=10) if str(p).startswith(str(tmp_path / "D")) else real_usage(p))
    res = disk.clean(layout, {"id": "m2", "moves": [{"path": str(llama), "bytes": 600 * MB, "drive": str(tmp_path / "D")}]})
    assert res["moves"][0]["status"] == "no_space" and llama.exists()
    monkeypatch.setattr(disk.shutil, "disk_usage", real_usage)
    monkeypatch.setattr(disk, "_same_content", lambda a, b, budget: False)  # e.g. a failing USB stick
    res = disk.clean(layout, {"id": "m3", "moves": [{"path": str(llama), "bytes": 600 * MB, "drive": str(tmp_path / "D")}]})
    assert res["moves"][0]["status"] == "verify_failed" and (llama / "l.gguf").exists()
    # Only to a backup drive the PC itself found, only from places that may be cleaned.
    res = disk.clean(layout, {"id": "m4", "moves": [{"path": str(llama), "bytes": 1, "drive": str(tmp_path / "elsewhere")},
                                                    {"path": str(home / ".ollama"), "bytes": 1, "drive": str(tmp_path / "D")}]})
    assert [m["status"] for m in res["moves"]] == ["not_allowed", "not_allowed"]


def test_cleanup_tells_when_the_space_did_not_come_back(tmp_path, monkeypatch):
    """Seen 06.11.2026: 17 GB of an LM Studio model deleted, free space unchanged, because a program still held
    the file open (Windows frees the space only when the last handle closes). The result says so."""
    layout = big_pc(tmp_path)
    home = tmp_path / "Users" / "anna"
    usage = disk.shutil.disk_usage(tmp_path)
    monkeypatch.setattr(disk.shutil, "disk_usage", lambda p: usage)  # free space does not change
    res = disk.clean(layout, {"id": "h1", "folders": [{"path": str(home / ".lmstudio" / "models"), "bytes": 1}]}, held_min=MB)
    assert res["freed"] >= 1500 * MB and res["free_gain"] == 0 and res["held"] is True
