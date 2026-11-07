"""Server backup for a reinstall (user request 06.11.2026): everything that is not on GitHub -- the server key the
agents trust, the database, the phone panel's token -- copied and checked file by file, and put back after a format."""

import json
import sqlite3
from datetime import datetime

import pytest

from bonelia.server import backup as bk


def server_dir(tmp_path):
    d = tmp_path / "server-data"
    d.mkdir()
    (d / "server_ed25519.key").write_bytes(b"KEY-1")
    (d / "dashboard.token").write_text("tok")
    db = sqlite3.connect(d / "bonelia.db")
    db.execute("create table t (x)")
    db.execute("insert into t values (42)")
    db.commit()
    db.close()
    (d / "panel-url.txt").write_text("http://x")  # rebuilt at start: not needed
    return d


def test_backup_copies_key_database_and_token_and_checks_them(tmp_path):
    d = server_dir(tmp_path)
    extra = tmp_path / "server-state.conf"
    extra.write_text("tailscale")
    out = bk.make_backup(d, tmp_path / "usb" / "BONELIA-Yedek", extras={"tailscale/server-state.conf": extra},
                         info={"agent_device_id": "dev_abc", "root": "C:\\BoneliaAI\\web-sablon\\bonelia-ai"},
                         now=datetime(2026, 11, 6, 20, 15, 0))
    assert out.name == "sunucu-20261106-201500"
    m = json.loads((out / "manifest.json").read_text())
    assert set(m["files"]) == {"data/server_ed25519.key", "data/dashboard.token", "data/bonelia.db", "extras/tailscale/server-state.conf"}
    assert m["info"]["agent_device_id"] == "dev_abc"
    assert sqlite3.connect(out / "data" / "bonelia.db").execute("select x from t").fetchone() == (42,)
    assert bk.verify(out) == []
    (out / "data" / "server_ed25519.key").write_bytes(b"BROKEN")
    assert bk.verify(out) == ["data/server_ed25519.key"]


def test_a_backup_without_the_server_key_is_refused(tmp_path):
    d = server_dir(tmp_path)
    (d / "server_ed25519.key").unlink()
    with pytest.raises(FileNotFoundError):
        bk.make_backup(d, tmp_path / "usb")


def test_only_the_newest_backups_are_kept_and_the_latest_is_found(tmp_path):
    d = server_dir(tmp_path)
    root = tmp_path / "usb" / "BONELIA-Yedek"
    for i in range(7):
        bk.make_backup(d, root, now=datetime(2026, 11, 1 + i, 9, 0, 0), keep=5)
    names = sorted(p.name for p in root.iterdir() if p.is_dir())
    assert len(names) == 5 and names[0] == "sunucu-20261103-090000"
    assert bk.latest(root).name == "sunucu-20261107-090000"
    (root / "sunucu-20261108-090000").mkdir()  # an unfinished copy has no manifest: never picked
    assert bk.latest(root).name == "sunucu-20261107-090000"


def test_restore_puts_everything_back_and_keeps_a_different_existing_server_aside(tmp_path):
    d = server_dir(tmp_path)
    out = bk.make_backup(d, tmp_path / "usb", now=datetime(2026, 11, 6, 9, 0, 0))
    fresh = tmp_path / "new-pc" / "server-data"
    fresh.mkdir(parents=True)
    (fresh / "server_ed25519.key").write_bytes(b"KEY-NEW")  # the server was started once before the restore
    res = bk.restore(out, fresh, now=datetime(2026, 11, 6, 21, 0, 0))
    assert (fresh / "server_ed25519.key").read_bytes() == b"KEY-1"
    assert sqlite3.connect(fresh / "bonelia.db").execute("select x from t").fetchone() == (42,)
    assert res["moved_aside"] and (tmp_path / "new-pc" / "server-data.onceki-20261106-210000" / "server_ed25519.key").read_bytes() == b"KEY-NEW"
    # a damaged backup is never restored
    (out / "data" / "bonelia.db").write_bytes(b"x")
    with pytest.raises(ValueError):
        bk.restore(out, tmp_path / "other")


def test_command_line(tmp_path, capsys):
    d = server_dir(tmp_path)
    cfg = tmp_path / "server.toml"
    cfg.write_text(f'[server]\ndata_dir = "{d.as_posix()}"\n')
    assert bk.main(["make", "--config", str(cfg), "--dest", str(tmp_path / "usb"), "--info", "agent_device_id=dev_x"]) == 0
    made = json.loads(capsys.readouterr().out)
    assert made["ok"] and bk.verify(made["folder"]) == []
    assert bk.main(["latest", "--root", str(tmp_path / "usb")]) == 0
    assert json.loads(capsys.readouterr().out)["folder"] == made["folder"]


def test_a_made_backup_is_recorded_for_the_panel_and_its_age_is_known(tmp_path, capsys):
    """Weekly backup (06.11.2026): the server learns when the last backup was made (panel + reminder), and the
    automatic run knows whether the newest one on the stick is a week old already."""
    from bonelia.server.store import Store

    d = server_dir(tmp_path)
    cfg = tmp_path / "server.toml"
    cfg.write_text(f'[server]\ndata_dir = "{d.as_posix()}"\n')
    assert bk.main(["make", "--config", str(cfg), "--dest", str(tmp_path / "usb"), "--record"]) == 0
    made = json.loads(capsys.readouterr().out)
    rec = Store(d / "bonelia.db").get_setting("server_backup")
    assert rec["folder"] == made["folder"] and rec["at"]
    assert bk.main(["latest", "--root", str(tmp_path / "usb")]) == 0
    assert json.loads(capsys.readouterr().out)["age_days"] == 0
    assert bk.main(["latest", "--root", str(tmp_path / "nothing")]) == 1
    assert json.loads(capsys.readouterr().out)["age_days"] is None
