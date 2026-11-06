"""The vault's two halves (browser bundle and Python) must understand each other exactly."""

import json
import shutil
import subprocess
from importlib import resources

import pytest

from bonelia.security import vault

BUNDLE = resources.files("bonelia").joinpath("server/static/vault.js")


def test_python_round_trip_and_wrong_password():
    meta = vault.create("Kasa-Sifre-2026")
    assert vault.valid_meta(meta)
    priv = vault.unlock(meta, "Kasa-Sifre-2026")
    box = vault.seal(meta["pub"], {"password": "Ab3dEf7hJk", "note": "Kasse 1"})
    assert vault.valid_box(box)
    assert vault.open_box(priv, box) == {"password": "Ab3dEf7hJk", "note": "Kasse 1"}
    with pytest.raises(ValueError, match="wrong_password"):
        vault.unlock(meta, "falsch")
    # Every seal is different; nothing readable is in it.
    other = vault.seal(meta["pub"], {"password": "Ab3dEf7hJk"})
    assert other["ct"] != box["ct"] and "Ab3dEf7hJk" not in json.dumps(box)


def test_shape_checks_reject_garbage():
    meta = vault.create("x" * 12)
    box = vault.seal(meta["pub"], {"password": "p"})
    assert not vault.valid_box({**box, "extra": 1}) and not vault.valid_box({**box, "epk": "AAAA"})
    assert not vault.valid_box({**box, "ct": "!!"}) and not vault.valid_box("text")
    assert not vault.valid_meta({**meta, "kdf": {**meta["kdf"], "n": 2}}) and not vault.valid_meta({})
    assert vault.valid_public_key(meta["pub"]) and not vault.valid_public_key("abc")


def test_random_passwords_are_long_and_plain():
    pws = {vault.random_password() for _ in range(200)}
    assert len(pws) == 200
    assert all(len(p) == 16 and p.isalnum() and not set(p) & set("IOl01") for p in pws)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_browser_bundle_and_python_open_each_others_boxes():
    meta_py = vault.create("Ana-Sifre-1")
    box_py = vault.seal(meta_py["pub"], {"password": "PyToJs5678", "user": "admin"})
    script = """
const fs = require('fs'); eval(fs.readFileSync(process.argv[1], 'utf8'));
const V = globalThis.BoneliaVault; const input = JSON.parse(process.argv[2]);
(async () => {
  const priv = await V.unlock(input.meta, 'Ana-Sifre-1');
  const opened = V.open(priv, input.box);
  let wrong = null; try { await V.unlock(input.meta, 'yanlis'); } catch (e) { wrong = e.message; }
  const meta = await V.create('Telefon-Sifre-9');
  const box = V.seal(meta.pub, { password: 'JsToPy1234', note: 'Ü' });
  const pw = V.randomPassword();
  process.stdout.write(JSON.stringify({ opened, wrong, meta, box, pw }));
})().catch((e) => { console.error(e); process.exit(1); });
"""
    out = subprocess.run(["node", "-e", script, str(BUNDLE), json.dumps({"meta": meta_py, "box": box_py})],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    res = json.loads(out.stdout)
    assert res["opened"] == {"password": "PyToJs5678", "user": "admin"}
    assert res["wrong"] == "wrong_password"
    assert vault.valid_meta(res["meta"]) and vault.valid_box(res["box"])
    priv = vault.unlock(res["meta"], "Telefon-Sifre-9")
    assert vault.open_box(priv, res["box"]) == {"password": "JsToPy1234", "note": "Ü"}
    assert len(res["pw"]) == 16 and res["pw"].isalnum()
