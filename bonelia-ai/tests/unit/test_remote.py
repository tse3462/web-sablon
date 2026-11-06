"""RustDesk remote access: the agent reads the PC's RustDesk ID (user request 06.11.2026)."""

from bonelia.collectors.remote import parse_rustdesk_id, rustdesk_info, set_rustdesk_password


def test_parse_id_from_command_output_and_config():
    assert parse_rustdesk_id("123456789\r\n") == "123456789"
    assert parse_rustdesk_id("ID: 1 234 567 890") == "1234567890"
    assert parse_rustdesk_id("id = '987654321'\nenc_id = ''\n") == "987654321"
    assert parse_rustdesk_id("") is None and parse_rustdesk_id("error: not running") is None
    assert parse_rustdesk_id("12345") is None  # too short to be a RustDesk ID


def test_rustdesk_info_uses_the_installed_program_then_the_config_file(tmp_path):
    exe = tmp_path / "rustdesk.exe"; exe.write_bytes(b"x")
    cfg = tmp_path / "RustDesk.toml"; cfg.write_text("id = '555666777'\n")
    calls = []

    def run(cmd):
        calls.append(cmd)
        return (0, "STATE : 4 RUNNING") if cmd[0] == "sc" else (1, "")

    info = rustdesk_info(exe_paths=[exe], config_paths=[cfg], run=run, windows=True)
    assert info == {"installed": True, "rustdesk_id": "555666777", "service": "running"}
    assert [str(exe), "--get-id"] in calls
    assert rustdesk_info(exe_paths=[tmp_path / "none.exe"], config_paths=[], run=run, windows=True) == {
        "installed": False, "rustdesk_id": None, "service": "missing"}
    assert rustdesk_info(windows=False) is None


def test_new_password_counts_only_when_rustdesk_says_done(tmp_path):
    """Seen 06.11.2026: RustDesk exits with 0 even when it refuses; only "Done!" means the password changed."""
    exe = tmp_path / "rustdesk.exe"; exe.write_bytes(b"x")

    def with_output(text):
        calls = []
        result = set_rustdesk_password("Ab3dEf7hJk2mNp4q", exe_paths=[exe], windows=True,
                                       run=lambda cmd: (calls.append(cmd), (0, text))[1])
        return result, calls

    result, calls = with_output("Done!\r\n")
    assert result == "ok" and calls == [[str(exe), "--password", "Ab3dEf7hJk2mNp4q"]]
    assert with_output("Installation and administrative privileges required!\n")[0] == "not_admin"
    assert with_output("Settings are disabled!\n")[0] == "disabled"
    assert with_output("Changing permanent password is disabled!\n")[0] == "disabled"
    assert with_output("Changing permanent password was rejected by daemon\n")[0] == "rejected"
    assert with_output("")[0] == "failed"
    assert set_rustdesk_password("with space", exe_paths=[exe], windows=True, run=lambda c: (0, "Done!")) == "invalid"
    assert set_rustdesk_password("Ab3dEf7hJk2mNp4q", exe_paths=[tmp_path / "nope.exe"], windows=True) == "missing"
    assert set_rustdesk_password("Ab3dEf7hJk2mNp4q", windows=False) == "not_windows"
