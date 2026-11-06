"""Programs on the PC for the automatic rescue (user request 06.11.2026): which windows do not answer, how much
memory each program uses, and the Windows calls to end, close and start a program.

Two ways the agent runs:
* as the signed-in user (the owner's own PC): everything is read and done directly;
* as SYSTEM in session 0 (customer PCs): Windows hides the user's windows from session 0, so a small
  watcher (``session-watch``) is started in the signed-in user's session. It only writes which windows do
  not answer into %ProgramData%\\BONELIA-AI\\session\\<session>\\ (a folder made by the agent that only that
  user may write into); the agent reads it as untrusted data and checks every process itself (that program,
  owned by that user, never a Windows program). Ending, closing and starting all run IN the user's session
  WITH the user's own rights (CreateProcessAsUser + taskkill), so Windows itself refuses anything the user
  could not do -- a forged report can never make SYSTEM end or start something on its behalf.
* On the owner's PC the agent is elevated; a program is started again with the desktop's normal rights
  (explorer's token) or not at all -- never elevated.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

IS_WINDOWS = sys.platform == "win32"
STATES_FRESH_S = 45  # the watcher writes every 10 s
HELPER_RETRY_S = 60
ALIVE_STALE_S = 300  # the watcher stops when the agent has not been seen for five minutes
MAX_WINDOWS = 500
MAX_REPORT_BYTES = 256 * 1024


# ---------- data written by the watcher (user-writable, so parsed defensively)
def parse_states(raw: Any) -> dict[int, bool]:
    """{"states": {"<pid>": true/false}} -> {pid: hung}; anything else is ignored."""
    out: dict[int, bool] = {}
    states = raw.get("states") if isinstance(raw, dict) else None
    if not isinstance(states, dict):
        return out
    for k, v in list(states.items())[:MAX_WINDOWS]:
        if isinstance(k, str) and k.isascii() and k.isdecimal() and len(k) <= 10 and 0 < int(k) < 2**32 and isinstance(v, bool):
            out[int(k)] = v
    return out


def read_states(path: Path, now: float | None = None) -> dict[int, bool] | None:
    """The watcher's last report, or None when it is missing or older than STATES_FRESH_S."""
    now = time.time() if now is None else now
    try:
        st = os.lstat(path)
        if path.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400 or not path.is_file():  # no links
            return None
        if now - st.st_mtime > STATES_FRESH_S or st.st_size > MAX_REPORT_BYTES:
            return None
        with open(path, "rb") as f:
            data = f.read(MAX_REPORT_BYTES + 1)
        return parse_states(json.loads(data.decode("utf-8"))) if len(data) <= MAX_REPORT_BYTES else None
    except (OSError, ValueError):
        return None


def session_watch(folder: Path, alive: Path, window_states: Callable[[], dict[int, bool]] | None = None,
                  interval_s: float = 10, rounds: int | None = None,
                  clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                  single: Callable[[], bool] | None = None) -> int:
    """The watcher in the user's session: write which windows do not answer into <folder>/windows.json; stop when
    the agent is gone (``alive`` older than five minutes) or another watcher already runs in this session."""
    if not (single or _single_watcher)():
        return 0
    window_states = window_states or windows_hung_states
    out = folder / "windows.json"
    n = 0
    while rounds is None or n < rounds:
        n += 1
        try:
            if clock() - alive.stat().st_mtime > ALIVE_STALE_S:
                return 0
        except OSError:
            return 0
        try:
            states = window_states()
            tmp = out.with_suffix(".tmp")
            tmp.write_text(json.dumps({"at": int(clock()), "pid": os.getpid(), "states": {str(k): bool(v) for k, v in states.items()}}),
                           encoding="utf-8")
            os.replace(tmp, out)
        except OSError:
            pass
        sleep(interval_s)
    return 0


def system32(name: str) -> str:
    """Windows' own tools by full path: never a same-named file from the program's folder or the PATH."""
    if not IS_WINDOWS:
        return name
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


_MUTEX = None


def _single_watcher() -> bool:
    """One watcher per session (a per-session named mutex); off Windows always True."""
    global _MUTEX
    if not IS_WINDOWS:
        return True
    _MUTEX = _k32.CreateMutexW(None, False, "Local\\BONELIA-AI-session-watch")
    return bool(_MUTEX) and ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


# ---------- Windows calls (ctypes); every function is harmless off Windows
if IS_WINDOWS:  # pragma: no cover - exercised by tests/windows on a real Windows host
    import ctypes
    from ctypes import wintypes

    def _dll(name: str):  # by full path: a planted DLL next to the program is never loaded
        return ctypes.WinDLL(system32(name + ".dll"), use_last_error=True)

    _k32 = _dll("kernel32")
    _u32 = _dll("user32")
    _adv = _dll("advapi32")
    _wts = _dll("wtsapi32")
    _env = _dll("userenv")
    _k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.CreateMutexW.restype = wintypes.HANDLE

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _u32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
    _u32.IsWindowVisible.argtypes = [wintypes.HWND]
    _u32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    _u32.GetWindow.restype = wintypes.HWND
    _u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    _u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _u32.IsHungAppWindow.argtypes = [wintypes.HWND]
    _u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _k32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE

    class _STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD),
                    ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD)]

    class _WTS_SESSION_INFO(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR), ("State", ctypes.c_int)]

    _wts.WTSQueryUserToken.argtypes = [wintypes.ULONG, ctypes.POINTER(wintypes.HANDLE)]
    _wts.WTSEnumerateSessionsW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.POINTER(ctypes.POINTER(_WTS_SESSION_INFO)), ctypes.POINTER(wintypes.DWORD)]
    _wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    _wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int, ctypes.POINTER(wintypes.LPWSTR),
                                                 ctypes.POINTER(wintypes.DWORD)]
    _adv.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                      ctypes.POINTER(wintypes.HANDLE)]
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _adv.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                          wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                          ctypes.POINTER(_STARTUPINFO), ctypes.POINTER(_PROCESS_INFORMATION)]
    _adv.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                                             ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(_STARTUPINFO),
                                             ctypes.POINTER(_PROCESS_INFORMATION)]
    _env.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.BOOL]
    _env.DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]

    _GW_OWNER, _WM_CLOSE = 4, 0x0010
    _MAXIMUM_ALLOWED, _SECURITY_IMPERSONATION, _TOKEN_PRIMARY = 0x02000000, 2, 1
    _CREATE_UNICODE_ENVIRONMENT, _CREATE_NO_WINDOW, _CREATE_NEW_CONSOLE = 0x400, 0x08000000, 0x10
    _STARTF_USESHOWWINDOW, _SW_HIDE, _SW_SHOWNORMAL = 1, 0, 1
    _PROCESS_QUERY_INFORMATION = 0x0400
    _TOKEN_DUP = 0x0001 | 0x0002 | 0x0008  # assign primary, duplicate, query


def own_session_id() -> int:
    if not IS_WINDOWS:
        return -1
    return process_session(os.getpid())


def process_session(pid: int) -> int:
    if not IS_WINDOWS:
        return -1
    sid = wintypes.DWORD()
    return int(sid.value) if _k32.ProcessIdToSessionId(int(pid), ctypes.byref(sid)) else -1


def active_session_id() -> int | None:
    """The session of the person at the PC (also over Remote Desktop); None when nobody is signed in."""
    if not IS_WINDOWS:
        return None
    info, count = ctypes.POINTER(_WTS_SESSION_INFO)(), wintypes.DWORD()
    if _wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(info), ctypes.byref(count)):
        try:
            for i in range(count.value):
                if info[i].State == 0 and info[i].SessionId != 0:  # WTSActive
                    return int(info[i].SessionId)
        finally:
            _wts.WTSFreeMemory(info)
    return None


def session_user(sid: int) -> str | None:
    """DOMAIN\\user signed in to that session."""
    if not IS_WINDOWS:
        return None

    def q(cls: int) -> str:
        buf, n = wintypes.LPWSTR(), wintypes.DWORD()
        if not _wts.WTSQuerySessionInformationW(None, sid, cls, ctypes.byref(buf), ctypes.byref(n)):
            return ""
        try:
            return buf.value or ""
        finally:
            _wts.WTSFreeMemory(buf)

    user, domain = q(5), q(7)  # WTSUserName, WTSDomainName
    return f"{domain}\\{user}" if user and domain else (user or None)


def _top_windows() -> list[tuple[int, int]]:
    """(hwnd, pid) of visible, titled top-level windows of this session (what the user sees on the taskbar)."""
    out: list[tuple[int, int]] = []

    def cb(hwnd, _):
        if _u32.IsWindowVisible(hwnd) and not _u32.GetWindow(hwnd, _GW_OWNER) and _u32.GetWindowTextLengthW(hwnd) > 0:
            pid = wintypes.DWORD()
            _u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                out.append((hwnd, int(pid.value)))
        return len(out) < MAX_WINDOWS

    _u32.EnumWindows(_WNDENUMPROC(cb), 0)
    return out


def windows_hung_states() -> dict[int, bool]:
    """{pid: hung} for programs with a window in THIS session; hung if any of its windows does not answer."""
    if not IS_WINDOWS:
        return {}
    states: dict[int, bool] = {}
    for hwnd, pid in _top_windows():
        states[pid] = states.get(pid, False) or bool(_u32.IsHungAppWindow(hwnd))
    return states


def _startupinfo(hidden: bool):
    si = _STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    si.lpDesktop = "winsta0\\default"
    si.dwFlags = _STARTF_USESHOWWINDOW
    si.wShowWindow = _SW_HIDE if hidden else _SW_SHOWNORMAL
    return si


def _finish(pi, wait_s: float | None) -> int:
    try:
        if wait_s:
            _k32.WaitForSingleObject(pi.hProcess, int(wait_s * 1000))
        return int(pi.dwProcessId)
    finally:
        _k32.CloseHandle(pi.hThread)
        _k32.CloseHandle(pi.hProcess)


def run_as_active_user(cmdline: str, cwd: str | None = None, hidden: bool = True, wait_s: float | None = None,
                       app: str | None = None) -> int | None:
    """Start a program in the signed-in user's session as that user (only possible for SYSTEM).
    app: the program file by full path (then the command line's first word is only its name for the program)."""
    if not IS_WINDOWS:
        return None
    sid = active_session_id()
    if sid is None:
        return None
    user, primary, env = wintypes.HANDLE(), wintypes.HANDLE(), ctypes.c_void_p()
    if not _wts.WTSQueryUserToken(sid, ctypes.byref(user)):
        return None
    try:
        if not _adv.DuplicateTokenEx(user, _MAXIMUM_ALLOWED, None, _SECURITY_IMPERSONATION, _TOKEN_PRIMARY, ctypes.byref(primary)):
            return None
        try:
            if not _env.CreateEnvironmentBlock(ctypes.byref(env), primary, False):
                return None  # never start the user's program with SYSTEM's environment
            si, pi = _startupinfo(hidden), _PROCESS_INFORMATION()
            flags = _CREATE_UNICODE_ENVIRONMENT | (_CREATE_NO_WINDOW if hidden else _CREATE_NEW_CONSOLE)
            ok = _adv.CreateProcessAsUserW(primary, app, ctypes.create_unicode_buffer(cmdline), None, None, False, flags,
                                           env, cwd if cwd and os.path.isdir(cwd) else None, ctypes.byref(si), ctypes.byref(pi))
            return _finish(pi, wait_s) if ok else None
        finally:
            if env:
                _env.DestroyEnvironmentBlock(env)
            _k32.CloseHandle(primary)
    finally:
        _k32.CloseHandle(user)


def _run_as_shell_user(cmdline: str, cwd: str | None, app: str | None = None) -> int | None:
    """An elevated agent (owner's PC) starts programs with the desktop's normal rights, like a double-click:
    the token of explorer.exe in this session."""
    import psutil

    me = own_session_id()
    shell = next((p for p in psutil.process_iter(["name", "pid"]) if (p.info.get("name") or "").lower() == "explorer.exe"
                  and process_session(p.info["pid"]) == me), None)
    if shell is None:
        return None
    hp = _k32.OpenProcess(_PROCESS_QUERY_INFORMATION, False, shell.info["pid"])
    if not hp:
        return None
    tok, primary = wintypes.HANDLE(), wintypes.HANDLE()
    try:
        if not _adv.OpenProcessToken(hp, _TOKEN_DUP, ctypes.byref(tok)):
            return None
        try:
            if not _adv.DuplicateTokenEx(tok, _MAXIMUM_ALLOWED, None, _SECURITY_IMPERSONATION, _TOKEN_PRIMARY, ctypes.byref(primary)):
                return None
            si, pi = _startupinfo(False), _PROCESS_INFORMATION()
            ok = _adv.CreateProcessWithTokenW(primary, 0, app, ctypes.create_unicode_buffer(cmdline), 0, None,
                                              cwd if cwd and os.path.isdir(cwd) else None, ctypes.byref(si), ctypes.byref(pi))
            return _finish(pi, None) if ok else None
        finally:
            _k32.CloseHandle(tok)
            if primary:
                _k32.CloseHandle(primary)
    finally:
        _k32.CloseHandle(hp)


def _is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------- what the agent uses
def agent_session_dir() -> Path:
    from ..agent.install import agent_dir
    return agent_dir() / "session"


def _is_link(p: Path) -> bool:
    try:
        return p.is_symlink() or bool(getattr(os.lstat(p), "st_file_attributes", 0) & 0x400)  # symlink or junction
    except OSError:
        return False


def _icacls(*args: str) -> bool:
    r = subprocess.run([system32("icacls.exe"), *args], capture_output=True, check=False,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return r.returncode == 0


def helper_command(folder: Path, alive: Path) -> tuple[str, str]:
    """(program file, command line) of the watcher; the program file is passed by full path."""
    if getattr(sys, "frozen", False):
        app = sys.executable
        args = [app, "session-watch", "--dir", str(folder), "--alive", str(alive)]
    else:
        exe = Path(sys.executable)
        pyw = exe.with_name("pythonw.exe")
        app = str(pyw if pyw.is_file() else exe)
        args = [app, "-m", "bonelia", "session-watch", "--dir", str(folder), "--alive", str(alive)]
    return app, subprocess.list2cmdline(args)


class WindowsOps:
    """The PC as seen by the rescue tools and the rescue logic."""

    def __init__(self, folder: Path | None = None, clock: Callable[[], float] = time.time):
        self.service = IS_WINDOWS and own_session_id() == 0
        self.folder = folder or agent_session_dir()
        self.clock = clock
        self._helper_at = 0.0
        self._ready: dict[tuple[int, str], Path] = {}

    # -- whose session
    def target_session(self) -> int | None:
        return active_session_id() if self.service else own_session_id()

    def target_user(self) -> str | None:
        if self.service:
            sid = active_session_id()
            return session_user(sid) if sid is not None else None
        import psutil
        try:
            return psutil.Process(os.getpid()).username()
        except psutil.Error:
            return None

    # -- reading
    def hung_states(self) -> dict[int, bool] | None:
        if not self.service:
            return windows_hung_states()
        sid = active_session_id()
        user = session_user(sid) if sid is not None else None
        if sid is None or not user:
            return None
        d = self._session_folder(sid, user)
        if d is None:
            return None
        states = read_states(d / "windows.json", self.clock())
        if states is None and self.clock() - self._helper_at >= HELPER_RETRY_S:
            self._helper_at = self.clock()  # the watcher itself refuses to run twice in a session
            app, line = helper_command(d, self.folder / "agent.alive")
            run_as_active_user(line, hidden=True, app=app)
        return states

    def _session_folder(self, sid: int, user: str) -> Path | None:
        """Session 0: a folder only the signed-in user may write files into (not delete or replace), made and
        secured by the agent; agent.alive lies one level up where users may only read."""
        import hashlib

        try:
            if _is_link(self.folder):
                return None
            self.folder.mkdir(parents=True, exist_ok=True)
            (self.folder / "agent.alive").write_text(str(int(self.clock())), encoding="ascii")
        except OSError:
            return None
        key = (sid, user.lower())
        d = self._ready.get(key)
        if d is not None and d.is_dir() and not _is_link(d):
            return d
        d = self.folder / f"{sid}-{hashlib.sha256(user.lower().encode()).hexdigest()[:10]}"
        try:
            if d.exists() or _is_link(d):  # left from before (or made by someone else): moved aside, never reused
                os.rename(d, d.with_name(d.name + f".old{int(self.clock())}"))
            d.mkdir()
        except OSError:
            return None
        if not _icacls(str(d), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
                       f"{user}:(RX,WD)", f"{user}:(OI)(IO)M"):
            return None
        self._ready[key] = d
        return d

    def snapshot(self) -> dict[str, Any] | None:
        if not IS_WINDOWS:
            return None
        import psutil

        vm = psutil.virtual_memory()
        states = self.hung_states() or {}
        procs = []
        for pid, hung in states.items():
            try:
                p = psutil.Process(pid)
                rss = p.memory_info().rss
                for c in p.children(recursive=True):  # e.g. a browser keeps most of its memory in child processes
                    try:
                        rss += c.memory_info().rss
                    except (psutil.Error, OSError):
                        pass
                procs.append({"pid": pid, "name": p.name(), "mb": int(rss / 1024**2), "hung": bool(hung),
                              "started": round(p.create_time(), 1)})
            except (psutil.Error, OSError):
                continue
        return {"mem_pct": round(vm.percent, 1), "total_mb": int(vm.total / 1024**2), "procs": procs}

    # -- for the tools
    def info(self, pid: int) -> dict[str, Any] | None:
        """The program behind a number: name, its own program file (not what it says about itself), owner check."""
        import psutil

        try:
            p = psutil.Process(pid)
            name, exe, owner = p.name(), p.exe(), p.username()
            args = p.cmdline()[1:]
            try:
                cwd = p.cwd()
            except (psutil.Error, OSError):
                cwd = str(Path(exe).parent)
        except (psutil.Error, OSError):
            return None
        target, user = self.target_session(), self.target_user()
        mine = (target is not None and target > 0 and process_session(pid) == target
                and bool(user) and str(owner).lower() == str(user).lower())
        return {"name": name, "own_session": mine, "cmd": [exe, *args], "cwd": cwd}

    def is_hung(self, pid: int) -> bool | None:
        states = self.hung_states()
        return None if states is None else states.get(pid)

    def kill(self, pid: int) -> None:
        if self.service:  # with the user's own rights: Windows refuses what the user could not end
            tk = system32("taskkill.exe")
            run_as_active_user(subprocess.list2cmdline([tk, "/F", "/T", "/PID", str(int(pid))]), hidden=True, wait_s=15, app=tk)
            return
        import psutil

        try:
            p = psutil.Process(pid)
            for c in p.children(recursive=True):
                try:
                    c.kill()
                except psutil.Error:
                    pass
            p.kill()
        except psutil.Error:
            pass

    def close(self, pid: int, timeout_s: float) -> bool:
        """Like a click on the X: the program may ask to save and stay open (then False)."""
        import psutil

        if self.service:
            tk = system32("taskkill.exe")
            run_as_active_user(subprocess.list2cmdline([tk, "/PID", str(int(pid))]), hidden=True, wait_s=15, app=tk)
        else:
            for hwnd, wpid in _top_windows():
                if wpid == pid:
                    _u32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
        try:
            psutil.Process(pid).wait(timeout=timeout_s)
            return True
        except psutil.TimeoutExpired:
            return False
        except psutil.Error:
            return True  # already gone

    def launch(self, cmd: list[str], cwd: str | None) -> int | None:
        """Start the program again as the user, with normal rights; None if that is not possible."""
        if not cmd or not os.path.isabs(cmd[0]) or not os.path.isfile(cmd[0]):
            return None
        app, line = cmd[0], subprocess.list2cmdline(cmd)
        if self.service:
            return run_as_active_user(line, cwd, hidden=False, app=app)
        if _is_elevated():  # never start a program with the agent's admin rights
            return _run_as_shell_user(line, cwd, app=app)
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        p = subprocess.Popen(cmd, executable=app, cwd=cwd if cwd and os.path.isdir(cwd) else None, creationflags=flags,
                             close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.pid

    def alive(self, pid: int) -> bool:
        import psutil

        try:
            return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
        except psutil.Error:
            return False

    def sleep(self, s: float) -> None:
        time.sleep(s)


_OPS: WindowsOps | None = None


def windows_ops() -> WindowsOps:
    global _OPS
    if _OPS is None:
        _OPS = WindowsOps()
    return _OPS
