"""BoneliaAI.exe — BONELİA AI Portable Monitor command line.

Without arguments the frozen executable opens the local UI.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .. import PRODUCT_NAME, __version__
from ..security.crypto import Vault
from . import reports
from pydantic import ValidationError

from .client import FakeServerError, ServerError, ServerUnavailable, enroll
from .portable import PortableHome, utf8_console
from .session import Session


def _passphrase(confirm: bool = False) -> str:
    env = os.environ.get("BONELIA_PASSPHRASE")
    if env:
        return env
    p = getpass.getpass("USB parolası / USB-Passwort: ")
    if confirm and getpass.getpass("Tekrar / Wiederholen: ") != p:
        raise SystemExit("Parolalar eşleşmiyor / Passwörter stimmen nicht überein")
    return p


def _session(args) -> Session:
    home = PortableHome(Path(args.home) if args.home else None).ensure()
    lang = args.lang or home.settings().get("language", "tr")
    s = Session(home=home, lang=lang, ca_file=args.ca)
    if s.enrolled and getattr(args, "unlock", True):
        s.unlock(_passphrase())
    return s


def _print(obj, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))
    else:
        print(reports.render_text(obj) if isinstance(obj, dict) and obj.get("report_type") else obj)


CONSENT = """BONELİA AI Agent bu bilgisayara kalıcı olarak kurulacak.
- Windows açılınca arka planda başlar, birkaç dakikada bir hata kayıtlarını salt okunur tarar.
- Bulguları kişisel veriler temizlenmiş olarak BONELİA AI sunucusuna gönderir.
- İşletmenin izin verdiği GÜVENLİ onarımları (ör. durmuş bir hizmeti başlatmak) kendisi yapar ve doğrular.
- Ticari kayıtları değiştirmez. 'BoneliaAI-Konsol.exe agent-uninstall' ile tamamen kaldırılır.

Der BONELİA AI Agent wird dauerhaft auf diesem PC installiert (Hintergrundüberwachung, sichere
Selbstreparatur mit Freigabe des Betriebs). Entfernen: 'BoneliaAI-Konsol.exe agent-uninstall'.
"""


def _enroll_agent_from_usb(args, label: str):
    """Silent path: the USB's limited install key. First time: unlock the USB once and create that key."""
    from ..security.crypto import DeviceCredentials
    from .client import ServerClient

    home = PortableHome(Path(args.home) if args.home else None).ensure()
    key_file = home.path("config", "install.key")
    # Address the agents use to reach the home server (e.g. its Tailscale address), if different from the USB's
    agent_url = args.server or home.settings().get("agent_server_url")
    if key_file.is_file():
        installer = ServerClient(DeviceCredentials.from_json(key_file.read_bytes()), ca_file=args.ca)
        return installer.enroll_agent(label, agent_url)
    usb = Session(home=home, lang=args.lang or "tr", ca_file=args.ca)
    if not usb.enrolled:
        print("Bu USB kayıtlı değil / nicht registriert.", file=sys.stderr)
        return None
    print("İlk kurulum: USB parolası bir kez sorulur; sonraki bilgisayarlarda sorulmaz. / "
          "Erste Installation: USB-Passwort wird einmal abgefragt.")
    usb.unlock(_passphrase())
    if not args.no_install_key:
        ik = usb.client.create_install_key("Install key " + (usb.creds.device_id[-6:]))
        key_file.write_bytes(ik.to_json())  # can ONLY enroll agents; revocable on the server
        print("Kurulum anahtarı USB'ye kaydedildi (yalnızca bilgisayar kurma yetkisi). / Installationsschlüssel gespeichert.")
    return usb.client.enroll_agent(label, agent_url)


def _agent_command(args) -> int:
    import socket

    from ..agent import install as inst
    from ..repair.windows_tools import is_admin
    from ..security.redact import pseudonymize

    if args.cmd == "agent-status":
        state = {}
        try:
            state = json.loads(inst.state_path().read_text(encoding="utf-8")).get("last_cycle", {})
        except (OSError, ValueError):
            pass
        print(json.dumps({"installed": inst.task_installed(), "credentials": inst.cred_path().is_file(),
                          "dir": str(inst.agent_dir()), "last_cycle": state}, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "agent-uninstall":
        if sys.platform == "win32" and not is_admin():
            print("Yönetici olarak çalıştırın / Als Administrator ausführen.", file=sys.stderr)
            return 2
        print(json.dumps({"removed": inst.uninstall(),
                          "note": "Sunucuda cihazı da iptal edin / Gerät auch am Server widerrufen: bonelia-server revoke <device_id>"},
                         indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "agent-install":
        if sys.platform != "win32":
            print("Agent yalnızca Windows'ta kurulabilir / nur unter Windows.", file=sys.stderr)
            return 2
        if not is_admin():
            print("Yönetici olarak çalıştırın / Als Administrator ausführen.", file=sys.stderr)
            return 2
        print(CONSENT)
        if not args.yes and input("İşletmenin izni var mı? / Zustimmung des Betriebs? (evet/ja): ").strip().lower() not in ("evet", "ja", "yes", "e", "j", "y"):
            print("İptal edildi / Abgebrochen.")
            return 1
        label = args.label or f"Agent {pseudonymize(socket.gethostname(), 'agent-label')[:12]}"
        existing = None
        if inst.cred_path().is_file():
            try:
                existing = inst.load_credentials()
            except (OSError, ValueError):
                existing = None
        if existing is not None and not args.code:
            # Already installed on this PC: keep its identity, just refresh program + task (re-install / update)
            ok, info = inst.install_task(start_now=not args.no_start)
            if not ok:
                print(f"Kurulum güncellenemedi / Aktualisierung fehlgeschlagen: {info}", file=sys.stderr)
                return 5
            print(json.dumps({"installed": True, "already_installed": True, "device_id": existing.device_id,
                              "task": inst.TASK_NAME}, indent=2))
            return 0
        try:
            if args.code:
                if not args.server:
                    print("--server gerekli / erforderlich", file=sys.stderr)
                    return 2
                creds = enroll(args.server, args.code, label, ca_file=args.ca)
            else:  # one-click from the USB: no enrollment code needed
                creds = _enroll_agent_from_usb(args, label)
                if creds is None:
                    return 2
        except ServerError:
            print("Kayıt reddedildi: kod yanlış, kullanılmış veya süresi dolmuş / Registrierung abgelehnt.", file=sys.stderr)
            return 4
        except ServerUnavailable:
            print("Sunucuya ulaşılamıyor / Server nicht erreichbar: " + args.server, file=sys.stderr)
            return 3
        except (ValidationError, ValueError) as exc:
            print(f"Geçersiz giriş veya yanlış parola / Ungültige Eingabe oder falsches Passwort: {exc}", file=sys.stderr)
            return 2
        inst.save_credentials(creds)
        ok, info = inst.install_task(start_now=not args.no_start)
        if not ok:
            print(f"Görev oluşturulamadı / Aufgabe nicht erstellt: {info}", file=sys.stderr)
            return 5
        print(json.dumps({"installed": True, "device_id": creds.device_id, "tenant_id": creds.tenant_id, "scopes": creds.scopes,
                          "task": inst.TASK_NAME, "command": info}, indent=2))
        return 0

    # agent run
    import logging
    from logging.handlers import RotatingFileHandler

    from ..agent.agent import Agent, AgentState
    from .client import ServerClient

    inst.agent_dir().mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, handlers=[RotatingFileHandler(inst.agent_dir() / "agent.log", maxBytes=1_000_000,
                                                                          backupCount=3, encoding="utf-8")])
    try:
        creds = inst.load_credentials()
    except (OSError, ValueError) as exc:
        print(f"Agent kurulu değil / nicht installiert: {exc}", file=sys.stderr)
        return 2
    frozen = getattr(sys, "frozen", False)
    agent = Agent(ServerClient(creds, ca_file=args.ca), AgentState(inst.state_path()), lang=args.lang or "tr",
                  own_exe=Path(sys.executable) if frozen else None, self_update=frozen)
    if args.once:
        print(json.dumps(agent.cycle(), indent=2, ensure_ascii=False, default=str))
        return 0
    agent.run_forever(args.interval)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv and getattr(sys, "frozen", False):
        argv = ["ui"]
    p = argparse.ArgumentParser(prog="BoneliaAI", description=f"{PRODUCT_NAME} Portable Monitor {__version__}")
    p.add_argument("--home", help="portable root (default: folder of the executable)")
    p.add_argument("--lang", choices=["tr", "de", "en"])
    p.add_argument("--ca", help="CA/certificate file to trust for the server's TLS")
    p.add_argument("--version", action="version", version=f"{PRODUCT_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def scan_args(sp):
        sp.add_argument("--mode", choices=["quick", "full", "recent", "app"], default="quick")
        sp.add_argument("--app", help="inspect a specific application (name filter)")
        sp.add_argument("--hours", type=int)
        sp.add_argument("--log", action="append", default=None, help="authorised application log file (repeatable)")
        sp.add_argument("--json", action="store_true")
        sp.add_argument("--export", type=Path, help="write a plaintext report copy to this folder (outside the USB)")

    sc = sub.add_parser("scan", help="local, read-only diagnosis (works offline)")
    scan_args(sc)
    sc.add_argument("--no-unlock", dest="unlock", action="store_false")

    an = sub.add_parser("analyze", help="scan and ask the central AI server")
    scan_args(an)
    an.add_argument("--allow-cloud", action="store_true", help="customer consents to cloud AI for this analysis")

    en = sub.add_parser("enroll", help="register this USB copy with the server")
    en.add_argument("--server", required=True)
    en.add_argument("--code", required=True)
    en.add_argument("--label", required=True)
    en.add_argument("--server-key", help="expected server public key (out-of-band fingerprint)")

    sub.add_parser("status")
    al = sub.add_parser("adapters", help="list application adapters known to the server")
    al.add_argument("--json", action="store_true")
    ad = sub.add_parser("adapter", help="server-side health analysis through an optional application adapter")
    ad.add_argument("adapter_id")
    ad.add_argument("--allow-cloud", action="store_true")
    ad.add_argument("--json", action="store_true")
    ch = sub.add_parser("chat")
    ch.add_argument("question")
    sub.add_parser("tools")
    tr_ = sub.add_parser("tool", help="evaluate/run a tool through the gateway (dry-run by default)")
    tr_.add_argument("tool_id")
    tr_.add_argument("--params", default="{}")
    tr_.add_argument("--execute", action="store_true", help="real execution (policy and approvals still apply)")
    tr_.add_argument("--approval")
    ag = sub.add_parser("agent", help="run the background agent (normally started by Windows at boot)")
    ag.add_argument("--once", action="store_true", help="one cycle, then exit (prints a JSON summary)")
    ag.add_argument("--interval", type=int, default=300)
    ai_ = sub.add_parser("agent-install", help="install continuous monitoring on THIS PC (admin, business consent)")
    ai_.add_argument("--server", help="server address for the agent (default: settings 'agent_server_url' or the USB's)")
    ai_.add_argument("--no-install-key", action="store_true", help="do not create the passphrase-free install key")
    ai_.add_argument("--code", help="optional enrollment code; without it the enrolled USB authorises the install")
    ai_.add_argument("--label", default=None)
    ai_.add_argument("--yes", action="store_true", help="the business has agreed (skips the question)")
    ai_.add_argument("--no-start", action="store_true")
    sub.add_parser("agent-uninstall", help="remove the agent completely from this PC")
    sub.add_parser("agent-status")
    ui = sub.add_parser("ui", help="open the local graphical interface")
    ui.add_argument("--no-browser", action="store_true")
    ui.add_argument("--port", type=int, default=0)

    utf8_console()
    args = p.parse_args(argv)

    if args.cmd == "enroll":
        home = PortableHome(Path(args.home) if args.home else None).ensure()
        vault = Vault(home.vault_path)
        if vault.exists():
            print("Bu USB zaten kayıtlı / bereits registriert. (config/device.vault)", file=sys.stderr)
            return 2
        try:
            creds = enroll(args.server, args.code, args.label, args.server_key, ca_file=args.ca)
        except (ValidationError, ValueError) as exc:
            msg = "Kayıt kodu veya sunucu adresi geçersiz / Code oder Serveradresse ungültig"
            if isinstance(exc, ValidationError) and any("enrollment_code" in str(e.get("loc")) for e in exc.errors()):
                msg = ("Kayıt kodu geçersiz: sunucunun verdiği ABCD-EFGH-... kodunu yazın / "
                       "Registrierungscode ungültig: den vom Server erzeugten Code ABCD-EFGH-... eingeben")
            elif not isinstance(exc, ValidationError):
                msg = f"{msg}: {exc}"
            print(msg, file=sys.stderr)
            return 2
        except ServerUnavailable:
            print("Sunucuya ulaşılamıyor / Server nicht erreichbar: " + args.server, file=sys.stderr)
            return 3
        except ServerError:
            print("Sunucu kaydı reddetti: kod yanlış, kullanılmış veya süresi dolmuş (30 dk) / "
                  "Registrierung abgelehnt: Code falsch, bereits benutzt oder abgelaufen (30 Min.)", file=sys.stderr)
            return 4
        except FakeServerError as exc:
            print(f"Sunucu kimliği doğrulanamadı / Serveridentität nicht bestätigt: {exc}", file=sys.stderr)
            return 5
        vault.save(creds, _passphrase(confirm=True))
        print(json.dumps({"device_id": creds.device_id, "tenant_id": creds.tenant_id, "scopes": creds.scopes}, indent=2))
        return 0

    if args.cmd.startswith("agent"):
        return _agent_command(args)

    if args.cmd == "ui":
        from .ui import serve_ui

        home = PortableHome(Path(args.home) if args.home else None).ensure()
        return serve_ui(Session(home=home, lang=args.lang or home.settings().get("language", "tr"), ca_file=args.ca),
                        port=args.port, open_browser=not args.no_browser)

    s = _session(args)
    if args.cmd == "status":
        print(json.dumps({"product": PRODUCT_NAME, "version": __version__, "home": str(s.home.root), "enrolled": s.enrolled,
                          "device_id": s.creds.device_id if s.creds else None, "server": s.server_status()}, indent=2, ensure_ascii=False))
        return 0
    if args.cmd in ("scan", "analyze"):
        s.scan(mode=args.mode, app_query=args.app, hours=args.hours, log_paths=args.log)
        rep = s.analyze(allow_cloud=args.allow_cloud) if args.cmd == "analyze" else s.last_report
        if args.export:
            for f in s.export_last(args.export):
                print(f"exported: {f}", file=sys.stderr)
        _print(rep, args.json)
        return 0
    if not s.client:
        print("Cihaz kayıtlı değil / Gerät nicht registriert.", file=sys.stderr)
        return 2
    try:
        if args.cmd == "adapters":
            rows = s.client.adapters()
            if args.json:
                _print(rows, True)
            for a in [] if args.json else rows:
                print(f"{a['adapter_id']:<20} {a.get('load_status', ''):<15} {a.get('name', '')}"
                      + ("  [assigned]" if a.get("assigned_to_tenant") else ""))
        elif args.cmd == "adapter":
            res = s.client.adapter_health(args.adapter_id, s.lang, allow_cloud=args.allow_cloud)
            if args.json:
                _print(res, True)
            else:
                print(f"{args.adapter_id} · AI: {res['ai_mode']} · {res['collector_status']}")
                for n in res.get("notices", []):
                    print(f"! {n}")
                for ev, d in zip(res["events"], res["diagnoses"]):
                    print(f"\n[{ev['severity']}] {ev['title']}")
                    for h in d["hypotheses"][:3]:
                        print(f"  - ({h['confidence']}) {h['cause']}")
                if not res["events"]:
                    print("Sorun bulunmadı / keine Probleme gefunden / no problems found")
        elif args.cmd == "chat":
            res = s.client.chat(args.question, s.lang)
            print(res["answer"])
            print(f"\n[{res['produced_by']}, {res['grounded_on']} events]", file=sys.stderr)
        elif args.cmd == "tools":
            _print(s.client.tools(), True)
        elif args.cmd == "tool":
            _print(s.client.run_tool(args.tool_id, json.loads(args.params), dry_run=not args.execute, approval_id=args.approval), True)
    except ServerUnavailable:
        print("Sunucuya ulaşılamıyor / Server nicht erreichbar.", file=sys.stderr)
        return 3
    except ServerError as exc:
        print(f"Sunucu reddetti / Server lehnte ab: {exc.status} {exc.detail}", file=sys.stderr)
        return 4
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
