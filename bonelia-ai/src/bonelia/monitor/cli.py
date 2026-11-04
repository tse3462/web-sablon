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
from .client import ServerError, ServerUnavailable, enroll
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
        creds = enroll(args.server, args.code, args.label, args.server_key, ca_file=args.ca)
        vault.save(creds, _passphrase(confirm=True))
        print(json.dumps({"device_id": creds.device_id, "tenant_id": creds.tenant_id, "scopes": creds.scopes}, indent=2))
        return 0

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
