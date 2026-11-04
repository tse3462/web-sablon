"""`bonelia-server` — local administration of the home AI server.

Admin actions run on the server machine itself (direct DB access); they are not
reachable over the network in v0.1.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..repair.policy import params_hash
from ..monitor.portable import utf8_console
from .config import ServerConfig
from .store import Store


def _store(cfg: ServerConfig) -> Store:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    return Store(cfg.db_path)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bonelia-server", description="BONELİA AI Server administration")
    p.add_argument("--config", type=Path, default=None)
    p.add_argument("--data-dir", type=Path, default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the API server")
    s.add_argument("--host")
    s.add_argument("--port", type=int)

    t = sub.add_parser("tenant-add", help="create a customer (tenant)")
    t.add_argument("name")
    t.add_argument("--environment", choices=["test", "production"], default="test")
    t.add_argument("--cloud-ai", action="store_true", help="customer consents to cloud AI")
    t.add_argument("--daily-budget", type=float, default=0.0)
    t.add_argument("--monthly-budget", type=float, default=0.0)

    sub.add_parser("tenants")

    e = sub.add_parser("enroll-code", help="one-time enrollment code for a USB device")
    e.add_argument("tenant_id")
    e.add_argument("--scopes", default="diagnose", help="comma separated, e.g. diagnose,adapter:<adapter_id>")
    e.add_argument("--ttl-minutes", type=int, default=30)

    d = sub.add_parser("devices")
    d.add_argument("--tenant")

    ar = sub.add_parser("allow-repairs", help="one-time customer consent for on-site repairs (level 1, or 2 incl. restarts)")
    ar.add_argument("tenant_id")
    ar.add_argument("--level", type=int, choices=[0, 1, 2], default=1,
                    help="0 = read-only, 1 = safe repairs (start a stopped service), 2 = also restart services")
    ar.add_argument("--include-devices", action="store_true",
                    help="also give this customer's USB devices the rights to repair and to install the agent")

    ds = sub.add_parser("device-scopes", help="add/remove permissions of an enrolled USB device")
    ds.add_argument("device_id")
    ds.add_argument("--add", default="")
    ds.add_argument("--remove", default="")

    r = sub.add_parser("revoke", help="revoke a device immediately (lost USB)")
    r.add_argument("device_id")

    a = sub.add_parser("approve", help="admin approval for one tool run (single use)")
    a.add_argument("tenant_id")
    a.add_argument("tool_id")
    a.add_argument("--params", default="{}")
    a.add_argument("--by", required=True)
    a.add_argument("--ttl-minutes", type=int, default=30)

    al = sub.add_parser("alerts", help="what happened at your customers (important findings and repairs)")
    al.add_argument("--tenant")
    al.add_argument("--hours", type=int, default=24)
    al.add_argument("--all", action="store_true", help="include 'check' findings, not only 'important'")

    au = sub.add_parser("audit")
    au.add_argument("--tenant")
    au.add_argument("--verify", action="store_true")

    u = sub.add_parser("usage")
    u.add_argument("tenant_id")

    sub.add_parser("hw-check", help="assess hardware and recommend a local model size")

    sub.add_parser("notify-test", help="send a test notification through the configured channels")

    pa = sub.add_parser("publish-agent", help="publish a new agent program; installed PCs update themselves")
    pa.add_argument("exe", help="path to BoneliaAI-Konsol.exe from the new USB package")

    db = sub.add_parser("dashboard", help="open the local control panel (browser, this PC only)")
    db.add_argument("--port", type=int, default=0)
    db.add_argument("--no-browser", action="store_true")

    utf8_console()
    args = p.parse_args(argv)
    cfg = ServerConfig.load(args.config, args.data_dir)

    if args.cmd == "serve":
        import uvicorn

        from .app import create_app

        host = args.host or cfg.host
        port = args.port or cfg.port
        if host not in ("127.0.0.1", "::1", "localhost") and not (cfg.tls_cert and cfg.tls_key) and not host.startswith("100."):
            print("Refusing to listen on a non-loopback address without TLS (use Tailscale 100.x or configure tls_cert/tls_key).",
                  file=sys.stderr)
            return 2
        uvicorn.run(create_app(cfg), host=host, port=port, log_level="info",
                    ssl_certfile=str(cfg.tls_cert) if cfg.tls_cert else None, ssl_keyfile=str(cfg.tls_key) if cfg.tls_key else None)
        return 0

    if args.cmd == "hw-check":
        from .hwprobe import assess

        print(json.dumps(assess(str(cfg.data_dir if cfg.data_dir.exists() else ".")), indent=2, ensure_ascii=False))
        return 0

    store = _store(cfg)
    if args.cmd == "publish-agent":
        import hashlib
        import shutil

        from ..contracts import utcnow
        from ..security.crypto import sign_update
        from .app import load_or_create_server_key

        src = Path(args.exe)
        if not src.is_file() or src.suffix.lower() != ".exe":
            print("BoneliaAI-Konsol.exe bulunamadı / nicht gefunden", file=sys.stderr)
            return 2
        data = src.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        d = cfg.data_dir / "agent_update"
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, d / "BoneliaAI-Agent.exe")
        manifest = {"sha256": sha, "size": len(data), "signature": sign_update(load_or_create_server_key(cfg), sha, len(data)),
                    "published_at": utcnow().isoformat()}
        (d / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        store.audit("admin", "agent.update_published", {"sha256": sha, "size": len(data)})
        print(json.dumps({"published": True, "sha256": sha, "size": len(data),
                          "note": "Kurulu bilgisayarlar 5 dakika içinde güncellenir / PCs aktualisieren sich binnen 5 Minuten"}, indent=2))
        return 0
    if args.cmd == "notify-test":
        from .notify import build_notifier

        n = build_notifier(store, cfg.notify)
        ok = n.test()
        print(json.dumps({"channels": [c.name for c in n.channels], "sent": ok}, indent=2))
        return 0 if ok else 1
    if args.cmd == "dashboard":
        from .dashboard import serve_dashboard

        return serve_dashboard(store, port=args.port, open_browser=not args.no_browser)
    if args.cmd == "tenant-add":
        print(store.create_tenant(args.name, args.cloud_ai, args.daily_budget, args.monthly_budget, args.environment))
    elif args.cmd == "tenants":
        print(json.dumps(store.tenants(), indent=2, ensure_ascii=False))
    elif args.cmd == "enroll-code":
        code = store.create_enrollment_code(args.tenant_id, [s.strip() for s in args.scopes.split(",") if s.strip()],
                                            args.ttl_minutes)
        print(code)
    elif args.cmd == "devices":
        print(json.dumps(store.devices(args.tenant), indent=2, ensure_ascii=False))
    elif args.cmd == "allow-repairs":
        if store.tenant(args.tenant_id) is None:
            print("unknown tenant", file=sys.stderr)
            return 1
        from ..repair.builtin_tools import SAFE_AUTO_TOOLS

        safe_tools = list(SAFE_AUTO_TOOLS) if args.level >= 1 else []
        store.update_tenant(args.tenant_id, max_auto_level=args.level, auto_tools=safe_tools,
                            production_writes_allowed=1 if args.level >= 1 else 0)
        updated = []
        if args.include_devices:
            for d in store.devices(args.tenant_id):
                if d["status"] == "active":
                    store.update_device_scopes(d["id"], ["repair:windows", "install:agent"] if args.level >= 1 else [],
                                               [] if args.level >= 1 else ["repair:windows", "install:agent"])
                    updated.append(d["id"])
        print(json.dumps({"tenant_id": args.tenant_id, "repair_level": args.level, "one_click_tools": safe_tools,
                          "devices_updated": updated}, indent=2))
    elif args.cmd == "device-scopes":
        scopes = store.update_device_scopes(args.device_id, [s for s in args.add.split(",") if s.strip()],
                                            [s for s in args.remove.split(",") if s.strip()])
        if scopes is None:
            print("not found", file=sys.stderr)
            return 1
        print(json.dumps({"device_id": args.device_id, "scopes": scopes}, indent=2))
    elif args.cmd == "revoke":
        ok = store.revoke_device(args.device_id)
        print("revoked" if ok else "not found")
        return 0 if ok else 1
    elif args.cmd == "approve":
        params = json.loads(args.params)
        print(store.create_approval(args.tenant_id, args.tool_id, params_hash(args.tool_id, params), args.by, args.ttl_minutes))
    elif args.cmd == "alerts":
        from datetime import timedelta

        from ..contracts import DiagnosticEvent, utcnow

        since = utcnow() - timedelta(hours=args.hours)
        names = {t["id"]: t["name"] for t in store.tenants()}
        rows = []
        for r in store.recent_events(since, args.tenant):
            ev = DiagnosticEvent.model_validate_json(r["payload"])
            if ev.triage.value == "important" or (args.all and ev.triage.value == "check"):
                rows.append({"at": r["received_at"][:19], "customer": names.get(r["tenant_id"], r["tenant_id"]),
                             "device": r["label"], "triage": ev.triage.value, "title": ev.title, "app": ev.app.name,
                             "x": ev.occurrences, "repair": ev.repair_tool})
        repairs = [{"at": a["at"][:19], "customer": names.get(a["tenant_id"], a["tenant_id"]), "action": a["action"],
                    "detail": json.loads(a["detail"])} for a in store.audit_log(args.tenant, 300)
                   if a["action"] in ("tool.executed", "tool.denied") and a["at"] >= since.isoformat()]
        print(json.dumps({"findings": rows, "repairs": repairs}, indent=2, ensure_ascii=False))
    elif args.cmd == "audit":
        if args.verify:
            ok = store.verify_audit_chain()
            print("audit chain OK" if ok else "AUDIT CHAIN BROKEN")
            return 0 if ok else 1
        print(json.dumps(store.audit_log(args.tenant), indent=2, ensure_ascii=False))
    elif args.cmd == "usage":
        print(json.dumps({"day": store.ai_spend(args.tenant_id, "day"), "month": store.ai_spend(args.tenant_id, "month"),
                          "by_model": store.ai_usage(args.tenant_id)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
