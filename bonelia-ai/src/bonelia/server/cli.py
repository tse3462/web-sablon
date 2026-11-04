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
    e.add_argument("--scopes", default="diagnose", help="comma separated, e.g. diagnose,adapter:veedelkorb")
    e.add_argument("--ttl-minutes", type=int, default=30)

    d = sub.add_parser("devices")
    d.add_argument("--tenant")

    r = sub.add_parser("revoke", help="revoke a device immediately (lost USB)")
    r.add_argument("device_id")

    a = sub.add_parser("approve", help="admin approval for one tool run (single use)")
    a.add_argument("tenant_id")
    a.add_argument("tool_id")
    a.add_argument("--params", default="{}")
    a.add_argument("--by", required=True)
    a.add_argument("--ttl-minutes", type=int, default=30)

    au = sub.add_parser("audit")
    au.add_argument("--tenant")
    au.add_argument("--verify", action="store_true")

    u = sub.add_parser("usage")
    u.add_argument("tenant_id")

    sub.add_parser("hw-check", help="assess hardware and recommend a local model size")

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
    elif args.cmd == "revoke":
        ok = store.revoke_device(args.device_id)
        print("revoked" if ok else "not found")
        return 0 if ok else 1
    elif args.cmd == "approve":
        params = json.loads(args.params)
        print(store.create_approval(args.tenant_id, args.tool_id, params_hash(args.tool_id, params), args.by, args.ttl_minutes))
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
