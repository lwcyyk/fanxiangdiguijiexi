from __future__ import annotations

import argparse
import json
from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.admin.publisher import AdminPublisher
from resolver_identity.common.config import load_settings
from resolver_identity.db.sqlite import connect
from resolver_identity.db.schema import init_db
from resolver_identity.db.repositories import IndexerRepository, RegistryRepository
from resolver_identity.common.registry_factory import create_registry_backend


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolver identity admin CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("publish-demo")
    demo.add_argument("--resolver-id", default="operator-a/resolver-01")
    demo.add_argument("--ip", default="1.1.1.1")
    demo.add_argument("--transport", default="udp")
    demo.add_argument("--port", type=int, default=53)
    demo.add_argument("--valid-from", default="2026-07-01T00:00:00Z")
    demo.add_argument("--valid-until", default="2027-07-01T00:00:00Z")
    args = parser.parse_args()
    settings = load_settings()
    conn = connect(settings.db_path)
    init_db(conn)
    publisher = AdminPublisher(
        IndexerRepository(conn),
        create_registry_backend(settings, RegistryRepository(conn)),
        settings.signature_secret,
        ed25519_private_key_b64=settings.issuer_private_key_b64 or None,
    )
    if args.cmd == "publish-demo":
        obj = build_resolver_object(
            args.resolver_id,
            "operator-a",
            "Operator A",
            [{"endpoint_id": "endpoint-01", "ip": args.ip, "port": args.port, "transport": args.transport}],
            args.valid_from,
            args.valid_until,
        )
        print(json.dumps(publisher.publish(obj), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
