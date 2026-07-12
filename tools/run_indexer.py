from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Resolver Identity Indexer API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    try:
        import uvicorn
    except ModuleNotFoundError:
        print("uvicorn is not installed. Run: pip install -e '.[dev]'", file=sys.stderr)
        raise SystemExit(1)
    uvicorn.run("resolver_identity.indexer.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
