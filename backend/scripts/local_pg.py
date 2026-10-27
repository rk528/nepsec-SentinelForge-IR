"""Start (or reuse) a local PostgreSQL server without Docker, using pgserver.

Usage:  python scripts/local_pg.py [--data-dir PATH]
Prints a DATABASE_URL for a database named after --db (default: sentinelforge).
The server keeps running after this script exits; stop it with --stop.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import pgserver
except ImportError:  # pragma: no cover
    sys.exit("pgserver is not installed: pip install -r requirements-dev.txt")

DEFAULT_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share") / "sentinelforge-pg"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=str(DEFAULT_DIR))
    parser.add_argument("--db", default="sentinelforge")
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()

    server = pgserver.get_server(args.data_dir, cleanup_mode="stop" if args.stop else None)
    if args.stop:
        server.cleanup()
        print("stopped")
        return
    exists = server.psql(f"SELECT 1 FROM pg_database WHERE datname = '{args.db}';")
    if "1 row" not in exists:
        server.psql(f'CREATE DATABASE "{args.db}";')
    base = server.get_uri().rsplit("/", 1)[0]
    print(f"{base}/{args.db}")


if __name__ == "__main__":
    main()
