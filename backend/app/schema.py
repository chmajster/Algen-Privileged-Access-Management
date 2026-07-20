"""Explicit schema administration commands; reset is never run by startup."""
import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import MetaData

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import SCHEMA_VERSION, SchemaVersion


def sqlite_path() -> Path:
    if not settings.database_url.startswith("sqlite:///"):
        raise RuntimeError("The built-in backup command supports SQLite; use your database-native backup tool")
    return Path(settings.database_url.removeprefix("sqlite:///"))


def backup(destination: str | None) -> Path:
    source = sqlite_path().resolve()
    if not source.exists():
        raise RuntimeError(f"Database not found: {source}")
    target = Path(destination) if destination else source.with_name(f"{source.stem}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.bak{source.suffix}")
    target=target.resolve()
    if target==source: raise RuntimeError("Backup destination must differ from the live database")
    target.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(source) as source_db,sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
    return target


def reset(confirm: bool) -> None:
    if not confirm:
        raise RuntimeError("Refusing reset without --confirm-reset. Take a backup first.")
    existing=MetaData(); existing.reflect(bind=engine); existing.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.add(SchemaVersion(id=1, version=SCHEMA_VERSION)); db.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    backup_parser = commands.add_parser("backup"); backup_parser.add_argument("--output")
    reset_parser = commands.add_parser("reset"); reset_parser.add_argument("--confirm-reset", action="store_true")
    args = parser.parse_args()
    if args.command == "backup": print(backup(args.output))
    else: reset(args.confirm_reset)


if __name__ == "__main__":
    main()
