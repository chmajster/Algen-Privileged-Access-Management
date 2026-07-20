"""Database bootstrap with an explicit, non-destructive schema boundary."""
from collections.abc import Generator

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


class Base(DeclarativeBase):
    pass


class UnsupportedSchemaError(RuntimeError):
    pass


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app import models

    tables = set(inspect(engine).get_table_names())
    if tables and "schema_version" not in tables:
        raise UnsupportedSchemaError(
            "Unsupported pre-v2 database. No data was changed. Back it up, then run "
            "`python -m app.schema reset --confirm-reset` or migrate it explicitly."
        )
    if not tables:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            db.add(models.SchemaVersion(id=1, version=models.SCHEMA_VERSION))
            db.commit()
    else:
        with SessionLocal() as db:
            version = db.get(models.SchemaVersion, 1)
            if not version or version.version != models.SCHEMA_VERSION:
                found = version.version if version else "missing"
                raise UnsupportedSchemaError(
                    f"Unsupported schema version {found}; expected {models.SCHEMA_VERSION}. No data was changed."
                )
    from app.rbac import seed_access_control
    with SessionLocal() as db:
        seed_access_control(db)
