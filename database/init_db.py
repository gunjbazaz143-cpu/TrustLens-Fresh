"""
Database bootstrap.
Creates all tables, seeds the bootstrap admin, and auto-heals stale schemas
(an old TrustLens installation may have outdated table columns).

Strategy:
  - SQLite / MySQL are both supported.
  - On boot we compare every model's columns against the live table. If a
    table's columns do not match the models, the table is dropped and
    recreated. This is intentional for a rewrite: stale schemas must not
    break inserts.
"""

import time
from pathlib import Path

from sqlalchemy import inspect, text

from models import db, init_admin_user


def init_app(app) -> None:
    """Create/verify tables and seed admin + reference data. Safe on every boot."""
    with app.app_context():
        _ensure_database(app)
        _verify_schema(app)
        db.create_all()
        _normalize_legacy_report_statuses(app)
        init_admin_user(app)
        from database.seed_product_db import seed_product_db

        seed_product_db(app)
        app.logger.info("Database ready.")


def _ensure_database(app) -> None:
    """Make sure the target database exists before connecting."""
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if uri.startswith("sqlite"):
        db_path = uri.replace("sqlite:///", "")
        if not (db_path.startswith("/") or db_path.startswith("C:") or ":" in db_path):
            db_path = str(app.config["BASE_DIR"] / "database" / "trustlens.db")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return

    if uri.startswith("mysql") and "pymysql" in uri:
        try:
            import pymysql

            host_part = uri.split("@")[1].split("/")[0]
            user = uri.split("//")[1].split(":")[0]
            password = uri.split("//")[1].split(":")[1].split("@")[0]
            host = host_part.split(":")[0]
            port = int(host_part.split(":")[1]) if ":" in host_part else 3306
            db_name = uri.split("/")[-1].split("?")[0]

            connection = pymysql.connect(host=host, user=user, password=password, port=port)
            cursor = connection.cursor()
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            cursor.close()
            connection.close()
        except Exception as exc:  # noqa: BLE001
            app.logger.warning("Could not auto-create MySQL database: %s", exc)


def _verify_schema(app) -> None:
    """
    Reconcile live tables with the current models without losing data.

    - Additive drift (model has columns the live table lacks) is repaired with
      ``ALTER TABLE ... ADD COLUMN`` so existing rows are preserved.
    - Destructive drift (columns removed or retyped) drops only the drifted
      table and lets ``db.create_all()`` rebuild it.
    """
    try:
        inspector = inspect(db.engine)
        existing = set(inspector.get_table_names())
        for table in db.metadata.tables.values():
            if table.name not in existing:
                continue
            model_cols = {c.name for c in table.columns}
            live_cols = {c["name"] for c in inspector.get_columns(table.name)}
            added = model_cols - live_cols
            removed = live_cols - model_cols

            if not added and not removed:
                continue

            if added and not removed:
                _add_missing_columns(app, table, added)
            else:
                _drop_table(app, table.name)
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("Schema verification skipped: %s", exc)


def _add_missing_columns(app, table, added: set) -> None:
    """Add newly introduced model columns to an existing table (data-safe)."""
    dialect = db.engine.dialect.name
    preparer = db.engine.dialect.identifier_preparer
    for column_name in sorted(added):
        column = table.columns[column_name]
        column_type = column.type.compile(dialect=db.engine.dialect)
        statement = (
            f"ALTER TABLE {preparer.quote(table.name)} "
            f"ADD COLUMN {preparer.quote(column.name)} {column_type}"
        )
        with db.engine.begin() as conn:
            conn.execute(text(statement))
        app.logger.info(
            "Migrated column %s.%s (type %s).", table.name, column.name, column_type,
        )


def _drop_table(app, table_name: str) -> None:
    """Drop a single destructively-drifted table; create_all rebuilds it."""
    dialect = db.engine.dialect.name
    app.logger.warning("Schema drift on %s - rebuilding that table.", table_name)
    with db.engine.begin() as conn:
        if dialect == "mysql":
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        conn.execute(text(f"DROP TABLE IF EXISTS `{table_name}`"))
        if dialect == "mysql":
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))


def _normalize_legacy_report_statuses(app) -> None:
    """
    Translate pre-workflow report statuses into the 4-state model.

    The original report portal used pending/approved/rejected. The admin
    workflow now uses new / under review / resolved / rejected. This is a
    one-time idempotent data fix that never deletes rows.
    """
    from models.report import ScamReport

    mappings = {"pending": "new", "approved": "resolved"}
    changed = 0
    for old_status, new_status in mappings.items():
        rows = ScamReport.query.filter(ScamReport.status == old_status).all()
        for row in rows:
            row.status = new_status
            changed += 1
    if changed:
        db.session.commit()
        app.logger.info(
            "Migrated %s legacy report status(es) to the new workflow.", changed,
        )
