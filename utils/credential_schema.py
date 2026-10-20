"""Idempotent per-project setup of the credential governance tables (#6757, C-1009).

``create_all`` provisions them for new projects. Existing project schemas get them here, from the
startup safety net in ``module.py`` or from the ``create_credential_governance_tables`` admin task.
Both only create what is missing, so a steady-state boot issues no DDL.
"""
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy import bindparam, text
from pylon.core.tools import log
from tools import config as c, db

from ..models.credential_governance import (
    LEGACY_INDEX, PERSONAL_INDEX, SHARED_INDEX, CredentialReference, CredentialStoreLedger, CredentialUseGrant,
)

_MODELS = (CredentialReference, CredentialUseGrant, CredentialStoreLedger)
USAGE = "project_id= is required. Format: project_id=<all|N>[;dry_run]"

# Only fully provisioned project schemas (they already hold the configuration table) are considered.
_MISSING_QUERY = text(
    "SELECT t.table_schema FROM information_schema.tables t "
    "WHERE t.table_name = 'configuration' AND t.table_schema ~ '^p_[0-9]+$' "
    "AND (SELECT count(*) FROM information_schema.tables x "
    "WHERE x.table_schema = t.table_schema AND x.table_name IN :names) < :expected"
).bindparams(bindparam("names", expanding=True))


def _new_indexes():
    by_name = {index.name: index for index in CredentialReference.__table__.indexes}
    return by_name[SHARED_INDEX], by_name[PERSONAL_INDEX]


def _legacy_index():
    """The pre-personal single index, as a drop target: a table of its own, so the model's metadata is not touched."""
    table = sa.Table("credential_reference", sa.MetaData(), sa.Column("configuration_id", sa.Integer),
                     schema=c.POSTGRES_TENANT_SCHEMA)
    return sa.Index(LEGACY_INDEX, table.c.configuration_id)


def _table_exists(session) -> bool:
    connection = session.connection()
    table = CredentialReference.__table__
    return sa.inspect(connection).has_table(table.name, schema=connection.schema_for_object(table))


def _index_names(session) -> set:
    """The names of the indexes on the project's ``credential_reference``, read from the catalog (reflection skips the
    expression index of the personal pair on some dialects). PostgreSQL in production; SQLite in the unit tests."""
    connection = session.connection()
    table = CredentialReference.__table__
    if connection.dialect.name == "postgresql":
        rows = connection.execute(
            text("SELECT indexname FROM pg_indexes WHERE schemaname = :schema AND tablename = :table"),
            {"schema": connection.schema_for_object(table), "table": table.name})
    else:
        rows = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = :table"), {"table": table.name})
    return {row[0] for row in rows}


def personal_index_applied(session) -> bool:
    """True when this project's ``credential_reference`` has the two partial indexes that allow personal references."""
    return {SHARED_INDEX, PERSONAL_INDEX} <= _index_names(session)


@contextmanager
def project_tx(project_id):
    """A session on one project's schema that rolls back on any failure. Callers commit explicitly."""
    with db.get_session(project_id) as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise


def project_ids_missing_credential_tables():
    """One catalog query: project schemas that lack any of the three tables."""
    params = {"names": [model.__tablename__ for model in _MODELS], "expected": len(_MODELS)}
    with db.get_session(None) as session:
        rows = session.execute(_MISSING_QUERY, params).fetchall()
    return [int(row[0][2:]) for row in rows]


def apply_credential_tables(project_ids, dry_run=False):
    """Create the missing tables, one transaction per project, so one broken schema does not stop
    the rest. Returns ``(migrated, failed)``; on a dry run ``migrated`` is what would be created."""
    migrated, failed = [], []
    for pid in project_ids:
        if dry_run:
            migrated.append(pid)
            continue
        try:
            with db.get_session(pid) as session:
                for model in _MODELS:
                    model.__table__.create(session.connection(), checkfirst=True)
                session.commit()
            migrated.append(pid)
        except Exception:  # pylint: disable=W0703
            log.exception("credential governance schema: failed to migrate project %s", pid)
            failed.append({"project_id": pid})
    return migrated, failed


def project_ids_missing_personal_index(project_ids):
    """The projects among ``project_ids`` whose ``credential_reference`` exists but still has the pre-personal index
    (one catalog read per project)."""
    pending = []
    for pid in project_ids:
        with project_tx(pid) as session:
            if _table_exists(session) and not personal_index_applied(session):
                pending.append(pid)
    return pending


def apply_personal_index(project_ids, dry_run=False):
    """Swap the one live-reference index for the shared and personal pair (``personal_index`` step), one transaction
    per project (DDL is transactional on PostgreSQL, so a project is never left without a unique index). Existing
    rows are all non-personal, so both new indexes build over data the old one already kept unique. Returns
    ``(migrated, failed)`` like ``apply_credential_tables``."""
    migrated, failed = [], []
    for pid in project_ids:
        if dry_run:
            migrated.append(pid)
            continue
        try:
            with db.get_session(pid) as session:
                connection = session.connection()
                present = _index_names(session)
                connection.execute(sa.schema.DropIndex(_legacy_index(), if_exists=True))
                for index in _new_indexes():
                    if index.name not in present:
                        index.create(connection)
                session.commit()
            migrated.append(pid)
        except Exception:  # pylint: disable=W0703
            log.exception("credential governance schema: failed to apply the personal index to project %s", pid)
            failed.append({"project_id": pid})
    return migrated, failed


def parse_project_param(param, usage=USAGE):
    """``(project_id_filter, dry_run, None)`` or ``(None, False, readable error)``. ``all`` -> filter None."""
    dry_run = False
    project_id_filter = None
    found = False
    for seg in [s.strip() for s in (param or "").split(";")]:
        if seg.lower().startswith("project_id="):
            found = True
            value = seg[len("project_id="):].strip()
            if value.lower() != "all":
                try:
                    project_id_filter = int(value)
                except ValueError:
                    return None, False, f"invalid project_id: '{value}'"
                if project_id_filter <= 0:
                    return None, False, f"invalid project_id: '{value}'"
        elif seg.lower() == "dry_run":
            dry_run = True
    if not found:
        return None, False, usage
    return project_id_filter, dry_run, None


def target_project_ids(module, project_id_filter):
    """The requested project, or every project that finished creation."""
    if project_id_filter is not None:
        return [project_id_filter]
    return [
        p["id"] for p in (module.context.rpc_manager.call.project_list(filter_={"create_success": True}) or [])
    ]
