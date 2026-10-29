"""Idempotent per-project setup of the credential governance tables (#6757, C-1009).

``create_all`` provisions them for new projects. Existing project schemas get them here, from the
startup safety net in ``module.py`` or from the ``create_credential_governance_tables`` admin task.
Both only create what is missing, so a steady-state boot issues no DDL.

Personal credential references (#7119) need two changes to a project that predates them, applied by the
``personal_index`` step of the task: the single live-reference unique index becomes a shared and a personal pair, and
``credential_reference.written_by`` is added (also by the startup safety net, since the model reads it). The step takes
``lock_timeout`` 5 s on PostgreSQL: a project whose table is busy fails alone and is reported, and the step is repeated.

``credential_use_grant.subject_user_id`` (the user a grant's subject was resolved from; perf review 2026-10-21, S5) is
the ``grant_subject_user_id`` step: additive like ``written_by``, applied by the startup safety net and by the task.
"""
import time
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy import bindparam, text
from pylon.core.tools import log
from tools import config as c, db

from ..models.credential_governance import (
    LEGACY_INDEX, PERSONAL_INDEX, SHARED_INDEX, CredentialOfflineMaterial, CredentialReference, CredentialStoreLedger,
    CredentialUseGrant,
)

# credential_offline_material (#7131) is created like the others: by create_all, the startup safety net and the task
_MODELS = (CredentialReference, CredentialUseGrant, CredentialStoreLedger, CredentialOfflineMaterial)
LOCK_TIMEOUT = "5s"
RETRY_ATTEMPTS = 3   # the startup guard tries a project that hit the lock timeout again this many times ...
RETRY_DELAY_S = 5    # ... this long after
WRITTEN_BY = "written_by"
SUBJECT_USER_ID = "subject_user_id"
USAGE = "project_id= is required. Format: project_id=<all|N>[;dry_run]"

# Only fully provisioned project schemas (they already hold the configuration table) are considered.
_MISSING_QUERY = text(
    "SELECT t.table_schema FROM information_schema.tables t "
    "WHERE t.table_name = 'configuration' AND t.table_schema ~ '^p_[0-9]+$' "
    "AND (SELECT count(*) FROM information_schema.tables x "
    "WHERE x.table_schema = t.table_schema AND x.table_name IN :names) < :expected"
).bindparams(bindparam("names", expanding=True))


# Project schemas that have credential_reference but not its written_by column (one catalog query)
_MISSING_COLUMN_QUERY = text(
    "SELECT t.table_schema FROM information_schema.tables t "
    "WHERE t.table_name = 'credential_reference' AND t.table_schema ~ '^p_[0-9]+$' "
    "AND NOT EXISTS (SELECT 1 FROM information_schema.columns x WHERE x.table_schema = t.table_schema "
    "AND x.table_name = 'credential_reference' AND x.column_name = 'written_by')")


# Project schemas that have credential_use_grant but not its subject_user_id column
_MISSING_GRANT_COLUMN_QUERY = text(
    "SELECT t.table_schema FROM information_schema.tables t "
    "WHERE t.table_name = 'credential_use_grant' AND t.table_schema ~ '^p_[0-9]+$' "
    "AND NOT EXISTS (SELECT 1 FROM information_schema.columns x WHERE x.table_schema = t.table_schema "
    "AND x.table_name = 'credential_use_grant' AND x.column_name = 'subject_user_id')")


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


def _column_names(session, table=None) -> set:
    """The column names of the project's ``credential_reference`` (or ``table``), read from the catalog as the indexes
    are."""
    connection = session.connection()
    table = CredentialReference.__table__ if table is None else table
    if connection.dialect.name == "postgresql":
        rows = connection.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_schema = :schema AND table_name = :table"),
            {"schema": connection.schema_for_object(table), "table": table.name})
        return {row[0] for row in rows}
    return {row[1] for row in connection.execute(text(f'PRAGMA table_info("{table.name}")'))}


def personal_index_applied(session) -> bool:
    """True when this project's ``credential_reference`` has the two partial indexes that allow personal references and
    no longer has the single index they replace (which would keep allowing one reference per configuration)."""
    names = _index_names(session)
    return {SHARED_INDEX, PERSONAL_INDEX} <= names and LEGACY_INDEX not in names


def personal_schema_applied(session) -> bool:
    """The whole ``personal_index`` step is done: the indexes and the ``written_by`` column."""
    return personal_index_applied(session) and WRITTEN_BY in _column_names(session)


def _set_lock_timeout(connection):
    """Bound the wait for a lock on the table to ``LOCK_TIMEOUT`` for this transaction (PostgreSQL only)."""
    if connection.dialect.name == "postgresql":
        connection.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))


def _add_integer_column(connection, table, column, present_columns):
    if column in present_columns:
        return
    preparer = connection.dialect.identifier_preparer
    schema = connection.schema_for_object(table)
    name = f"{preparer.quote_schema(schema)}.{preparer.quote(table.name)}" if schema else preparer.quote(table.name)
    # PostgreSQL: idempotent even if another replica adds the column between the catalog read and here
    guard = "IF NOT EXISTS " if connection.dialect.name == "postgresql" else ""
    connection.execute(text(f"ALTER TABLE {name} ADD COLUMN {guard}{column} INTEGER"))


def _add_written_by(connection, present_columns):
    _add_integer_column(connection, CredentialReference.__table__, WRITTEN_BY, present_columns)


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
    """One catalog query: project schemas that lack any of the governance tables."""
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
    """The projects among ``project_ids`` whose ``credential_reference`` exists but lacks a part of the
    ``personal_index`` step (the index pair, or ``written_by``); one catalog read per project."""
    pending = []
    for pid in project_ids:
        with project_tx(pid) as session:
            if _table_exists(session) and not personal_schema_applied(session):
                pending.append(pid)
    return pending


def project_ids_missing_written_by():
    """One catalog query: project schemas whose ``credential_reference`` has no ``written_by`` column yet."""
    with db.get_session(None) as session:
        rows = session.execute(_MISSING_COLUMN_QUERY).fetchall()
    return [int(row[0][2:]) for row in rows]


def apply_written_by(project_ids):
    """Add ``written_by`` where it is missing (additive and idempotent; the startup safety net runs it, since the model
    reads the column). Returns ``(migrated, failed)``."""
    migrated, failed = [], []
    for pid in project_ids:
        try:
            with db.get_session(pid) as session:
                connection = session.connection()
                _set_lock_timeout(connection)
                _add_written_by(connection, _column_names(session))
                session.commit()
            migrated.append(pid)
        except Exception:  # pylint: disable=W0703
            log.exception("credential governance schema: failed to add written_by to project %s", pid)
            failed.append({"project_id": pid})
    return migrated, failed


def apply_with_retry(apply, project_ids, attempts=RETRY_ATTEMPTS, delay_s=RETRY_DELAY_S, sleep=time.sleep):
    """``apply(project_ids)`` (an ``apply_*`` function returning ``(migrated, failed)``), then the projects that failed
    (a busy table: the lock timeout) again up to ``attempts`` times, ``delay_s`` apart. Returns the totals."""
    migrated, failed = apply(project_ids)
    migrated = list(migrated)
    for _ in range(attempts):
        if not failed:
            break
        sleep(delay_s)
        again, failed = apply([entry["project_id"] for entry in failed])
        migrated.extend(again)
    return migrated, failed


def project_ids_missing_grant_subject_user_id():
    """One catalog query: project schemas whose ``credential_use_grant`` has no ``subject_user_id`` column yet."""
    with db.get_session(None) as session:
        rows = session.execute(_MISSING_GRANT_COLUMN_QUERY).fetchall()
    return [int(row[0][2:]) for row in rows]


def apply_grant_subject_user_id(project_ids, dry_run=False):
    """Add ``credential_use_grant.subject_user_id`` where it is missing (``grant_subject_user_id`` step; additive and
    idempotent; the startup safety net runs it, since the model reads the column), one transaction per project that
    waits at most ``LOCK_TIMEOUT``. Returns ``(migrated, failed)``; on a dry run ``migrated`` is what would be added."""
    migrated, failed = [], []
    table = CredentialUseGrant.__table__
    for pid in project_ids:
        if dry_run:
            migrated.append(pid)
            continue
        try:
            with db.get_session(pid) as session:
                connection = session.connection()
                _set_lock_timeout(connection)
                _add_integer_column(connection, table, SUBJECT_USER_ID, _column_names(session, table))
                session.commit()
            migrated.append(pid)
        except Exception:  # pylint: disable=W0703
            log.exception("credential governance schema: failed to add subject_user_id to project %s", pid)
            failed.append({"project_id": pid})
    return migrated, failed


def apply_personal_index(project_ids, dry_run=False):
    """Swap the one live-reference index for the shared and personal pair and add ``written_by`` (``personal_index``
    step), one transaction per project (DDL is transactional on PostgreSQL, so a project is never left without a unique
    index) that waits at most ``LOCK_TIMEOUT`` for the table: a timeout fails that project alone. Existing rows are all
    non-personal, so both new indexes build over data the old one already kept unique. Returns ``(migrated, failed)``
    like ``apply_credential_tables``."""
    migrated, failed = [], []
    for pid in project_ids:
        if dry_run:
            migrated.append(pid)
            continue
        try:
            with db.get_session(pid) as session:
                connection = session.connection()
                _set_lock_timeout(connection)
                present = _index_names(session)
                _add_written_by(connection, _column_names(session))
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
