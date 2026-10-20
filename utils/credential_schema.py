"""Idempotent per-project setup of the credential governance tables (#6757, C-1009).

``create_all`` provisions them for new projects. Existing project schemas get them here, from the
startup safety net in ``module.py`` or from the ``create_credential_governance_tables`` admin task.
Both only create what is missing, so a steady-state boot issues no DDL.
"""
from contextlib import contextmanager

from sqlalchemy import bindparam, text
from pylon.core.tools import log
from tools import db

from ..models.credential_governance import CredentialReference, CredentialStoreLedger, CredentialUseGrant

_MODELS = (CredentialReference, CredentialUseGrant, CredentialStoreLedger)
USAGE = "project_id= is required. Format: project_id=<all|N>[;dry_run]"

# Only fully provisioned project schemas (they already hold the configuration table) are considered.
_MISSING_QUERY = text(
    "SELECT t.table_schema FROM information_schema.tables t "
    "WHERE t.table_name = 'configuration' AND t.table_schema ~ '^p_[0-9]+$' "
    "AND (SELECT count(*) FROM information_schema.tables x "
    "WHERE x.table_schema = t.table_schema AND x.table_name IN :names) < :expected"
).bindparams(bindparam("names", expanding=True))


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
