"""Store reconciliation and the store smoke test (#6757, C-1009): the admin tasks behind
``reconcile_credential_store`` and ``credential_store_smoke``.

The reconciler settles ledger rows an import or a retire left behind (a crash between the store and the
database, or a store that timed out). It looks at the store before it decides: a staged generation that
reached the store is committed, one that did not is released, and the material of a retired or missing
reference is deleted. It never deletes the material of a live reference. Each outcome is an audit event.
"""
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from pylon.core.tools import log
from sqlalchemy import select
from tools import secret_stores

from ..models.credential_governance import CredentialReference, CredentialStoreLedger
from . import credential_audit as audit
from .credential_errors import CredentialTaskError, require_actor, store_error_result
from .credential_onboarding import _configuration_facts, _mint, _store_ref
from .credential_schema import (
    parse_project_param, project_ids_missing_credential_tables, project_tx, target_project_ids,
)
from .credential_state import commit_generation, release_generation, set_ledger_state

DEFAULT_OLDER_THAN_S = 300
BATCH_SIZE = 200
RECONCILE_USAGE = "project_id= is required. Format: project_id=<all|N>[;older_than_s=300][;dry_run]"
SMOKE_USAGE = "Format: store_kind=corporate_vault[;dry_run]"


def parse_reconcile_param(param):
    """``(project_id_filter, older_than_s, dry_run, None)`` or ``(None, 0, False, readable error)``."""
    older_than_s = DEFAULT_OLDER_THAN_S
    rest = []
    for seg in [s.strip() for s in (param or "").split(";")]:
        if seg.lower().startswith("older_than_s="):
            try:
                older_than_s = int(seg.split("=", 1)[1])
            except ValueError:
                return None, 0, False, f"invalid {seg}"
            if older_than_s < 0:
                return None, 0, False, f"invalid {seg}"
        elif seg:
            rest.append(seg)
    project_id_filter, dry_run, error = parse_project_param(";".join(rest), RECONCILE_USAGE)
    return project_id_filter, older_than_s, dry_run, error


def _reference_view(project_id, row):
    """What the store calls need, for a reference that may no longer exist."""
    return SimpleNamespace(id=row.credential_ref, project_id=project_id, store_kind=row.store_kind, store_locator={})


def _event(reason_code, ref_view, actor, **fields):
    return audit.build_event(
        "lifecycle", reason_code, project_id=ref_view.project_id, actor_user_id=actor, credential_ref=ref_view.id,
        **fields)


def _begin(project_id, view, row, actor):
    """The audit event a store call carries as its decision id, committed before the call."""
    correlation = audit.new_event_id()
    with project_tx(project_id) as session:
        audit.record(session, _event(
            "CREDENTIAL_RECONCILE_STARTED", view, actor, event_id=correlation, credential_generation=row.generation))
        session.commit()
    return correlation


def _close(  # pylint: disable=R0913
    project_id, row, view, actor, ledger_state, reason_code, *, commit=False, configuration_generation=None,
    release=False,
):
    """Move the ledger row to its end state, with the reference change it implies, in one transaction.
    False: the commit lost a race and nothing was changed."""
    with project_tx(project_id) as session:
        if commit and not commit_generation(session, view.id, row.generation, configuration_generation):
            session.rollback()
            return False
        if release:
            release_generation(session, view.id, row.generation)
        set_ledger_state(session, row.id, ("intent", "written"), ledger_state)
        audit.record(session, _event(
            reason_code, view, actor, credential_generation=row.generation, outcome="success"))
        session.commit()
    return True


def _store_failed(project_id, view, row, actor, exc):
    with project_tx(project_id) as session:
        audit.record(session, _event(
            exc.audit_code, view, actor, credential_generation=row.generation, outcome="failed"))
        session.commit()
    return "deferred"


def _delete_material(project_id, row, view, actor, ledger_state, reason_code):
    correlation = _begin(project_id, view, row, actor)
    try:
        secret_stores.get_store(view.store_kind, governed=True).delete_all(
            _store_ref(view), _mint("reconcile", view, correlation, actor))
    except secret_stores.StoreError as exc:
        return _store_failed(project_id, view, row, actor, exc)
    _close(project_id, row, view, actor, ledger_state, reason_code)
    return "completed" if ledger_state == "committed" else "abandoned"


def _settle_write(project_id, row, ref, view, actor):  # pylint: disable=R0911
    generation = row.generation
    if ref is None or ref.state == "retired":
        return _delete_material(project_id, row, view, actor, "abandoned", "CREDENTIAL_RECONCILED_ABANDONED")
    if ref.generation >= generation:  # the commit went through; only the ledger lagged
        _close(project_id, row, view, actor, "committed", "CREDENTIAL_RECONCILED_COMMITTED")
        return "healed"
    if ref.pending_generation != generation:  # nothing staged: leave the store alone
        _close(project_id, row, view, actor, "abandoned", "CREDENTIAL_RECONCILED_ABANDONED")
        return "abandoned"
    correlation = _begin(project_id, view, row, actor)
    try:
        ctx = _mint("reconcile", view, correlation, actor)
        meta = secret_stores.get_store(view.store_kind, governed=True).metadata(_store_ref(view), ctx)
    except secret_stores.StoreError as exc:
        return _store_failed(project_id, view, row, actor, exc)
    if generation not in meta.versions:
        _close(project_id, row, view, actor, "abandoned", "CREDENTIAL_RECONCILED_ABANDONED", release=True)
        return "abandoned"
    # The material is in the store: commit it against the configuration as it is now. A probe compares the
    # two, so a configuration whose secret changed in between cannot be validated and has to be imported again.
    try:
        facts = _configuration_facts(project_id, str(ref.configuration_uuid))
    except CredentialTaskError:
        return "deferred"
    done = _close(project_id, row, view, actor, "committed", "CREDENTIAL_RECONCILED_COMMITTED",
                  commit=True,
                  configuration_generation=(facts or {}).get("generation"))
    return "rolled_forward" if done else "deferred"


def _settle_delete(project_id, row, ref, view, actor):
    if ref is not None and ref.state != "retired":  # never delete what a live reference still points at
        _close(project_id, row, view, actor, "abandoned", "CREDENTIAL_RECONCILED_ABANDONED")
        return "abandoned"
    return _delete_material(project_id, row, view, actor, "committed", "CREDENTIAL_RECONCILED_DELETED")


def _settle(project_id, row, actor):
    with project_tx(project_id) as session:
        found = session.execute(select(CredentialReference).where(
            CredentialReference.id == row.credential_ref, CredentialReference.project_id == project_id,
        )).scalar_one_or_none()
        ref = None if found is None else SimpleNamespace(
            state=found.state, generation=found.generation, pending_generation=found.pending_generation,
            configuration_uuid=found.configuration_uuid)
    view = _reference_view(project_id, row)
    settle = _settle_write if row.op == "write" else _settle_delete
    return settle(project_id, row, ref, view, actor)


def reconcile_project(project_id, older_than_s, actor, dry_run=False) -> Counter:
    """Settle the stale ledger rows of one project (at most ``BATCH_SIZE`` per run). Counts by outcome."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=older_than_s)
    with project_tx(project_id) as session:
        rows = [
            SimpleNamespace(id=r.id, credential_ref=r.credential_ref, generation=r.generation,
                            store_kind=r.store_kind, op=r.op)
            for r in session.execute(
                select(CredentialStoreLedger)
                .where(CredentialStoreLedger.state.in_(("intent", "written")),
                       CredentialStoreLedger.updated_at <= cutoff)
                .order_by(CredentialStoreLedger.updated_at).limit(BATCH_SIZE)
            ).scalars()
        ]
    counts = Counter()
    for row in rows:
        counts["candidates" if dry_run else _settle(project_id, row, actor)] += 1
    return counts


def reconcile_store(module, param, actor_user_id=0):
    """Settle interrupted store writes and deletes. Returns totals by outcome; never a path or a value."""
    project_id_filter, older_than_s, dry_run, error = parse_reconcile_param(param)
    if error:
        log.error("reconcile_credential_store: %s", error)
        return {"error": error}
    if not dry_run:
        try:
            require_actor(actor_user_id)
        except CredentialTaskError as exc:
            return exc.result()
    try:
        missing = set(project_ids_missing_credential_tables())
        project_ids = [pid for pid in target_project_ids(module, project_id_filter) if pid not in missing]
    except Exception:  # pylint: disable=W0703
        log.exception("reconcile_credential_store: failed to list projects")
        return {"error": "failed to list projects"}
    totals, failed = Counter(), []
    for pid in project_ids:
        try:
            totals.update(reconcile_project(pid, older_than_s, actor_user_id, dry_run))
        except Exception as exc:  # pylint: disable=W0703
            log.error("reconcile_credential_store: project %s failed (%s)", pid, type(exc).__name__)
            failed.append({"project_id": pid})
    log.info("%sreconcile_credential_store: %s failed=%s", "[DRY RUN] " if dry_run else "", dict(totals), len(failed))
    return {**dict(totals), "failed": len(failed), "failed_projects": failed, "dry_run": dry_run}


# --- store smoke test ------------------------------------------------------------------------------

def run_store_smoke(param, actor_user_id=0):
    """Check the customer policy shape of the corporate Vault store: the canary reads, a list, another
    tenant and a write without check-and-set are all refused. Operator only."""
    values = {"dry_run": False}
    for seg in [s.strip() for s in (param or "").split(";") if s.strip()]:
        key, _, value = seg.partition("=")
        if seg.lower() == "dry_run":
            values["dry_run"] = True
        elif key.strip().lower() == "store_kind" and value.strip():
            values["store_kind"] = value.strip()
        else:
            return {"error": f"unknown parameter '{seg}'. {SMOKE_USAGE}"}
    if values.get("store_kind") != "corporate_vault":
        return {"error": f"store_kind=corporate_vault required. {SMOKE_USAGE}"}
    if values["dry_run"]:
        return {"dry_run": True, "action": "smoke", "store_kind": "corporate_vault"}
    try:
        require_actor(actor_user_id)
    except CredentialTaskError as exc:
        return exc.result()
    correlation = audit.new_event_id()
    try:
        store = secret_stores.get_store("corporate_vault", governed=True)
        audit.record_autocommit(audit.build_event(
            "lifecycle", "CREDENTIAL_STORE_SMOKE_STARTED", project_id=None, actor_user_id=actor_user_id,
            event_id=correlation))
        ctx = secret_stores.CredentialStoreProvider.mint(
            "smoke", decision_id=correlation, actor_ref=audit.operator_ref(actor_user_id), project_id=0,
            ref_id=uuid.uuid4())
        checks = store.smoke(ctx)
    except secret_stores.StoreError as exc:
        _record_smoke_outcome(actor_user_id, exc.audit_code, "failed")
        return store_error_result(exc)
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential_store_smoke: failed (%s)", type(exc).__name__)
        return {"error": "failed; nothing was changed (is the audit trail available?)", "code": "FAILED"}
    passed = all(checks.values())
    _record_smoke_outcome(
        actor_user_id, "CREDENTIAL_STORE_SMOKE_PASSED" if passed else "CREDENTIAL_STORE_SMOKE_FAILED",
        "success" if passed else "failed")
    return {"action": "smoke", "store_kind": "corporate_vault", "checks": dict(checks), "passed": passed,
            "dry_run": False}


def _record_smoke_outcome(actor_user_id, reason_code, outcome):
    try:
        audit.record_autocommit(audit.build_event(
            "probe", reason_code, project_id=None, actor_user_id=actor_user_id, outcome=outcome))
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential_store_smoke: outcome not recorded (%s)", type(exc).__name__)
