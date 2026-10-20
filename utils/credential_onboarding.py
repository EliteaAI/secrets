"""Operator actions on credential references (#6757, C-1009): the admin task behind
``manage_credential_reference``.

``create`` -> ``import`` -> ``probe`` -> ``approve`` -> ``activate``, plus ``suspend``/``resume``/``retire``.
Works with governance off, so references can be prepared before the flag is switched on. Every state
change is a ``lifecycle``, ``probe`` or ``approval`` audit event written in the same transaction as the
change.

Import copies the secret material of the configuration into the reference's store, on the server: the
material never travels in a task parameter, a result, a log line or an event. The legacy copy stays
where it is until the release path moves to the store. The store write happens outside any
transaction, between three short ones (stake the generation, mark the ledger written, commit the
generation), so a crash at any point leaves a ledger row ``reconcile_credential_store`` settles.
"""
import hashlib
import hmac
import json
import uuid
from types import SimpleNamespace

from pylon.core.tools import log
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from tools import config as c, secret_stores, this

from ..models.credential_governance import CredentialReference, CredentialStoreLedger
from . import credential_audit as audit
from .credential_errors import CredentialTaskError, require_actor, store_error_result
from .credential_schema import project_tx
from .credential_state import (
    InvalidTransition, approve_reference, claim_generation, commit_generation, release_generation,
    set_ledger_state, transition_reference,
)

ACTIONS = ("create", "import", "probe", "approve", "activate", "suspend", "resume", "retire")
ONBOARD_STORE_KINDS = ("database", "corporate_vault")
ONBOARD_OWNERSHIP_CLASSES = ("project_shared", "service", "technical")
USAGE = (
    "Format: project_id=N;action=<create|import|probe|approve|activate|suspend|resume|retire>;"
    "configuration_uuid=U;store_kind=<database|corporate_vault>;ownership_class=<project_shared|service|technical> "
    "(create) or ref=R (every other action)[;approval_ref=...;policy_revision=...] (approve)[;dry_run]"
)
INT_KEYS = ("project_id",)
TEXT_KEYS = ("action", "configuration_uuid", "ref", "store_kind", "ownership_class", "approval_ref", "policy_revision")
UUID_KEYS = ("configuration_uuid", "ref")
# Store answers that prove the request was not carried out; anything else (a timeout) may have been
DEFINITE_STORE_FAILURES = frozenset({"DENIED", "SEALED", "TLS_INVALID", "VERSION_CONFLICT", "NOT_FOUND"})
# The states each simple action starts from, and the state it ends in
MOVES = {
    "suspend": ({"active"}, "suspended"),
    "resume": ({"suspended"}, "active"),
    "retire": ({"pending", "validated", "active", "suspended"}, "retired"),
}


def parse_reference_param(param):
    """``(values, None)`` or ``(None, readable error)``."""
    values = {"dry_run": False}
    for seg in [s.strip() for s in (param or "").split(";")]:
        if not seg:
            continue
        if seg.lower() == "dry_run":
            values["dry_run"] = True
            continue
        key, sep, value = seg.partition("=")
        key, value = key.strip().lower(), value.strip()
        if not sep or key not in INT_KEYS + TEXT_KEYS:
            return None, f"unknown parameter '{seg}'. {USAGE}"
        if key in INT_KEYS:
            try:
                values[key] = int(value)
            except ValueError:
                return None, f"invalid {key}: '{value}'"
            if values[key] <= 0:
                return None, f"invalid {key}: '{value}'"
        else:
            values[key] = value
    for key in UUID_KEYS:
        if key in values:
            try:
                values[key] = str(uuid.UUID(values[key]))
            except ValueError:
                return None, f"invalid {key}: '{values[key]}'"
    action = values.get("action")
    if "project_id" not in values or action is None:
        return None, f"project_id and action required. {USAGE}"
    if action not in ACTIONS:
        return None, f"invalid action: '{action}'"
    needed = ("configuration_uuid", "store_kind", "ownership_class") if action == "create" else ("ref",)
    if action == "approve":
        needed += ("approval_ref", "policy_revision")
    missing = [key for key in needed if not values.get(key)]
    if missing:
        return None, f"{', '.join(missing)} required. {USAGE}"
    if action == "create":
        if values["store_kind"] not in ONBOARD_STORE_KINDS:
            return None, f"invalid store_kind: '{values['store_kind']}'"
        if values["ownership_class"] not in ONBOARD_OWNERSHIP_CLASSES:
            return None, f"invalid ownership_class: '{values['ownership_class']}'"
    return values, None


def _configurations():
    try:
        return this.for_module("configurations").module
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None


def _configuration_facts(project_id, configuration_uuid):
    try:
        found = _configurations().configuration_credential_facts(project_id, [configuration_uuid])
    except CredentialTaskError:
        raise
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    return (found or {}).get(configuration_uuid)


def _read_bundle(project_id, configuration_id, ctx):
    """The configuration's secret fields (``fields``) and the generation they were read at."""
    try:
        bundle = _configurations().configuration_secret_bundle(project_id, configuration_id, ctx)
    except CredentialTaskError:
        raise
    except ValueError as exc:  # the method raises fixed codes, never values
        if str(exc) in ("NO_SECRET_FIELDS", "SECRET_UNRESOLVED"):
            raise CredentialTaskError(str(exc)) from None
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    if bundle is None:
        raise CredentialTaskError("CONFIGURATION_NOT_FOUND")
    return bundle


def _digest(fields) -> bytes:
    canonical = json.dumps(
        {name: secret.get_secret_value() for name, secret in fields.items()}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def _locator(store_kind):
    if store_kind == "database":
        return {"section": "credential_store"}
    return {"tenant": getattr(c, "CORPORATE_VAULT_TENANT_SEGMENT", None),
            "mount": getattr(c, "CORPORATE_VAULT_MOUNT", None) or "kv-elitea"}


def _load(session, project_id, ref_id):
    """The reference as plain values, so it can be used after the transaction ends."""
    row = session.execute(select(CredentialReference).where(
        CredentialReference.id == uuid.UUID(ref_id), CredentialReference.project_id == project_id,
    )).scalar_one_or_none()
    if row is None:
        raise CredentialTaskError("REFERENCE_NOT_FOUND")
    return SimpleNamespace(
        **{column.name: getattr(row, column.name) for column in CredentialReference.__table__.columns})


def _store_ref(ref):
    return secret_stores.StoreRef(
        ref_id=ref.id, project_id=ref.project_id, store_kind=ref.store_kind, locator=dict(ref.store_locator or {}))


def _mint(purpose, ref, correlation, actor):
    return secret_stores.CredentialStoreProvider.mint(
        purpose, decision_id=correlation, actor_ref=audit.operator_ref(actor), project_id=ref.project_id, ref_id=ref.id)


def _open_ledger(session, ref, generation, op, correlation):
    """Record the intent to touch the store. A row left by an abandoned attempt is reused."""
    row = session.execute(select(CredentialStoreLedger).where(
        CredentialStoreLedger.credential_ref == ref.id, CredentialStoreLedger.generation == generation,
        CredentialStoreLedger.op == op,
    )).scalar_one_or_none()
    if row is None:
        row = CredentialStoreLedger(
            credential_ref=ref.id, generation=generation, store_kind=ref.store_kind, op=op, state="intent",
            correlation_id=correlation, attempts=1)
        session.add(row)
    else:
        row.state, row.correlation_id, row.attempts = "intent", correlation, (row.attempts or 0) + 1
    session.flush()
    return row.id


def _event(reason_code, ref, actor, event_type="lifecycle", **fields):
    return audit.build_event(
        event_type, reason_code, project_id=ref.project_id, actor_user_id=actor, credential_ref=ref.id, **fields)


# --- actions -------------------------------------------------------------------------------------

def _create(values, actor):
    project_id = values["project_id"]
    facts = _configuration_facts(project_id, values["configuration_uuid"])
    if facts is None:
        raise CredentialTaskError("CONFIGURATION_NOT_FOUND")
    if facts.get("section") != "credentials" or facts.get("project_id") != project_id:
        raise CredentialTaskError("CONFIGURATION_NOT_ELIGIBLE")
    secret_stores.get_store(values["store_kind"], governed=True)  # a store that cannot be used is refused now
    if values["dry_run"]:
        return {"dry_run": True, "action": "create", "state": "pending", "provider": facts["type"]}
    with project_tx(project_id) as session:
        if session.execute(select(CredentialReference.id).where(
                CredentialReference.configuration_id == facts["id"], CredentialReference.state != "retired",
        )).first() is not None:
            raise CredentialTaskError("REFERENCE_EXISTS")
        row = CredentialReference(
            project_id=project_id, configuration_id=facts["id"],
            configuration_uuid=uuid.UUID(values["configuration_uuid"]), provider=facts["type"],
            auth_mode="static_secret", ownership_class=values["ownership_class"], store_kind=values["store_kind"],
            store_locator=_locator(values["store_kind"]), generation=0,
            state="pending", created_by=actor, state_changed_by=actor,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            raise CredentialTaskError("REFERENCE_EXISTS") from None
        audit.record(session, _event(
            "CREDENTIAL_REF_PENDING", row, actor, credential_generation=0, outcome="success", revocation_epoch=0))
        session.commit()
        return {"action": "create", "reference": str(row.id), "state": "pending", "dry_run": False}


def _import(values, actor):  # pylint: disable=R0914
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if ref.state not in ("pending", "validated"):
            raise CredentialTaskError("INVALID_STATE")
        generation = ref.generation + 1
        if values["dry_run"]:
            return {"dry_run": True, "action": "import", "reference": values["ref"], "generation": generation}
        correlation = audit.new_event_id()
        if not claim_generation(session, ref.id, generation):
            session.rollback()
            raise CredentialTaskError("IMPORT_IN_FLIGHT")
        ledger_id = _open_ledger(session, ref, generation, "write", correlation)
        audit.record(session, _event(
            "CREDENTIAL_IMPORT_STARTED", ref, actor, event_id=correlation, credential_generation=generation))
        session.commit()
    #
    try:
        ctx = _mint("onboard", ref, correlation, actor)
        bundle = _read_bundle(project_id, ref.configuration_id, ctx)
        store = secret_stores.get_store(ref.store_kind, governed=True)
        meta = store.write(
            _store_ref(ref), secret_stores.SecretValue(bundle["fields"], generation),
            expected_version=generation - 1, ctx=ctx)
    except (CredentialTaskError, secret_stores.StoreError) as exc:
        return _import_failed(project_id, ref, generation, ledger_id, actor, exc)
    #
    with project_tx(project_id) as session:
        set_ledger_state(session, ledger_id, ("intent",), "written")
        session.commit()
    with project_tx(project_id) as session:
        if not commit_generation(session, ref.id, generation, bundle["configuration_generation"]):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        set_ledger_state(session, ledger_id, ("intent", "written"), "committed")
        audit.record(session, _event(
            "CREDENTIAL_GENERATION_COMMITTED", ref, actor, credential_generation=generation, outcome="success",
            vault_request_id=getattr(meta, "request_id", None)))
        session.commit()
    return {"action": "import", "reference": values["ref"], "generation": generation, "state": "pending",
            "dry_run": False}


def _import_failed(project_id, ref, generation, ledger_id, actor, exc):
    """Settle a failed import. Whatever proves the store was not written is released at once; a timeout
    leaves the staged generation for the sweeper, which can look at the store."""
    is_store = isinstance(exc, secret_stores.StoreError)
    code = exc.audit_code if is_store else exc.code
    with project_tx(project_id) as session:
        if not is_store or exc.code in DEFINITE_STORE_FAILURES:
            release_generation(session, ref.id, generation)
            set_ledger_state(session, ledger_id, ("intent", "written"), "abandoned")
        audit.record(session, _event(code, ref, actor, credential_generation=generation, outcome="failed"))
        session.commit()
    return store_error_result(exc) if is_store else exc.result()


def _probe(values, actor):
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if ref.state != "pending" or ref.generation < 1 or ref.pending_generation is not None:
            raise CredentialTaskError("INVALID_STATE")
        if values["dry_run"]:
            return {"dry_run": True, "action": "probe", "reference": values["ref"], "generation": ref.generation}
        correlation = audit.new_event_id()
        audit.record(session, _event(
            "CREDENTIAL_PROBE_STARTED", ref, actor, event_id=correlation, credential_generation=ref.generation))
        session.commit()
    #
    request_id = None
    try:
        ctx = _mint("probe", ref, correlation, actor)
        store = secret_stores.get_store(ref.store_kind, governed=True)
        sref = _store_ref(ref)
        meta = store.metadata(sref, ctx)
        request_id = getattr(meta, "request_id", None)
        if ref.generation not in meta.versions:
            raise secret_stores.StoreError("NOT_FOUND")
        stored = store.read(sref, ref.generation, ctx)
        current = _read_bundle(project_id, ref.configuration_id, ctx)
        if not hmac.compare_digest(_digest(stored.fields), _digest(current["fields"])):
            raise CredentialTaskError("MATERIAL_MISMATCH")
        if current["configuration_generation"] != ref.configuration_generation:
            raise CredentialTaskError("CONFIGURATION_CHANGED")
    except (CredentialTaskError, secret_stores.StoreError) as exc:
        is_store = isinstance(exc, secret_stores.StoreError)
        with project_tx(project_id) as session:
            audit.record(session, _event(
                exc.audit_code if is_store else exc.code, ref, actor, event_type="probe",
                credential_generation=ref.generation, outcome="failed", vault_request_id=request_id))
            session.commit()
        return store_error_result(exc) if is_store else exc.result()
    #
    with project_tx(project_id) as session:
        if not transition_reference(session, ref.id, "pending", "validated", actor=actor,
                                    validated_generation=ref.generation):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        audit.record(session, _event(
            "CREDENTIAL_REF_VALIDATED", ref, actor, event_type="probe", credential_generation=ref.generation,
            outcome="success", vault_request_id=request_id))
        session.commit()
    return {"action": "probe", "reference": values["ref"], "generation": ref.generation, "state": "validated",
            "dry_run": False}


def _approve(values, actor):
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if ref.state != "validated" or ref.approved_by is not None:
            raise CredentialTaskError("INVALID_STATE")
        if ref.created_by == actor:
            raise CredentialTaskError("SELF_APPROVAL")
        if values["dry_run"]:
            return {"dry_run": True, "action": "approve", "reference": values["ref"], "state": "validated"}
        if not approve_reference(session, ref.id, actor=actor, approval_ref=values["approval_ref"],
                                 policy_revision=values["policy_revision"]):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        audit.record(session, _event(
            "CREDENTIAL_REF_APPROVED", ref, actor, event_type="approval", credential_generation=ref.generation,
            outcome="success", approver_ref=values["approval_ref"], policy_revision=values["policy_revision"],
            revocation_epoch=ref.revocation_epoch))
        session.commit()
    return {"action": "approve", "reference": values["ref"], "state": "validated", "approved": True, "dry_run": False}


def _activate(values, actor):
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if ref.state != "validated":
            raise CredentialTaskError("INVALID_STATE")
        if ref.approved_by is None:
            raise CredentialTaskError("APPROVAL_REQUIRED")
        if values["dry_run"]:
            return {"dry_run": True, "action": "activate", "reference": values["ref"], "to": "active"}
        if not transition_reference(session, ref.id, "validated", "active", actor=actor):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        audit.record(session, _event(
            "CREDENTIAL_REF_ACTIVE", ref, actor, credential_generation=ref.generation, outcome="success",
            approver_ref=ref.approval_ref, policy_revision=ref.policy_revision, revocation_epoch=ref.revocation_epoch))
        session.commit()
    return {"action": "activate", "reference": values["ref"], "state": "active", "dry_run": False}


def _revoke_contexts(session, ref_id):
    """Revoke the live runs that hold this reference, in the same transaction. The method belongs to the
    admission layer; where it is not installed yet no run can hold a credential decision."""
    try:
        revoke = getattr(this.for_module("elitea_core").module, "revoke_credential_contexts", None)
    except Exception:  # pylint: disable=W0703
        revoke = None
    if revoke is None:
        log.warning("credential reference change: revoke_credential_contexts is not available")
        return
    revoke(session, ref_id)


def _move(values, actor):  # pylint: disable=R0914
    """suspend, resume and retire: one transition, an epoch bump where it takes the reference out of use."""
    action, project_id = values["action"], values["project_id"]
    starts, target = MOVES[action]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if ref.state not in starts:
            raise CredentialTaskError("INVALID_STATE")
        if values["dry_run"]:
            return {"dry_run": True, "action": action, "reference": values["ref"], "from": ref.state, "to": target}
        has_material = target == "retired" and (ref.generation > 0 or ref.pending_generation is not None)
        correlation = audit.new_event_id()
        if not transition_reference(session, ref.id, ref.state, target, actor=actor):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        epoch = session.execute(select(CredentialReference.revocation_epoch).where(
            CredentialReference.id == ref.id)).scalar_one()
        if target in ("suspended", "retired"):
            _revoke_contexts(session, ref.id)
        ledger_id = None
        if has_material:
            ledger_id = _open_ledger(
                session, ref, max(ref.generation, ref.pending_generation or 0), "delete_all", correlation)
        audit.record(session, _event(
            f"CREDENTIAL_REF_{target.upper()}", ref, actor, event_id=correlation, credential_generation=ref.generation,
            outcome="success", revocation_epoch=epoch))
        session.commit()
    result = {"action": action, "reference": values["ref"], "state": target, "dry_run": False}
    if ledger_id is not None:
        result["material_deleted"] = _delete_material(project_id, ref, ledger_id, correlation, actor)
    return result


def _delete_material(project_id, ref, ledger_id, correlation, actor) -> bool:
    """Remove every generation of a retired reference from its store. False leaves the ledger row for the sweeper."""
    try:
        secret_stores.get_store(ref.store_kind, governed=True).delete_all(
            _store_ref(ref), _mint("retire", ref, correlation, actor))
    except secret_stores.StoreError as exc:
        with project_tx(project_id) as session:
            audit.record(session, _event(exc.audit_code, ref, actor, outcome="failed"))
            session.commit()
        return False
    with project_tx(project_id) as session:
        set_ledger_state(session, ledger_id, ("intent", "written"), "committed")
        audit.record(session, _event("CREDENTIAL_MATERIAL_DELETED", ref, actor, outcome="success"))
        session.commit()
    return True


_ACTIONS = {
    "create": _create, "import": _import, "probe": _probe, "approve": _approve, "activate": _activate,
    "suspend": _move, "resume": _move, "retire": _move,
}


def manage_reference(param, actor_user_id=0):
    """Run one reference action. Returns a result dict, or ``{"error": ..., "code": ...}`` with nothing
    written (an import or probe that failed after it began has recorded the failure)."""
    values, error = parse_reference_param(param)
    if error:
        log.error("manage_credential_reference: %s", error)
        return {"error": error}
    try:
        if not values["dry_run"]:
            require_actor(actor_user_id)
        return _ACTIONS[values["action"]](values, actor_user_id)
    except CredentialTaskError as exc:
        return exc.result()
    except secret_stores.StoreError as exc:
        return store_error_result(exc)
    except InvalidTransition as exc:
        return {"error": f"{exc.reason_code}: {exc}", "code": exc.reason_code}
    except Exception as exc:  # pylint: disable=W0703
        log.error("manage_credential_reference: failed (%s)", type(exc).__name__)
        return {"error": "failed; if an import was running, run reconcile_credential_store", "code": "FAILED"}
