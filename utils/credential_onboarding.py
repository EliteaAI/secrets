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

A ``personal`` reference belongs to one project member (``custodian_ref``: the user id and the identity-provider
subject, resolved on the server). It has no import: its value is written through ``credential_material`` (the same
staged write), and its probe checks the store and, on request, the connection (#7119).
"""
import hashlib
import hmac
import json
import uuid
from types import SimpleNamespace

from pylon.core.tools import log
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from tools import auth, config as c, secret_stores, this

from ..models.credential_governance import CredentialReference, CredentialStoreLedger
from . import credential_audit as audit
from . import credential_delegation as delegation
from .credential_errors import CredentialTaskError, require_actor, store_error_result
from .credential_queries import subject_ref_of_user
from .credential_schema import personal_schema_applied, project_tx
from .credential_state import (
    InvalidTransition, approve_reference, claim_generation, commit_generation, release_generation,
    set_ledger_state, transition_reference,
)

ACTIONS = ("create", "import", "probe", "approve", "activate", "suspend", "resume", "retire")
ONBOARD_STORE_KINDS = ("database", "corporate_vault")
ONBOARD_OWNERSHIP_CLASSES = ("project_shared", "service", "technical", "personal")
USAGE = (
    "Format: project_id=N;action=<create|import|probe|approve|activate|suspend|resume|retire>;"
    "configuration_uuid=U;store_kind=<database|corporate_vault>;"
    "ownership_class=<project_shared|service|technical|personal>[;owner_user_id=N] (create; the owner of a personal "
    "reference) or ref=R (every other action)[;approval_ref=...;policy_revision=...] (approve)[;check_connection] "
    "(probe of a personal reference)[;dry_run]"
)
INT_KEYS = ("project_id", "owner_user_id")
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
        if seg.lower() == "check_connection":
            values["check_connection"] = True
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
        if (values["ownership_class"] == "personal") != ("owner_user_id" in values):
            return None, f"owner_user_id goes with ownership_class=personal, and only with it. {USAGE}"
    elif "owner_user_id" in values:
        return None, "owner_user_id applies to create only"
    if values.get("check_connection") and action != "probe":
        return None, "check_connection applies to probe only"
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
        return {"row": "cs"}   # governed material has its own row (``<db key>:cs``); the adapter ignores the locator
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


KEEP_GENERATIONS = 2


def prune_superseded(ref, generation, actor, correlation, meta=None):
    """Drop all but the newest ``KEEP_GENERATIONS`` generations of a reference's material (the live one and the one a
    run admitted just before may still read). Anchored to the live generation: nothing is pruned unless the newest
    version in the store is ``generation``, so a generation staged above the live one is never touched or counted.
    ``meta``: the store metadata when the caller already has it. ``correlation``: the id of an audit event committed
    before this call (the store's decision id). The port allows ``prune`` to the ``retire`` and ``reconcile`` purposes
    only, so the ``reconcile`` purpose is used here, also on the activation path. Best effort: never raises and never
    changes a settled outcome (a failure is logged; the next generation prunes again). Returns whether it pruned."""
    if generation <= KEEP_GENERATIONS:   # nothing can be superseded yet: no store call
        return False
    try:
        store = secret_stores.get_store(ref.store_kind, governed=True)
        ctx = _mint("reconcile", ref, correlation, actor)
        if meta is None:
            meta = store.metadata(_store_ref(ref), ctx)
        if not meta.versions or max(meta.versions) != generation:
            return False
        store.prune(_store_ref(ref), KEEP_GENERATIONS, ctx)
        return True
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential store: prune failed (%s)", type(exc).__name__)
        return False


def write_to_store(ref, fields, generation, correlation, actor):
    """Write ``fields`` (name -> SecretStr) to the reference's store as ``generation``, with check-and-set on the
    previous one. The store writes live here, with the other custody calls; ``credential_material`` stages around it."""
    return secret_stores.get_store(ref.store_kind, governed=True).write(
        _store_ref(ref), secret_stores.SecretValue(fields, generation), expected_version=generation - 1,
        ctx=_mint("onboard", ref, correlation, actor))


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


def _custodian(ref):
    custodian = getattr(ref, "custodian_ref", None)
    return custodian if getattr(ref, "ownership_class", None) == "personal" and isinstance(custodian, dict) else {}


def _event(reason_code, ref, actor, event_type="lifecycle", **fields):
    """A personal reference's events name its owner (``user_ref``): the credential is attributed to that user."""
    subject = _custodian(ref).get("subject_ref")
    if subject:
        fields.setdefault("user_ref", subject)
    return audit.build_event(
        event_type, reason_code, project_id=ref.project_id, actor_user_id=actor, credential_ref=ref.id, **fields)


def _owner_custodian(project_id, owner_user_id) -> dict:
    """``custodian_ref`` of a personal reference: the owner must be a member of the project, and the identity-provider
    subject is resolved here, from the identity service (a caller never supplies it). Membership comes first, so the
    answer does not tell whether a user exists."""
    try:
        members = {int(row["user_id"]) for row in auth.list_project_user_roles(project_id) or []}
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    if owner_user_id not in members:
        raise CredentialTaskError("OWNER_NOT_MEMBER")
    try:
        subject = subject_ref_of_user(owner_user_id)
    except CredentialTaskError as exc:
        raise CredentialTaskError(
            "OWNER_UNLINKED" if exc.code in ("SUBJECT_UNLINKED", "SUBJECT_NOT_FOUND") else exc.code) from None
    return {"user_id": owner_user_id, "subject_ref": subject}


# --- actions -------------------------------------------------------------------------------------

def _create(values, actor):  # pylint: disable=R0914
    project_id = values["project_id"]
    delegated = values.get("auth_mode") == delegation.AUTH_MODE
    descriptor = delegation.parse_descriptor(values.get("delegation")) if delegated else None
    facts = _configuration_facts(project_id, values["configuration_uuid"])
    if facts is None:
        raise CredentialTaskError("CONFIGURATION_NOT_FOUND")
    if facts.get("section") != "credentials" or facts.get("project_id") != project_id:
        raise CredentialTaskError("CONFIGURATION_NOT_ELIGIBLE")
    if delegated:   # a container (#6756 step 4): the configuration holds no secret value, and nothing is stored
        if facts.get("type") not in delegation.PROVIDERS:
            raise CredentialTaskError("UNSUPPORTED_PROVIDER")
        delegation.require_app(project_id, descriptor)
        correlation = audit.new_event_id()
        delegation.require_container(lambda: _read_bundle(project_id, facts["id"], secret_stores.CredentialStoreProvider.mint(
            "onboard", decision_id=correlation, actor_ref=audit.operator_ref(actor), project_id=project_id,
            ref_id=uuid.uuid4())))
    else:
        secret_stores.get_store(values["store_kind"], governed=True)  # a store that cannot be used is refused now
    personal = values["ownership_class"] == "personal"
    custodian = _owner_custodian(project_id, values["owner_user_id"]) if personal else None
    live = select(CredentialReference.id).where(
        CredentialReference.configuration_id == facts["id"], CredentialReference.state != "retired")
    if personal:   # a personal reference stands beside the shared one; one per owner
        live = live.where(CredentialReference.ownership_class == "personal",
                          CredentialReference.custodian_ref["subject_ref"].as_string() == custodian["subject_ref"])
    else:
        live = live.where(CredentialReference.ownership_class != "personal")
    if values["dry_run"]:
        if personal:
            with project_tx(project_id) as session:
                if not personal_schema_applied(session):
                    raise CredentialTaskError("MIGRATION_REQUIRED")
        return {"dry_run": True, "action": "create", "state": "pending", "provider": facts["type"],
                **({"auth_mode": delegation.AUTH_MODE} if delegated else {})}
    with project_tx(project_id) as session:
        if personal and not personal_schema_applied(session):   # the old index would allow one reference per configuration
            raise CredentialTaskError("MIGRATION_REQUIRED")
        if session.execute(live).first() is not None:
            raise CredentialTaskError("REFERENCE_EXISTS")
        row = CredentialReference(
            project_id=project_id, configuration_id=facts["id"],
            configuration_uuid=uuid.UUID(values["configuration_uuid"]), provider=facts["type"],
            auth_mode=delegation.AUTH_MODE if delegated else delegation.STATIC_AUTH_MODE,
            ownership_class=values["ownership_class"], custodian_ref=custodian,
            store_kind=values["store_kind"], store_locator=_locator(values["store_kind"]),
            # a container has its one generation from the start: no value is ever written, so none follows
            generation=1 if delegated else 0, configuration_generation=facts.get("generation") if delegated else None,
            capabilities={delegation.CAPABILITY_KEY: descriptor} if delegated else {},
            state="pending", created_by=actor, state_changed_by=actor,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            raise CredentialTaskError("REFERENCE_EXISTS") from None
        audit.record(session, _event(
            "CREDENTIAL_REF_PENDING", row, actor, credential_generation=row.generation, outcome="success",
            revocation_epoch=0))
        session.commit()
        return {"action": "create", "reference": str(row.id), "state": "pending", "dry_run": False,
                **({"auth_mode": delegation.AUTH_MODE} if delegated else {})}


def _import(values, actor):  # pylint: disable=R0914
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if delegation.is_delegated(ref):   # a container: there is nothing to import
            raise CredentialTaskError("DELEGATED_NO_VALUE")
        if ref.ownership_class == "personal":   # the configuration holds the shared value, not this user's
            raise CredentialTaskError("USE_PERSONAL_VALUE")
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
        if not commit_generation(session, ref.id, generation, bundle["configuration_generation"], written_by=actor):
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


def _owner_check(project_id, ref):
    """A personal value is not compared with the configuration's own (they differ by design); what must still hold is
    that the configuration has not changed since the value was written."""
    facts = _configuration_facts(project_id, str(ref.configuration_uuid))
    if facts is None:
        raise CredentialTaskError("CONFIGURATION_NOT_FOUND")
    if facts.get("generation") != ref.configuration_generation:
        raise CredentialTaskError("CONFIGURATION_CHANGED")


def _probe_store(project_id, ref, ctx):
    """The store checks of a probe. Returns the store's request id."""
    store = secret_stores.get_store(ref.store_kind, governed=True)
    sref = _store_ref(ref)
    meta = store.metadata(sref, ctx)
    request_id = getattr(meta, "request_id", None)
    if ref.generation not in meta.versions:
        raise secret_stores.StoreError("NOT_FOUND")
    if ref.ownership_class == "personal":
        _owner_check(project_id, ref)
        return request_id
    stored = store.read(sref, ref.generation, ctx)
    current = _read_bundle(project_id, ref.configuration_id, ctx)
    if not hmac.compare_digest(_digest(stored.fields), _digest(current["fields"])):
        raise CredentialTaskError("MATERIAL_MISMATCH")
    if current["configuration_generation"] != ref.configuration_generation:
        raise CredentialTaskError("CONFIGURATION_CHANGED")
    return request_id


def _check_connection(project_id, ref, actor):
    """Test a personal reference's stored value against its provider. The operator (``actor``, already authorised by the
    REST layer) holds ``credentials.probe``; the personal reference probed is its custodian's. Raises
    ``CHECK_CONNECTION_FAILED`` when the provider refuses the credential, ``DENIED_RBAC`` when the actor may not probe,
    and ``CHECK_CONNECTION_REFUSED`` when the check could not run (worker, store, audit). The answer is a code only:
    the provider's own text can echo what it was given."""
    owner = (_custodian(ref) or {}).get("user_id")
    try:
        answer = this.for_module("elitea_core").module.governed_check_connection(
            project_id, str(ref.configuration_uuid), ref.provider, owner, actor_user_id=actor, onboarding=True)
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("CHECK_CONNECTION_REFUSED") from None
    if not isinstance(answer, dict) or answer.get("requires_authorization") or answer.get("success") not in (True, False):
        raise CredentialTaskError("CHECK_CONNECTION_REFUSED")
    if answer["success"]:
        return
    if answer.get("code") == "DENIED_RBAC":
        raise CredentialTaskError("DENIED_RBAC")
    raise CredentialTaskError("CHECK_CONNECTION_REFUSED" if answer.get("code") else "CHECK_CONNECTION_FAILED")


class _DelegatedProbe(Exception):
    """The reference probed is Entra-delegated: it has no store to look at (``_probe_delegated``)."""

    def __init__(self, ref):
        super().__init__("delegated")
        self.ref = ref


def _probe_any(values, actor):
    try:
        return _probe(values, actor)
    except _DelegatedProbe as found:
        return _probe_delegated(values, actor, found.ref)


def _probe_delegated(values, actor, ref):
    """The probe of an Entra-delegated reference (#6756 step 4): can its custodian (a personal one, probed by that
    person only: it uses their sign-in) or the operator (a project one) obtain a token through it now? A pending reference that passes becomes validated; the outcome is
    audited with the exchange's own code. No store is touched, and the token never reaches this plugin."""
    project_id = values["project_id"]
    if ref.state not in ("pending", "validated", "active"):
        raise CredentialTaskError("INVALID_STATE")
    person = actor
    if ref.ownership_class == "personal":   # the custodian's own sign-in is tried by the custodian, nobody else
        person = _custodian(ref).get("user_id")
        if person is None or person != actor:
            raise CredentialTaskError("DELEGATED_OWNER_PROBE")
    if values["dry_run"]:
        return {"dry_run": True, "action": "probe", "reference": values["ref"], "generation": ref.generation}
    failure = None
    try:
        delegation.probe(ref, person)
    except CredentialTaskError as exc:
        failure = exc
    state = ref.state
    with project_tx(project_id) as session:
        if failure is None and state == "pending":
            if not transition_reference(session, ref.id, "pending", "validated", actor=actor,
                                        validated_generation=ref.generation):
                session.rollback()
                raise CredentialTaskError("CONCURRENT_CHANGE")
            state = "validated"
        code = (getattr(failure, "reason", None) or failure.code) if failure else (
            "CREDENTIAL_REF_VALIDATED" if state != ref.state else "CREDENTIAL_DELEGATION_PROBED")
        audit.record(session, _event(code, ref, actor, event_type="probe", credential_generation=ref.generation,
                                     outcome="failed" if failure else "success"))
        session.commit()
    if failure is not None:
        return {**failure.result(), "reason": getattr(failure, "reason", failure.code)}
    return {"action": "probe", "reference": values["ref"], "generation": ref.generation, "state": state,
            "dry_run": False, "auth_mode": delegation.AUTH_MODE}


def _probe(values, actor):  # pylint: disable=R0914
    project_id = values["project_id"]
    check = bool(values.get("check_connection"))
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if delegation.is_delegated(ref):
            raise _DelegatedProbe(ref)   # the transaction ends untouched; probed on its own path
        if check and ref.ownership_class != "personal":
            raise CredentialTaskError("INVALID_REQUEST")
        if (ref.state not in (("pending", "validated", "active") if check else ("pending",)) or ref.generation < 1
                or ref.pending_generation is not None):
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
        request_id = _probe_store(project_id, ref, ctx)
    except (CredentialTaskError, secret_stores.StoreError) as exc:
        is_store = isinstance(exc, secret_stores.StoreError)
        with project_tx(project_id) as session:
            audit.record(session, _event(
                exc.audit_code if is_store else exc.code, ref, actor, event_type="probe",
                credential_generation=ref.generation, outcome="failed", vault_request_id=request_id))
            session.commit()
        return store_error_result(exc) if is_store else exc.result()
    #
    if check:   # before the reference is validated: a provider that refuses the value leaves it pending
        failure = _connection_outcome(project_id, ref, actor)
        if failure is not None:
            return failure
    state = ref.state
    if state == "pending":
        with project_tx(project_id) as session:
            if not transition_reference(session, ref.id, "pending", "validated", actor=actor,
                                        validated_generation=ref.generation):
                session.rollback()
                raise CredentialTaskError("CONCURRENT_CHANGE")
            audit.record(session, _event(
                "CREDENTIAL_REF_VALIDATED", ref, actor, event_type="probe", credential_generation=ref.generation,
                outcome="success", vault_request_id=request_id))
            session.commit()
        state = "validated"
    result = {"action": "probe", "reference": values["ref"], "generation": ref.generation, "state": state,
              "dry_run": False}
    if check:
        result["connection_checked"] = True
    return result


def _connection_outcome(project_id, ref, actor):
    """Run the connection check and record how it went (it changes no state). Returns the refusal result, or ``None``
    when the check passed."""
    try:
        _check_connection(project_id, ref, actor)
        failure, code = None, "CREDENTIAL_CONNECTION_CHECKED"
    except CredentialTaskError as exc:
        failure, code = exc, "CREDENTIAL_CONNECTION_CHECK_FAILED"
    with project_tx(project_id) as session:
        audit.record(session, _event(
            code, ref, actor, event_type="probe", credential_generation=ref.generation,
            outcome="failed" if failure else "success"))
        session.commit()
    return None if failure is None else failure.result()


def _approve(values, actor):
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        ref = _load(session, project_id, values["ref"])
        if ref.state != "validated" or ref.approved_by is not None:
            raise CredentialTaskError("INVALID_STATE")
        if actor in (ref.created_by, ref.written_by):   # not the creator, and not whoever wrote this generation
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
        correlation = audit.new_event_id()   # the activation event is the decision id of the prune below
        audit.record(session, _event(
            "CREDENTIAL_REF_ACTIVE", ref, actor, event_id=correlation, credential_generation=ref.generation,
            outcome="success", approver_ref=ref.approval_ref, policy_revision=ref.policy_revision,
            revocation_epoch=ref.revocation_epoch))
        session.commit()
    prune_superseded(ref, ref.generation, actor, correlation)   # a new generation is live: older ones are dropped
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
        has_material = target == "retired" and not delegation.is_delegated(ref) and (
            ref.generation > 0 or ref.pending_generation is not None)
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
    "create": _create, "import": _import, "probe": _probe_any, "approve": _approve, "activate": _activate,
    "suspend": _move, "resume": _move, "retire": _move,
}


def run_reference_action(values, actor_user_id=0, audit_code=False):
    """Run one reference action from parsed ``values`` (the admin task and the REST API both end here). Returns
    a result dict, or ``{"error": ..., "code": ...}`` with nothing written (an import or probe that failed after
    it began has recorded the failure). The task reports a down audit trail as ``FAILED``; ``audit_code`` (the
    REST API) reports it as ``AUDIT_UNAVAILABLE``."""
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
        code = "AUDIT_UNAVAILABLE" if audit_code and isinstance(exc, audit.AuditUnavailable) else "FAILED"
        return {"error": "failed; if an import was running, run reconcile_credential_store", "code": code}


def manage_reference(param, actor_user_id=0):
    """The admin task: parse the parameter string, then run the action."""
    values, error = parse_reference_param(param)
    if error:
        log.error("manage_credential_reference: %s", error)
        return {"error": error}
    return run_reference_action(values, actor_user_id)
