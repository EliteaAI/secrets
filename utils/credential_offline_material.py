"""A person's offline delegated consent (#7131, C-1009): the store adapter of the refresh token a mandate owner gave.

When the owner of an autonomous mandate consents to its runs acting with their Microsoft sign-in, ``elitea_core`` obtains
one refresh token for it (auth_oidc) and keeps it here, as that person's personal material (class B): in the governed
store under the row's id, never in a row, an event, a result or a log line. The row says whose it is
(``custodian_user_id``, ``custodian_subject_ref`` = ``idp:<tid>:<oid>``, fixed at consent), which holder it was given to
(``holder_ref``, ``mandate:<uuid>``) and which client redeems it (``source``).

- ``keep``: a new row ``pending`` and generation 0, the store write of generation 1, then ``active`` with its event.
- ``release``: the token of an ``active`` row, only for its own holder and custodian (the caller names both; any
  difference is refused before the store is read). The caller decided and audits the use; this does not decide.
- ``rotate``: the authority issued a new refresh token on a redemption: written as the next generation (compare-and-set
  on the store and on the row), the older ones pruned to two.
- ``retire``: no longer releasable (consent withdrawn, the mandate gone, the authority refused it); the store copy is
  deleted after the state change committed. Idempotent.

A crash between the store write and the row leaves at most a ``pending`` row (never released) or one generation the row
does not name (never read); ``retire`` deletes every generation either way.
"""
import uuid
from datetime import datetime, timezone

from pydantic import SecretStr
from pylon.core.tools import log
from sqlalchemy import func, select, update
from tools import secret_stores

from ..models.credential_governance import MATERIAL_SOURCES, CredentialOfflineMaterial
from . import credential_audit as audit
from .credential_schema import project_tx

FIELD = "refresh_token"
STORE_KIND = "database"
KEEP_GENERATIONS = 2
MAX_TOKEN_CHARS = 16_384
MAX_REF_CHARS = 160
ROTATE_EVERY_S = 86_400   # at most one store write per day for a rotated token
RETIRED_REASONS = ("CONSENT_WITHDRAWN", "CONSENT_REPLACED", "CONSENT_REFUSED", "HOLDER_REVOKED")


class _Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _refused(code) -> dict:
    return {"ok": False, "reason_code": code}


def _text(value, limit=MAX_REF_CHARS) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit


def _token(value) -> str:
    token = value.get_secret_value() if hasattr(value, "get_secret_value") else value
    if not _text(token, MAX_TOKEN_CHARS):
        raise _Refused("INVALID_REQUEST")
    return token


def _store_ref(row):
    return secret_stores.StoreRef(ref_id=row.id, project_id=row.project_id, store_kind=row.store_kind,
                                  locator={"row": "cs"})


def _mint(purpose, row, decision_id, actor_ref):
    return secret_stores.CredentialStoreProvider.mint(
        purpose, decision_id=decision_id, actor_ref=actor_ref, project_id=row.project_id, ref_id=row.id)


def _event(event_type, reason_code, row, caller_ref, **fields):
    holder = row.holder_ref
    return audit.build_event(
        event_type, reason_code, project_id=row.project_id, actor_user_id=None, caller_ref=caller_ref,
        credential_ref=row.id, user_ref=row.custodian_subject_ref,
        mandate_ref=holder[len("mandate:"):] if holder.startswith("mandate:") else None, **fields)


def _load(session, project_id, material_ref):
    row = session.execute(select(CredentialOfflineMaterial).where(
        CredentialOfflineMaterial.id == uuid.UUID(str(material_ref)),
        CredentialOfflineMaterial.project_id == project_id)).scalar_one_or_none()
    if row is None:
        return None
    return type("Material", (), {column.name: getattr(row, column.name)
                                 for column in CredentialOfflineMaterial.__table__.columns})


def keep(project_id, *, holder_ref, custodian_user_id, custodian_subject_ref, source, refresh_token,
         actor_user_id) -> dict:  # pylint: disable=R0913
    """``{"ok": True, "material_ref", "generation"}`` or ``{"ok": False, "reason_code"}``. ``refresh_token``: a
    ``SecretStr``. The actor is the custodian (a person consents for themselves only)."""
    try:
        token = _token(refresh_token)
        if not (_text(holder_ref) and _text(custodian_subject_ref) and source in MATERIAL_SOURCES
                and isinstance(custodian_user_id, int) and not isinstance(custodian_user_id, bool)
                and custodian_user_id > 0 and actor_user_id == custodian_user_id):
            raise _Refused("INVALID_REQUEST")
        caller_ref = audit.operator_ref(actor_user_id)
        with project_tx(project_id) as session:
            row = CredentialOfflineMaterial(
                project_id=project_id, holder_ref=holder_ref, custodian_user_id=custodian_user_id,
                custodian_subject_ref=custodian_subject_ref, source=source, store_kind=STORE_KIND, generation=0,
                state="pending", created_by=actor_user_id)
            session.add(row)
            session.flush()
            material = type("Material", (), {"id": row.id, "project_id": project_id, "store_kind": STORE_KIND,
                                             "holder_ref": holder_ref, "custodian_subject_ref": custodian_subject_ref})
            session.commit()
        correlation = audit.new_event_id()
        secret_stores.get_store(STORE_KIND, governed=True).write(
            _store_ref(material), secret_stores.SecretValue({FIELD: SecretStr(token)}, 1), expected_version=0,
            ctx=_mint("onboard", material, correlation, caller_ref))
        token = None
        try:
            with project_tx(project_id) as session:
                moved = session.execute(update(CredentialOfflineMaterial).where(
                    CredentialOfflineMaterial.id == material.id, CredentialOfflineMaterial.state == "pending",
                    CredentialOfflineMaterial.generation == 0,
                ).values(state="active", generation=1, updated_at=func.now()).execution_options(
                    synchronize_session=False)).rowcount
                if moved != 1:
                    raise _Refused("CONCURRENT_CHANGE")
                audit.record(session, _event("lifecycle", "CREDENTIAL_OFFLINE_MATERIAL_KEPT", material, caller_ref,
                                             event_id=correlation, credential_generation=1, outcome="success"))
                session.commit()
        except BaseException:   # written but not activated: the store copy goes (the row stays pending, unreleased)
            _drop_unactivated(material, caller_ref)
            raise
        return {"ok": True, "material_ref": str(material.id), "generation": 1}
    except _Refused as refused:
        return _refused(refused.code)
    except secret_stores.StoreError as exc:
        return _refused(exc.audit_code)
    except audit.AuditUnavailable:
        return _refused("AUDIT_UNAVAILABLE")
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: keep failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")


def _drop_unactivated(material, caller_ref) -> None:
    """A value written whose row could not be activated: delete the store copy and retire the row (best effort; the
    row is pending, so it is never released either way)."""
    try:
        secret_stores.get_store(STORE_KIND, governed=True).delete_all(
            _store_ref(material), _mint("retire", material, audit.new_event_id(), caller_ref))
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: an unactivated value was not deleted (%s)", type(exc).__name__)
    try:
        with project_tx(material.project_id) as session:
            session.execute(update(CredentialOfflineMaterial).where(
                CredentialOfflineMaterial.id == material.id, CredentialOfflineMaterial.state == "pending",
            ).values(state="retired", retired_reason="CONSENT_REPLACED", updated_at=func.now()).execution_options(
                synchronize_session=False))
            session.commit()
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: an unactivated row was not retired (%s)", type(exc).__name__)


def release(project_id, material_ref, *, holder_ref, custodian_subject_ref, release_id, actor_ref) -> dict:
    """``{"ok": True, "refresh_token": SecretStr, "source", "generation"}`` or ``{"ok": False, "reason_code"}``:
    ``OFFLINE_MATERIAL_INACTIVE`` (none in this project, pending or retired), ``OFFLINE_MATERIAL_MISMATCH`` (another
    holder's or another person's), ``STORE_*``, ``DEPENDENCY_UNAVAILABLE``. One row read, one store read."""
    try:
        with project_tx(project_id) as session:
            row = _load(session, project_id, material_ref)
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: read failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")
    if row is None or row.state != "active" or row.generation < 1:
        return _refused("OFFLINE_MATERIAL_INACTIVE")
    if row.holder_ref != holder_ref or row.custodian_subject_ref != custodian_subject_ref:
        return _refused("OFFLINE_MATERIAL_MISMATCH")
    try:
        value = secret_stores.get_store(row.store_kind, governed=True).read(
            _store_ref(row), row.generation, _mint("release", row, release_id, actor_ref))
    except secret_stores.StoreError as exc:
        return _refused(exc.audit_code)
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: store read failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")
    token = (getattr(value, "fields", None) or {}).get(FIELD)
    if token is None:
        return _refused("STORE_NOT_FOUND")
    return {"ok": True, "refresh_token": token if hasattr(token, "get_secret_value") else SecretStr(token),
            "source": row.source, "generation": row.generation}


def rotate(project_id, material_ref, *, expected_generation, refresh_token, caller_ref, min_interval_s=ROTATE_EVERY_S,
           now=None) -> dict:  # pylint: disable=R0913
    """Keep the refresh token the authority issued on a redemption as the next generation: ``{"ok": True,
    "generation", "kept"}`` or ``{"ok": False, "reason_code"}`` (``CONCURRENT_CHANGE`` when another rotation or a
    retirement won; the older generation is still the row's then). Written only while the row is ``active`` at
    ``expected_generation``, and at most once per ``min_interval_s`` (the authority rotates on almost every redemption;
    the token kept stays valid, so ``kept`` is False and nothing is written in between)."""
    try:
        token = _token(refresh_token)
        with project_tx(project_id) as session:
            row = _load(session, project_id, material_ref)
        if row is None or row.state != "active" or row.generation != expected_generation:
            raise _Refused("CONCURRENT_CHANGE")
        changed = row.updated_at if row.updated_at is None or row.updated_at.tzinfo else \
            row.updated_at.replace(tzinfo=timezone.utc)
        if changed is not None and ((now or datetime.now(timezone.utc)) - changed).total_seconds() < min_interval_s:
            return {"ok": True, "generation": row.generation, "kept": False}
        generation, correlation = expected_generation + 1, audit.new_event_id()
        store = secret_stores.get_store(row.store_kind, governed=True)
        store.write(_store_ref(row), secret_stores.SecretValue({FIELD: SecretStr(token)}, generation),
                    expected_version=expected_generation, ctx=_mint("onboard", row, correlation, caller_ref))
        token = None
        with project_tx(project_id) as session:
            moved = session.execute(update(CredentialOfflineMaterial).where(
                CredentialOfflineMaterial.id == row.id, CredentialOfflineMaterial.state == "active",
                CredentialOfflineMaterial.generation == expected_generation,
            ).values(generation=generation, updated_at=func.now()).execution_options(
                synchronize_session=False)).rowcount
            if moved != 1:
                raise _Refused("CONCURRENT_CHANGE")
            audit.record(session, _event("rotation", "CREDENTIAL_OFFLINE_MATERIAL_ROTATED", row, caller_ref,
                                         event_id=correlation, credential_generation=generation, outcome="success"))
            session.commit()
        try:
            store.prune(_store_ref(row), KEEP_GENERATIONS, _mint("reconcile", row, correlation, caller_ref))
        except Exception as exc:  # pylint: disable=W0703  # best effort: the next rotation prunes again
            log.error("offline material: prune failed (%s)", type(exc).__name__)
        return {"ok": True, "generation": generation, "kept": True}
    except _Refused as refused:
        return _refused(refused.code)
    except secret_stores.StoreError as exc:
        return _refused(exc.audit_code)
    except audit.AuditUnavailable:
        return _refused("AUDIT_UNAVAILABLE")
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: rotate failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")


def retire(project_id, material_ref, *, reason, caller_ref, actor_user_id=None) -> dict:
    """No longer releasable, from now: ``{"ok": True, "retired": bool}`` (``False``: it was retired already) or
    ``{"ok": False, "reason_code"}``. The state change and its event commit first; the store copy is deleted after
    (a failed delete is logged and the copy is never read again)."""
    if reason not in RETIRED_REASONS:
        return _refused("INVALID_REQUEST")
    try:
        with project_tx(project_id) as session:
            row = _load(session, project_id, material_ref)
            if row is None:
                return _refused("OFFLINE_MATERIAL_INACTIVE")
            moved = session.execute(update(CredentialOfflineMaterial).where(
                CredentialOfflineMaterial.id == row.id, CredentialOfflineMaterial.state != "retired",
            ).values(state="retired", retired_by=actor_user_id, retired_reason=reason,
                     updated_at=func.now()).execution_options(synchronize_session=False)).rowcount
            if moved:
                audit.record(session, _event("withdrawal", "CREDENTIAL_OFFLINE_MATERIAL_RETIRED", row, caller_ref,
                                             credential_generation=row.generation or None, outcome="success"))
            session.commit()
        try:
            secret_stores.get_store(row.store_kind, governed=True).delete_all(
                _store_ref(row), _mint("retire", row, audit.new_event_id(), caller_ref))
        except Exception as exc:  # pylint: disable=W0703
            log.error("offline material: the store copy was not deleted (%s)", type(exc).__name__)
        return {"ok": True, "retired": bool(moved)}
    except audit.AuditUnavailable:
        return _refused("AUDIT_UNAVAILABLE")
    except Exception as exc:  # pylint: disable=W0703
        log.error("offline material: retire failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")
