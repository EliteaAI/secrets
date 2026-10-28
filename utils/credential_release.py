"""Trusted release of credential material (#6946, WP-1D slice 1, C-1009): the one place that reads a
reference's material for a run or a probe.

The caller (``elitea_core``, over the worker bus) has already decided: context, binding, grant, epochs, audit.
This module re-reads the reference itself, so a reference suspended, retired or moved to another generation
since that decision is refused here, mints the ``release`` store context and reads exactly the generation the
caller asked for. No fallback to another generation or another store.

The answer is a ``SecretValue`` (redacted repr, no pickle) inside a dict, or a refusal that is only a code.
Nothing here logs, audits or caches the value; the release audit event belongs to the caller, which commits it
before it builds any reply. ``release_id`` is the store ``decision_id`` (the Vault ``X-Correlation-Id``).

``release_materials`` is the batch: one session reads every reference, then one ``read_many`` per store kind, whatever
the number of references (perf review 2026-10-21, M1). A refusal of any item refuses the whole call before any store is
read, and a store failure discards what other stores returned: never partial material. ``release_material`` is the
batch of one.
"""
import uuid
from types import SimpleNamespace

from pylon.core.tools import log
from sqlalchemy import select
from tools import db, secret_stores

from ..models.credential_governance import CredentialReference
from .credential_delegation import DelegatedValue, is_delegated
from .credential_onboarding import _store_ref

RUN_STATES = frozenset({"active"})
PROBE_STATES = frozenset({"validated", "active"})  # a probe of saved material precedes activation
ONBOARDING_PROBE_STATES = frozenset({"pending", "validated", "active"})  # and a personal value is tried before it is validated
MAX_RELEASE_ITEMS = 64  # references per batch: what the stores' read_many takes


def _refused(reason_code: str, ref_id=None) -> dict:
    return {"ok": False, "reason_code": reason_code, "ref_id": None if ref_id is None else str(ref_id)}


def _items(items) -> dict:
    """``{ref uuid: generation}`` of a well-formed batch (``ValueError`` with a fixed message otherwise); a reference
    named twice must be named with one generation."""
    if not isinstance(items, (list, tuple)) or not items:
        raise ValueError("items: a non-empty list")
    wanted = {}
    for item in items:
        if not isinstance(item, dict) or "ref_id" not in item or "generation" not in item:
            raise ValueError("items: {ref_id, generation} each")
        ref_id, generation = item["ref_id"], item["generation"]
        ref_uuid = ref_id if isinstance(ref_id, uuid.UUID) else uuid.UUID(str(ref_id))
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise ValueError("generation: a positive integer")
        if wanted.setdefault(ref_uuid, generation) != generation:
            raise ValueError("items: one generation per reference")
    return wanted


def _allowed_states(allow_validated, allow_pending):
    return ONBOARDING_PROBE_STATES if allow_pending else PROBE_STATES if allow_validated else RUN_STATES


def _load_references(project_id, ref_uuids) -> dict:
    """``{ref uuid: row}`` of the project's references among ``ref_uuids``: one session, one statement. A reference
    of another project is simply absent."""
    with db.get_session(project_id) as session:
        rows = session.execute(select(CredentialReference).where(
            CredentialReference.project_id == project_id, CredentialReference.id.in_(list(ref_uuids)))).scalars().all()
        return {row.id: SimpleNamespace(
            **{column.name: getattr(row, column.name) for column in CredentialReference.__table__.columns})
            for row in rows}


def release_materials(  # pylint: disable=R0913
    project_id, items, release_id, actor_ref, *, allow_validated=False, allow_pending=False,
) -> dict:
    """``{"ok": True, "values": {ref_id: SecretValue}}`` or ``{"ok": False, "reason_code": ..., "ref_id": ...}``
    (``ref_id`` is the reference that was refused, ``None`` when none is to blame); ``ValueError`` (fixed message) for
    a malformed request. ``items``: ``[{ref_id, generation}]``, at most ``MAX_RELEASE_ITEMS`` references (more is
    refused as ``INVALID_REQUEST`` with nothing read, like the stores' ``read_many`` would). The first refusal in the
    order of ``items`` wins; reasons are those of ``release_material``."""
    if isinstance(items, (list, tuple)) and len(items) > MAX_RELEASE_ITEMS:
        return _refused("INVALID_REQUEST")
    wanted = _items(items)
    # validates project_id, release_id and actor_ref; a context is bound to one reference, so one is minted for each
    contexts = {ref_uuid: secret_stores.CredentialStoreProvider.mint(
        "release", decision_id=release_id, actor_ref=actor_ref, project_id=project_id, ref_id=ref_uuid)
        for ref_uuid in wanted}
    try:
        found = _load_references(project_id, wanted)
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential release: reference read failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")
    states = _allowed_states(allow_validated, allow_pending)
    for ref_uuid, generation in wanted.items():  # every check before any store is read
        ref = found.get(ref_uuid)
        if ref is None or ref.state not in states:  # absent, another project's, or not releasable: the same answer
            return _refused("CREDENTIAL_REFERENCE_INACTIVE", ref_uuid)
        if ref.generation != generation:
            return _refused("CREDENTIAL_GENERATION_MISMATCH", ref_uuid)
    by_kind, read = {}, {}
    for ref_uuid in wanted:
        if is_delegated(found[ref_uuid]):   # a container (#6756 step 4): its descriptor, no store read
            try:
                read[ref_uuid] = DelegatedValue(found[ref_uuid])
            except Exception:  # pylint: disable=W0703  # a descriptor that does not validate is not released
                return _refused("CREDENTIAL_REFERENCE_INACTIVE", ref_uuid)
            continue
        by_kind.setdefault(found[ref_uuid].store_kind, []).append(ref_uuid)
    for store_kind, ref_uuids in by_kind.items():
        try:
            got = secret_stores.get_store(store_kind, governed=True).read_many(
                [_store_ref(found[ref_uuid]) for ref_uuid in ref_uuids], [wanted[ref_uuid] for ref_uuid in ref_uuids],
                [contexts[ref_uuid] for ref_uuid in ref_uuids])
            read.update({ref_uuid: got[(ref_uuid, wanted[ref_uuid])] for ref_uuid in ref_uuids})
        except secret_stores.StoreError as exc:
            return _refused(exc.audit_code, (getattr(exc, "details", None) or {}).get("ref_id"))
        except Exception as exc:  # pylint: disable=W0703
            log.error("credential release: store read failed (%s)", type(exc).__name__)
            return _refused("DEPENDENCY_UNAVAILABLE")
    return {"ok": True, "values": {str(ref_uuid): read[ref_uuid] for ref_uuid in wanted}}  # in the order asked


def release_material(  # pylint: disable=R0913
    project_id, ref_id, generation, release_id, actor_ref, *, allow_validated=False, allow_pending=False,
) -> dict:
    """``{"ok": True, "value": SecretValue}`` or ``{"ok": False, "reason_code": ...}``; ``ValueError`` (fixed
    message) for a malformed request. Reasons: ``CREDENTIAL_REFERENCE_INACTIVE`` (no such reference in this
    project, or not in a state that may be released), ``CREDENTIAL_GENERATION_MISMATCH``, ``STORE_*`` (the store's
    own code), ``DEPENDENCY_UNAVAILABLE``. The batch of one."""
    answer = release_materials(
        project_id, [{"ref_id": ref_id, "generation": generation}], release_id, actor_ref,
        allow_validated=allow_validated, allow_pending=allow_pending)
    if not answer["ok"]:
        return {"ok": False, "reason_code": answer["reason_code"]}
    (value,) = answer["values"].values()
    return {"ok": True, "value": value}
