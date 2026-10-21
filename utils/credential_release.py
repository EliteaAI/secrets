"""Trusted release of credential material (#6946, WP-1D slice 1, C-1009): the one place that reads a
reference's material for a run or a probe.

The caller (``elitea_core``, over the worker bus) has already decided: context, binding, grant, epochs, audit.
This module re-reads the reference itself, so a reference suspended, retired or moved to another generation
since that decision is refused here, mints the ``release`` store context and reads exactly the generation the
caller asked for. No fallback to another generation or another store.

The answer is a ``SecretValue`` (redacted repr, no pickle) inside a dict, or a refusal that is only a code.
Nothing here logs, audits or caches the value; the release audit event belongs to the caller, which commits it
before it builds any reply. ``release_id`` is the store ``decision_id`` (the Vault ``X-Correlation-Id``).
"""
import uuid

from pylon.core.tools import log
from tools import db, secret_stores

from .credential_errors import CredentialTaskError
from .credential_onboarding import _load, _store_ref

RUN_STATES = frozenset({"active"})
PROBE_STATES = frozenset({"validated", "active"})  # a probe of saved material precedes activation
ONBOARDING_PROBE_STATES = frozenset({"pending", "validated", "active"})  # and a personal value is tried before it is validated


def _refused(reason_code: str) -> dict:
    return {"ok": False, "reason_code": reason_code}


def release_material(  # pylint: disable=R0913
    project_id, ref_id, generation, release_id, actor_ref, *, allow_validated=False, allow_pending=False,
) -> dict:
    """``{"ok": True, "value": SecretValue}`` or ``{"ok": False, "reason_code": ...}``; ``ValueError`` (fixed
    message) for a malformed request. Reasons: ``CREDENTIAL_REFERENCE_INACTIVE`` (no such reference in this
    project, or not in a state that may be released), ``CREDENTIAL_GENERATION_MISMATCH``, ``STORE_*`` (the store's
    own code), ``DEPENDENCY_UNAVAILABLE``."""
    ref_uuid = ref_id if isinstance(ref_id, uuid.UUID) else uuid.UUID(str(ref_id))
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ValueError("generation: a positive integer")
    # validates project_id, release_id and actor_ref too
    ctx = secret_stores.CredentialStoreProvider.mint(
        "release", decision_id=release_id, actor_ref=actor_ref, project_id=project_id, ref_id=ref_uuid)
    try:
        with db.get_session(project_id) as session:
            ref = _load(session, project_id, str(ref_uuid))
    except CredentialTaskError:  # absent, or another project's: the same answer
        return _refused("CREDENTIAL_REFERENCE_INACTIVE")
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential release: reference read failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")
    if ref.state not in (ONBOARDING_PROBE_STATES if allow_pending else PROBE_STATES if allow_validated else RUN_STATES):
        return _refused("CREDENTIAL_REFERENCE_INACTIVE")
    if ref.generation != generation:
        return _refused("CREDENTIAL_GENERATION_MISMATCH")
    try:
        value = secret_stores.get_store(ref.store_kind, governed=True).read(_store_ref(ref), generation, ctx)
    except secret_stores.StoreError as exc:
        return _refused(exc.audit_code)
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential release: store read failed (%s)", type(exc).__name__)
        return _refused("DEPENDENCY_UNAVAILABLE")
    return {"ok": True, "value": value}
