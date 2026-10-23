"""Credential reference and use grant lifecycles (#6757, C-1009): which changes are legal, and the
one conditional UPDATE that applies each without losing a race.

A reference becomes ``active`` only for material that was probed (``validated_generation`` equals
``generation``) and approved by someone other than its creator. Anything that takes a reference or a
grant out of use raises ``revocation_epoch``, so work admitted earlier can be told from work admitted
after the change. No function here commits: the caller owns the transaction, so related writes
(audit events, ledger rows) land with the change. False means the row is not in the expected state
any more (another writer won) or does not exist; the caller reads it again.
"""
from sqlalchemy import func, or_, update

from ..models.credential_governance import CredentialReference, CredentialStoreLedger, CredentialUseGrant

REFERENCE_TRANSITIONS = frozenset({
    ("pending", "validated"), ("validated", "pending"),  # a re-import invalidates the probe
    ("validated", "active"), ("active", "suspended"), ("suspended", "active"),
    ("pending", "retired"), ("validated", "retired"), ("active", "retired"), ("suspended", "retired"),
})
GRANT_TRANSITIONS = frozenset({
    ("pending_approval", "active"), ("active", "suspended"), ("suspended", "active"),
    ("pending_approval", "revoked"), ("active", "revoked"), ("suspended", "revoked"),
})
BUMPS_EPOCH = frozenset({"suspended", "retired", "revoked"})
# The states a new generation can be staged and committed in; ``suspended`` is the rotation path (suspend, write a new
# value, probe, approve, activate: the grants keep the reference id)
WRITABLE_STATES = ("pending", "validated", "suspended")
MAX_REF_LENGTH = 128


class InvalidTransition(ValueError):
    """The change is refused before touching the row. ``reason_code`` is stable, the message is for logs."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


def _require_actor(actor):
    if isinstance(actor, bool) or not isinstance(actor, int) or actor <= 0:
        raise InvalidTransition("ACTOR_REQUIRED", "an identified operator is required")


def _require_approval(approval_ref, policy_revision):
    for value in (approval_ref, policy_revision):
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_REF_LENGTH:
            raise InvalidTransition("APPROVAL_REQUIRED", "approval needs an approval reference and a policy revision")


def _apply(session, model, row_id, values, *conditions) -> bool:
    values["updated_at"] = func.now()
    result = session.execute(
        update(model).where(model.id == row_id, *conditions).values(**values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def transition_reference(  # pylint: disable=R0913
    session, ref_id, expected: str, target: str, *, actor: int, validated_generation=None,
) -> bool:
    """Move a reference from ``expected`` to ``target``. ``validated_generation`` is the probed generation
    (required for pending -> validated, which holds only while that is the committed generation)."""
    if (expected, target) not in REFERENCE_TRANSITIONS:
        raise InvalidTransition("INVALID_TRANSITION", f"{expected} -> {target} is not a legal reference change")
    _require_actor(actor)
    model = CredentialReference
    values = {"state": target, "state_changed_by": actor}
    conditions = [model.state == expected]
    if (expected, target) == ("pending", "validated"):
        if (isinstance(validated_generation, bool) or not isinstance(validated_generation, int)
                or validated_generation < 1):
            raise InvalidTransition("INVALID_TRANSITION", "a probed generation is required")
        values["validated_generation"] = validated_generation
        conditions += [model.generation == validated_generation, model.pending_generation.is_(None)]
    elif target == "pending":
        values.update(validated_generation=None, approved_by=None, approval_ref=None, policy_revision=None)
    elif target == "active":
        conditions += [model.approved_by.is_not(None), model.generation >= 1,
                       model.validated_generation == model.generation]
    if target in BUMPS_EPOCH:
        values["revocation_epoch"] = model.revocation_epoch + 1
    return _apply(session, model, ref_id, values, *conditions)


def transition_grant(session, grant_id, expected: str, target: str, *, actor: int) -> bool:
    """Move a grant from ``expected`` to ``target``. Approval is ``approve_grant``, not this."""
    if (expected, target) not in GRANT_TRANSITIONS or (expected, target) == ("pending_approval", "active"):
        raise InvalidTransition("INVALID_TRANSITION", f"{expected} -> {target} is not a legal grant change")
    _require_actor(actor)
    model = CredentialUseGrant
    values = {"state": target, "state_changed_by": actor}
    conditions = [model.state == expected]
    if target == "active":
        conditions.append(model.approved_by.is_not(None))
    if target in BUMPS_EPOCH:
        values["revocation_epoch"] = model.revocation_epoch + 1
    return _apply(session, model, grant_id, values, *conditions)


def approve_reference(session, ref_id, *, actor: int, approval_ref: str, policy_revision: str) -> bool:
    """Record the approval of a validated reference (state unchanged). Only someone other than its creator and the one
    who wrote its current generation."""
    _require_actor(actor)
    _require_approval(approval_ref, policy_revision)
    model = CredentialReference
    return _apply(
        session, model, ref_id,
        {"approved_by": actor, "approval_ref": approval_ref, "policy_revision": policy_revision,
         "state_changed_by": actor},
        model.state == "validated", model.approved_by.is_(None), model.created_by != actor,
        or_(model.written_by.is_(None), model.written_by != actor),
    )


def approve_grant(session, grant_id, *, actor: int, approval_ref: str, policy_revision: str) -> bool:
    """Approve a pending grant and activate it in the same statement. Only someone other than the creator."""
    _require_actor(actor)
    _require_approval(approval_ref, policy_revision)
    model = CredentialUseGrant
    return _apply(
        session, model, grant_id,
        {"state": "active", "approved_by": actor, "approval_ref": approval_ref, "policy_revision": policy_revision,
         "state_changed_by": actor},
        model.state == "pending_approval", model.approved_by.is_(None), model.created_by != actor,
        model.subject_kind.in_(("user_delegation", "mandate")),
    )


def claim_generation(session, ref_id, generation: int) -> bool:
    """Stake the next generation before the store is written: one importer wins, the other sees False."""
    model = CredentialReference
    return _apply(
        session, model, ref_id, {"pending_generation": generation},
        model.state.in_(WRITABLE_STATES), model.pending_generation.is_(None),
        model.generation == generation - 1,
    )


def release_generation(session, ref_id, generation: int) -> bool:
    """Drop a staged generation that did not reach the store."""
    model = CredentialReference
    return _apply(session, model, ref_id, {"pending_generation": None}, model.pending_generation == generation)


def commit_generation(session, ref_id, generation: int, configuration_generation, written_by=None) -> bool:
    """Make a staged write the committed generation (compare-and-set). A re-import of a validated reference
    puts it back to pending and clears its approval: the new material has to be probed and approved again (a suspended
    one, whose value was rotated, becomes pending the same way). ``written_by`` is whoever wrote it; ``None`` when that
    is not known (a write the reconciler rolls forward), and then the writer limit on approval does not apply."""
    model = CredentialReference
    return _apply(
        session, model, ref_id,
        {"generation": generation, "pending_generation": None, "configuration_generation": configuration_generation,
         "validated_generation": None, "approved_by": None, "approval_ref": None, "policy_revision": None,
         "state": "pending", "written_by": written_by},
        model.state.in_(WRITABLE_STATES), model.generation == generation - 1,
        model.pending_generation == generation,
    )


def set_ledger_state(session, ledger_id, expected: tuple, target: str) -> bool:
    """Advance a ledger row (intent -> written -> committed, or -> abandoned)."""
    model = CredentialStoreLedger
    return _apply(session, model, ledger_id, {"state": target}, model.state.in_(expected))
