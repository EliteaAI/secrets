"""Batch granting on approval, and the owner's consent notice (#7269, C-1009).

An approver who approves a member's grant may grant the same use to other members of the project at once ("also grant
to": user ids, or every member holding a project role). The approver is never a sibling's subject: named, the batch is
refused with ``SELF_APPROVAL`` and nothing is written; as a holder of the role, they are skipped (nobody grants a use to
themselves). The number of siblings is capped before any subject is looked up. The approval and the sibling grants are
one transaction (the shared session of ``credential_schema``): each sibling is created through the grant lifecycle under
the approved request (same binding, toolkit, reference and validity, its creator the requester of the approved grant, so
the four-eyes rule and its CHECK hold for each: the approver is never its creator) and approved by the same approver with
the same approval; its lifecycle events carry ``caller_ref batch:<grant id>`` and ``GRANT_BATCH_SIBLING`` names the
approver, so the audit says who decided. A personal reference or a mandate's grant has no siblings (a personal
credential is its owner's only).

After an approval commits, a grant on a credential that acts with a person's Microsoft sign-in asks for that person's
consent where it is given (#7337): the owner of a mandate's grant is notified to consent on the schedule, the subject of a
person's grant to consent for their scoped tokens when the platform lets tokens act with their owner's sign-in. The notice
is the platform's notification, never a consent itself.
"""
import uuid

from pylon.core.tools import log
from sqlalchemy import select
from tools import auth, db, this

from . import credential_audit as audit, credential_schema
from .credential_errors import CredentialTaskError
from .credential_grants import _MANDATE, ANY_TARGET, run_grant_action
from ..models.credential_governance import CredentialReference, CredentialUseGrant

MAX_SIBLINGS = 100
ROLES = ("admin", "editor", "viewer")
CONSENT_EVENT = "governance_consent_needed"
DELEGATED = "entra_delegated"
TOKEN_SOURCE = "token_owner_delegated"


class _OneTransaction:
    """The batch's session as the lifecycle functions see it: their commit is a flush (one commit at the end)."""

    def __init__(self, session):
        self._session = session

    def commit(self):
        self._session.flush()

    def __getattr__(self, name):
        return getattr(self._session, name)


def _members(project_id, user_ids, role):
    """The user ids to grant to: the named ones (each must be a member) and every holder of ``role``."""
    try:
        roles = {row["id"]: row["name"] for row in auth.list_project_roles(project_id) or []}
        members = {}
        for row in auth.list_project_user_roles(project_id) or []:
            if row.get("user_id") is not None:
                members.setdefault(int(row["user_id"]), set()).add(roles.get(row.get("role_id")))
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    named = list(dict.fromkeys(user_ids or []))
    if any(user_id not in members for user_id in named):
        raise CredentialTaskError("OWNER_NOT_MEMBER")
    by_role = [user_id for user_id, names in sorted(members.items()) if role and role in names and "system" not in names]
    return named, by_role


def approve_with_siblings(project_id, grant_id, approval, actor, user_ids=(), role=None):
    """Approve ``grant_id`` and grant the same use to ``user_ids`` and the holders of ``role``, all or nothing.
    ``{ok: True, id, state, siblings: [ids], skipped}``, or ``CredentialTaskError``."""
    if role is not None and role not in ROLES:
        raise CredentialTaskError("INVALID_REQUEST")
    named, by_role = _members(project_id, user_ids, role)
    if actor in named:
        raise CredentialTaskError("SELF_APPROVAL")   # the approver never grants a use to themselves
    from .credential_grants import grant_key_by_id  # pylint: disable=C0415
    from .credential_queries import subject_ref_of_user  # pylint: disable=C0415
    key = grant_key_by_id(project_id, grant_id)
    with db.get_session(project_id) as raw:
        grant = raw.execute(select(CredentialUseGrant).where(CredentialUseGrant.id == uuid.UUID(str(grant_id)))).scalar_one()
        reference = raw.get(CredentialReference, grant.credential_ref)
        if grant.subject_kind == "mandate" or reference is None or reference.ownership_class == "personal":
            raise CredentialTaskError("NO_SIBLINGS")   # a personal credential or a mandate's grant has no siblings
        requester, valid_until = grant.created_by, grant.valid_until
        existing = set(raw.execute(select(CredentialUseGrant.subject_user_id).where(
            CredentialUseGrant.agent_binding_ref == grant.agent_binding_ref,
            CredentialUseGrant.toolkit_instance_id == grant.toolkit_instance_id,
            CredentialUseGrant.credential_ref == grant.credential_ref, CredentialUseGrant.target_ref == ANY_TARGET,
            CredentialUseGrant.state != "revoked")).scalars())
        candidates = named + [user_id for user_id in by_role if user_id not in named]
        skipped = [user_id for user_id in candidates if user_id in existing or user_id == actor]
        candidates = [user_id for user_id in candidates if user_id not in skipped]
        if len(candidates) > MAX_SIBLINGS:   # before any subject is looked up
            raise CredentialTaskError("INVALID_REQUEST")
        targets = []
        for user_id in candidates:
            try:
                targets.append((user_id, subject_ref_of_user(user_id)))
            except CredentialTaskError as exc:
                if user_id in named or exc.code not in ("SUBJECT_UNLINKED", "SUBJECT_NOT_FOUND"):
                    raise
                skipped.append(user_id)   # a member of the role with no linked sign-in cannot hold a grant
        session = _OneTransaction(raw)
        token = credential_schema._SHARED_SESSION.set((project_id, session))  # pylint: disable=W0212
        try:
            approved = run_grant_action({"project_id": project_id, "action": "approve", "dry_run": False, **key,
                                         **approval}, actor, audit_code=True)
            if approved.get("error") is not None:
                raise CredentialTaskError(approved.get("code") or "FAILED")
            siblings = []
            for user_id, subject in targets:
                values = {"project_id": project_id, "binding_ref": key["binding_ref"], "toolkit_id": key["toolkit_id"],
                          "ref": key["ref"], "subject_ref": subject, "subject_user_id": user_id, "dry_run": False,
                          "caller_ref": f"batch:{grant_id}"}
                if valid_until is not None:
                    values["valid_until"] = valid_until
                created = run_grant_action({**values, "action": "create"}, requester, audit_code=True)
                if created.get("error") is not None:
                    raise CredentialTaskError(created.get("code") or "FAILED")
                done = run_grant_action({**values, "action": "approve", **approval}, actor, audit_code=True)
                if done.get("error") is not None:
                    raise CredentialTaskError(done.get("code") or "FAILED")
                audit.record(raw, audit.build_event(
                    "lifecycle", "GRANT_BATCH_SIBLING", project_id=project_id, actor_user_id=actor,
                    credential_ref=key["ref"], agent_binding_ref=key["binding_ref"],
                    toolkit_instance_id=str(key["toolkit_id"]), target_ref=f"grant:{grant_id}", user_ref=subject,
                    outcome="success"))
                siblings.append(created["grant"])
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            credential_schema._SHARED_SESSION.reset(token)  # pylint: disable=W0212
    for granted in [str(grant_id), *siblings]:
        notify_consent(project_id, granted)
    return {"ok": True, "action": "approve", "id": str(grant_id), "state": "active", "siblings": siblings,
            "skipped": skipped}


def _token_source_allowed():
    try:
        config = this.for_module("elitea_core").descriptor.config or {}
        return TOKEN_SOURCE in (config.get("mandate_identity_sources") or [])
    except Exception:  # pylint: disable=W0703
        return False


def _governed():
    """Is credential governance enforced (elitea_core, same process)? Unknown: no."""
    try:
        return bool(this.for_module("elitea_core").module.governance_profile.enabled)
    except Exception:  # pylint: disable=W0703
        return False


def notify_consent(project_id, grant_id) -> bool:
    """After an approval: ask the person whose consent a grant on a sign-in credential needs. Never raises. Off and
    audit only: nothing is read or sent (consent applies only while governance is enforced)."""
    if not _governed():
        return False
    try:
        with db.get_session(project_id) as session:
            row = session.execute(select(
                CredentialUseGrant.subject_kind, CredentialUseGrant.subject_ref, CredentialUseGrant.subject_user_id,
                CredentialUseGrant.state, CredentialReference.auth_mode, CredentialReference.provider,
            ).join(CredentialReference, CredentialReference.id == CredentialUseGrant.credential_ref).where(
                CredentialUseGrant.id == uuid.UUID(str(grant_id)))).first()
            if row is None or row.state != "active" or row.auth_mode != DELEGATED:
                return False
            if row.subject_kind == "mandate":
                owner = session.execute(select(_MANDATE.c.owner_user_id).where(
                    _MANDATE.c.id == uuid.UUID(row.subject_ref.partition(":")[2]))).scalar_one_or_none()
                user_id, target, text = owner, "schedules", "Your schedule can use a credential that acts with your " \
                    "Microsoft sign-in. Give your consent on the [schedule]()."
            elif _token_source_allowed():
                user_id, target, text = row.subject_user_id, "tokens", "You were granted a credential that acts with " \
                    "your Microsoft sign-in. To use it with a scoped API token, give your consent on [Personal tokens]()."
            else:
                return False
        if not user_id:
            return False
        this.module.context.event_manager.fire_event("notifications_stream", {
            "project_id": project_id, "user_id": int(user_id), "event_type": CONSENT_EVENT,
            "meta": {"message": text, "target": target, "grant_id": str(grant_id)}})
        return True
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential grants: the consent notice was not sent (%s)", type(exc).__name__)
        return False
