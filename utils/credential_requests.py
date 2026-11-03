"""A member's request for credential references and use grants, inside elitea_core's batch (#7269, C-1009).

``file_requests`` runs each item through the lifecycle function its admin task and REST route use
(``run_reference_action`` / ``run_grant_action``: their checks, four-eyes rules and audit events unchanged) with the
batch's session as the session of every ``project_tx`` of that project, so the batch commits once or not at all. The
member is the actor: a reference is the member's own personal one (custodian and owner the member), a grant is for the
member or for the member's mandate. A refused item raises ``CredentialTaskError`` (its code, ``key`` the item).
"""
import uuid

from . import credential_schema
from .credential_errors import CredentialTaskError
from .credential_grants import run_grant_action
from .credential_onboarding import run_reference_action

STORE_KIND = "database"
MAX_ITEMS = 128


def _refuse(result, key):
    error = CredentialTaskError(result.get("code") or "FAILED")
    error.key = key
    raise error


def _uuid(value):
    return str(uuid.UUID(str(value)))


def file_requests(session, project_id, items, actor):
    """``[{key, id}]`` in order, or ``CredentialTaskError`` (the batch is then rolled back by its owner)."""
    if not isinstance(items, list) or len(items) > MAX_ITEMS or not isinstance(actor, int) or actor <= 0:
        raise CredentialTaskError("INVALID_REQUEST")
    token = credential_schema._SHARED_SESSION.set((project_id, session))  # pylint: disable=W0212
    try:
        filed = []
        for item in items:
            if item.get("kind") == "reference":
                result = run_reference_action({
                    "project_id": project_id, "action": "create", "configuration_uuid": _uuid(item["configuration_uuid"]),
                    "store_kind": STORE_KIND, "ownership_class": "personal", "owner_user_id": actor, "dry_run": False,
                }, actor, audit_code=True)
                identifier = result.get("reference")
            elif item.get("kind") == "grant":
                subject = item.get("subject_ref")
                if not isinstance(subject, str) or not (subject.startswith("idp:") or subject.startswith("mandate:")):
                    raise CredentialTaskError("INVALID_REQUEST")
                if subject.startswith("idp:") and item.get("subject_user_id") != actor:
                    raise CredentialTaskError("FORBIDDEN")   # a member asks for their own grants only
                result = run_grant_action({
                    "project_id": project_id, "action": "create", "binding_ref": _uuid(item["binding_ref"]),
                    "toolkit_id": int(item["toolkit_id"]), "ref": _uuid(item["ref"]), "subject_ref": subject,
                    "subject_user_id": item.get("subject_user_id"), "dry_run": False,
                }, actor, audit_code=True)
                identifier = result.get("grant")
            else:
                raise CredentialTaskError("INVALID_REQUEST")
            if result.get("error") is not None or not identifier:
                _refuse(result, item.get("key"))
            filed.append({"key": item.get("key"), "id": identifier})
        return filed
    finally:
        credential_schema._SHARED_SESSION.reset(token)  # pylint: disable=W0212
