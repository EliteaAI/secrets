"""Operator actions on credential use grants (#6757, C-1009): the admin task behind
``manage_credential_grant``.

A grant lets one agent binding use one credential reference, for one toolkit, on behalf of one user
(``idp:<tenant>:<object>``) or of one autonomous mandate (``mandate:<uuid>``). It is created pending and
becomes active only when someone other than its creator approves it. Works with governance off. Every change is an audit event in the same transaction.
"""
import re
import uuid
from datetime import datetime, timezone

from pylon.core.tools import log
from sqlalchemy import Column, Integer, MetaData, String, Table, Uuid, select
from sqlalchemy.exc import IntegrityError
from tools import config as c

from ..models.credential_governance import CredentialReference, CredentialUseGrant
from . import credential_audit as audit
from .credential_errors import CredentialTaskError, require_actor
from .credential_schema import project_tx
from .credential_state import InvalidTransition, approve_grant, transition_grant

ACTIONS = ("create", "approve", "suspend", "resume", "revoke")
USAGE = (
    "Format: project_id=N;action=<create|approve|suspend|resume|revoke>;binding_ref=B;toolkit_id=T;ref=R;"
    "subject_ref=<idp:<tenant>:<object>|mandate:<uuid>>[;valid_until=<ISO-8601 with offset>] (create)"
    "[;approval_ref=...;policy_revision=...] (approve)[;dry_run]"
)
INT_KEYS = ("project_id", "toolkit_id")
TEXT_KEYS = ("action", "binding_ref", "ref", "subject_ref", "valid_until", "approval_ref", "policy_revision")
UUID_KEYS = ("binding_ref", "ref")
_IDP_SUBJECT = r"idp:[A-Za-z0-9._-]{1,64}:[A-Za-z0-9._-]{1,64}"
_MANDATE_SUBJECT = r"mandate:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"  # one spelling per id
SUBJECT_PATTERN = re.compile(rf"^(?:{_IDP_SUBJECT}|{_MANDATE_SUBJECT})$")
INACTIVE_MANDATE_STATES = ("expired", "revoked")
ANY_TARGET = "*"
# Moves that are not approval: action -> (states it starts from, state it ends in)
MOVES = {
    "suspend": ({"active"}, "suspended"),
    "resume": ({"suspended"}, "active"),
    "revoke": ({"pending_approval", "active", "suspended"}, "revoked"),
}

# Read-only views of the admission layer's tables: this plugin never imports another plugin's models. Real Table
# objects in a metadata of their own (never created from here): only those follow the project schema translation.
_VIEWS = MetaData()
_BINDING = Table(
    "agent_identity_binding", _VIEWS, Column("id", Uuid, primary_key=True), Column("project_id", Integer),
    Column("application_id", Integer), Column("version_id", Integer), schema=c.POSTGRES_TENANT_SCHEMA)
_MANDATE = Table(
    "autonomous_mandate", _VIEWS, Column("id", Uuid, primary_key=True), Column("project_id", Integer),
    Column("agent_binding_ref", Uuid), Column("state", String), schema=c.POSTGRES_TENANT_SCHEMA)
_TOOL_MAPPING = Table(
    "entity_tool_mapping", _VIEWS, Column("tool_id", Integer, primary_key=True), Column("entity_version_id", Integer),
    Column("entity_type", String), schema=c.POSTGRES_TENANT_SCHEMA)


def subject_kind(subject_ref: str) -> str:
    """``mandate`` for a ``mandate:<uuid>`` subject, else ``user_delegation`` (the subject was validated already)."""
    return "mandate" if subject_ref.startswith("mandate:") else "user_delegation"


def parse_grant_param(param):
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
    needed = ("project_id", "action", "binding_ref", "toolkit_id", "ref", "subject_ref")
    if values.get("action") == "approve":
        needed += ("approval_ref", "policy_revision")
    missing = [key for key in needed if not values.get(key)]
    if missing:
        return None, f"{', '.join(missing)} required. {USAGE}"
    if values["action"] not in ACTIONS:
        return None, f"invalid action: '{values['action']}'"
    if not SUBJECT_PATTERN.match(values["subject_ref"]):
        return None, f"invalid subject_ref: '{values['subject_ref']}'"
    if "valid_until" in values:
        if values["action"] != "create":
            return None, "valid_until applies to create only"
        try:
            until = datetime.fromisoformat(values["valid_until"])
        except ValueError:
            return None, f"invalid valid_until: '{values['valid_until']}'"
        if until.tzinfo is None or until <= datetime.now(timezone.utc):
            return None, f"invalid valid_until: '{values['valid_until']}' (needs an offset and must be in the future)"
        values["valid_until"] = until
    return values, None


def _find_grant(session, values):
    return session.execute(select(CredentialUseGrant).where(
        CredentialUseGrant.agent_binding_ref == uuid.UUID(values["binding_ref"]),
        CredentialUseGrant.toolkit_instance_id == str(values["toolkit_id"]),
        CredentialUseGrant.credential_ref == uuid.UUID(values["ref"]),
        CredentialUseGrant.target_ref == ANY_TARGET,
        CredentialUseGrant.subject_ref == values["subject_ref"],
    )).scalar_one_or_none()


def _subject_fields(values):
    subject = values["subject_ref"]
    if subject_kind(subject) == "mandate":
        return {"mandate_ref": subject.partition(":")[2]}
    return {"user_ref": subject}


def _check_mandate(session, values, project_id):
    """A mandate subject must be a live-enough mandate of this project for this very binding."""
    mandate = session.execute(select(_MANDATE.c.agent_binding_ref, _MANDATE.c.state).where(
        _MANDATE.c.id == uuid.UUID(values["subject_ref"].partition(":")[2]),
        _MANDATE.c.project_id == project_id)).first()
    if mandate is None:
        raise CredentialTaskError("MANDATE_NOT_FOUND")
    if mandate.agent_binding_ref != uuid.UUID(values["binding_ref"]):
        raise CredentialTaskError("MANDATE_BINDING_MISMATCH")
    if mandate.state in INACTIVE_MANDATE_STATES:
        raise CredentialTaskError("MANDATE_INACTIVE")


def _event(reason_code, values, actor, event_type="lifecycle", **fields):
    return audit.build_event(
        event_type, reason_code, project_id=values["project_id"], actor_user_id=actor,
        credential_ref=values["ref"], agent_binding_ref=values["binding_ref"],
        toolkit_instance_id=str(values["toolkit_id"]), target_ref=ANY_TARGET, **_subject_fields(values), **fields)


def _create(values, actor):
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        reference = session.execute(select(CredentialReference.state).where(
            CredentialReference.id == uuid.UUID(values["ref"]), CredentialReference.project_id == project_id,
        )).first()
        if reference is None:
            raise CredentialTaskError("REFERENCE_NOT_FOUND")
        if reference[0] == "retired":
            raise CredentialTaskError("INVALID_STATE")
        binding = session.execute(select(_BINDING.c.project_id, _BINDING.c.application_id, _BINDING.c.version_id).where(
            _BINDING.c.id == uuid.UUID(values["binding_ref"]))).first()
        if binding is None or binding.project_id != project_id:
            raise CredentialTaskError("BINDING_NOT_FOUND")
        if session.execute(select(_TOOL_MAPPING.c.tool_id).where(
                _TOOL_MAPPING.c.entity_version_id == binding.version_id, _TOOL_MAPPING.c.entity_type == "agent",
                _TOOL_MAPPING.c.tool_id == values["toolkit_id"])).first() is None:
            raise CredentialTaskError("TOOLKIT_NOT_IN_BINDING")
        if subject_kind(values["subject_ref"]) == "mandate":
            _check_mandate(session, values, project_id)
        if _find_grant(session, values) is not None:
            raise CredentialTaskError("GRANT_EXISTS")
        if values["dry_run"]:
            return {"dry_run": True, "action": "create", "state": "pending_approval"}
        grant = CredentialUseGrant(
            project_id=project_id, application_id=binding.application_id, subject_kind=subject_kind(values["subject_ref"]),
            subject_ref=values["subject_ref"], agent_binding_ref=uuid.UUID(values["binding_ref"]),
            toolkit_instance_id=str(values["toolkit_id"]), credential_ref=uuid.UUID(values["ref"]),
            target_ref=ANY_TARGET, valid_until=values.get("valid_until"), state="pending_approval",
            created_by=actor, state_changed_by=actor,
        )
        session.add(grant)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            raise CredentialTaskError("GRANT_EXISTS") from None
        grant_id = str(grant.id)
        audit.record(session, _event(
            "GRANT_PENDING_APPROVAL", values, actor, application_id=binding.application_id, outcome="success",
            revocation_epoch=0))
        session.commit()
    return {"action": "create", "grant": grant_id, "state": "pending_approval", "dry_run": False}


def _approve(values, actor):
    project_id = values["project_id"]
    with project_tx(project_id) as session:
        grant = _find_grant(session, values)
        if grant is None or grant.project_id != project_id:
            raise CredentialTaskError("GRANT_NOT_FOUND")
        if grant.state != "pending_approval":
            raise CredentialTaskError("INVALID_STATE")
        if grant.created_by == actor:
            raise CredentialTaskError("SELF_APPROVAL")
        if values["dry_run"]:
            return {"dry_run": True, "action": "approve", "grant": str(grant.id), "to": "active"}
        grant_id, application_id = grant.id, grant.application_id
        if not approve_grant(session, grant_id, actor=actor, approval_ref=values["approval_ref"],
                             policy_revision=values["policy_revision"]):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        audit.record(session, _event(
            "GRANT_ACTIVE", values, actor, event_type="approval", application_id=application_id, outcome="success",
            approver_ref=values["approval_ref"], policy_revision=values["policy_revision"], revocation_epoch=0))
        session.commit()
    return {"action": "approve", "grant": str(grant_id), "state": "active", "dry_run": False}


def _move(values, actor):
    action, project_id = values["action"], values["project_id"]
    starts, target = MOVES[action]
    with project_tx(project_id) as session:
        grant = _find_grant(session, values)
        if grant is None or grant.project_id != project_id:
            raise CredentialTaskError("GRANT_NOT_FOUND")
        if grant.state not in starts:
            raise CredentialTaskError("INVALID_STATE")
        grant_id, application_id, source = grant.id, grant.application_id, grant.state
        if values["dry_run"]:
            return {"dry_run": True, "action": action, "grant": str(grant_id), "from": source, "to": target}
        if not transition_grant(session, grant_id, source, target, actor=actor):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        epoch = session.execute(select(CredentialUseGrant.revocation_epoch).where(
            CredentialUseGrant.id == grant_id)).scalar_one()
        audit.record(session, _event(
            f"GRANT_{target.upper()}", values, actor, application_id=application_id, outcome="success",
            revocation_epoch=epoch))
        session.commit()
    return {"action": action, "grant": str(grant_id), "state": target, "dry_run": False}


_ACTIONS = {"create": _create, "approve": _approve, "suspend": _move, "resume": _move, "revoke": _move}


def manage_grant(param, actor_user_id=0):
    """Run one grant action. Returns a result dict, or ``{"error": ..., "code": ...}`` with nothing written."""
    values, error = parse_grant_param(param)
    if error:
        log.error("manage_credential_grant: %s", error)
        return {"error": error}
    try:
        if not values["dry_run"]:
            require_actor(actor_user_id)
        return _ACTIONS[values["action"]](values, actor_user_id)
    except CredentialTaskError as exc:
        return exc.result()
    except InvalidTransition as exc:
        return {"error": f"{exc.reason_code}: {exc}", "code": exc.reason_code}
    except Exception as exc:  # pylint: disable=W0703
        log.error("manage_credential_grant: failed (%s)", type(exc).__name__)
        return {"error": "failed; nothing was changed (is the audit trail available?)", "code": "FAILED"}
