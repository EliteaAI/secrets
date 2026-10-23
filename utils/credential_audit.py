"""Audit events of credential governance (#6757, C-1009): built in one place, recorded through tracing.

``record`` adds the event to the caller's session, so it commits with the change it describes.
Events carry references only: ids, generations, codes. Never material, a locator or a path.
"""
import uuid

from tools import this

OPERATOR = "operator"


def operator_ref(actor_user_id) -> str:
    return f"{OPERATOR}:{actor_user_id}" if actor_user_id else OPERATOR


def build_event(event_type, reason_code, *, project_id, actor_user_id, **fields) -> dict:
    """An event dict for ``security_audit_record``; ``None`` fields are dropped."""
    event = {"event_type": event_type, "reason_code": reason_code, "project_id": project_id,
             "caller_ref": operator_ref(actor_user_id), **fields}
    return {key: str(value) if isinstance(value, uuid.UUID) else value
            for key, value in event.items() if value is not None}


class AuditUnavailable(RuntimeError):
    """The audit trail did not take an event. The change it describes is not committed."""


def record(session, event: dict) -> str:
    """Add the event to ``session`` (no commit). Returns its ``event_id``; raises ``AuditUnavailable`` when the
    audit trail is down (a malformed event is a bug and keeps its own error)."""
    try:
        return this.for_module("tracing").module.security_audit_record(session, event)["event_id"]
    except (ValueError, TypeError):
        raise
    except Exception:  # pylint: disable=W0703
        raise AuditUnavailable("the audit trail is unavailable") from None


def record_autocommit(event: dict) -> None:
    """Record outside any caller transaction (events that belong to no project, e.g. the store smoke test)."""
    this.for_module("tracing").module.security_audit_record_autocommit(event)


def new_event_id() -> str:
    """An id for an event written later, so a store call can carry it as its decision id first."""
    return str(uuid.uuid4())
