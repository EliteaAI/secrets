"""REST skin over the credential lifecycle (#7119, C-1009): request validation, per-action permissions and the
mapping of lifecycle results to HTTP replies.

The state machines are not here. Every change goes through ``run_reference_action`` / ``run_grant_action``, the
same functions the admin tasks end in, so a REST call writes the same rows and the same audit event as the task.
Request bodies are strict: unknown fields, wrong types and a raw ``subject_ref`` are refused (400) before anything
runs, and no reply contains a value from the request, a store locator or secret material.
"""
import json
import uuid
from typing import ClassVar, Optional

from flask import request
from pydantic.v1 import BaseModel, Extra, StrictInt, StrictStr, ValidationError, root_validator, validator
from pylon.core.tools import log
from tools import auth, config as c
from werkzeug.exceptions import RequestEntityTooLarge

from . import credential_queries as queries
from .credential_errors import MESSAGES, CredentialTaskError
from .credential_grants import grant_key_by_id, parse_valid_until, run_grant_action
from .credential_onboarding import (
    ACTIONS as REFERENCE_ACTIONS, ONBOARD_OWNERSHIP_CLASSES, ONBOARD_STORE_KINDS, run_reference_action,
)
from .credential_state import MAX_REF_LENGTH
from ..models.credential_governance import GRANT_STATES, OWNERSHIP_CLASSES, REFERENCE_STATES, STORE_KINDS

VIEW, MANAGE, PROBE, APPROVE = "credentials.view", "credentials.manage", "credentials.probe", "credentials.approve"
_OPERATORS = {"super_admin": True, "admin": True, "viewer": False, "editor": False}
# Read access exists in administration mode only; the project (default) mode has no handler in slice 1
VIEW_ROLES = {
    "administration": dict(_OPERATORS),
    "default": {"system": False, "super_admin": False, "admin": False, "viewer": False, "editor": False},
}
# What the permission registry (module.py) and the handlers recommend for manage, probe and approve
OPERATE_ROLES = {"administration": dict(_OPERATORS), "default": {"admin": True, "viewer": False, "editor": False}}
REFERENCE_ACTION_PERMISSION = {
    "import": MANAGE, "activate": MANAGE, "suspend": MANAGE, "resume": MANAGE, "retire": MANAGE,
    "probe": PROBE, "approve": APPROVE,
}
GRANT_ACTION_PERMISSION = {"approve": APPROVE, "suspend": MANAGE, "resume": MANAGE, "revoke": MANAGE}

MAX_BODY_BYTES = 8192
DEFAULT_LIMIT, MAX_LIMIT, MAX_SEARCH = 20, 100, 128
SORT_ORDERS = ("asc", "desc")

STATUS = {
    400: ("INVALID_REQUEST", "APPROVAL_REQUIRED", "CONFIGURATION_NOT_ELIGIBLE", "UNSUPPORTED_STORE_KIND",
          "UNSUPPORTED_OWNERSHIP_CLASS", "TOOLKIT_NOT_IN_BINDING", "MANDATE_BINDING_MISMATCH"),
    403: ("FORBIDDEN", "SELF_APPROVAL", "ACTOR_REQUIRED"),
    404: ("REFERENCE_NOT_FOUND", "GRANT_NOT_FOUND", "CONFIGURATION_NOT_FOUND", "BINDING_NOT_FOUND",
          "MANDATE_NOT_FOUND", "SUBJECT_NOT_FOUND"),
    409: ("INVALID_STATE", "INVALID_TRANSITION", "CONCURRENT_CHANGE", "REFERENCE_EXISTS", "GRANT_EXISTS",
          "IMPORT_IN_FLIGHT", "CONFIGURATION_CHANGED", "MATERIAL_MISMATCH", "NO_SECRET_FIELDS", "SECRET_UNRESOLVED",
          "MANDATE_INACTIVE", "SUBJECT_UNLINKED"),
    413: ("REQUEST_TOO_LARGE",),
    503: ("DEPENDENCY_UNAVAILABLE",),
}
_STATUS_OF = {code: status for status, codes in STATUS.items() for code in codes}


def status_of(code):
    """The HTTP status of a refusal code: the store's codes are 503, anything unlisted is 500."""
    if isinstance(code, str) and code.startswith("STORE_"):
        return 503
    return _STATUS_OF.get(code, 500)


# --- replies -----------------------------------------------------------------------------------------------------

def error_reply(code, message=None):
    """``({error, code}, status)`` with a fixed message that holds no id or request value."""
    return {"error": message or MESSAGES.get(code) or MESSAGES["FAILED"], "code": code}, status_of(code)


def result_reply(result, created=False):
    """A lifecycle result as a reply: ``{ok: true, id, state, ...}`` or the refusal it carries."""
    if isinstance(result, dict) and result.get("error") is not None:
        code = result.get("code") or "FAILED"
        message = MESSAGES.get(code)
        if message is None:  # a store code: "STORE_X: message"
            prefix = f"{code}: "
            text = str(result["error"])
            message = text[len(prefix):] if text.startswith(prefix) else MESSAGES["FAILED"]
        return error_reply(code, message)
    body = {"ok": True}
    for key, value in result.items():
        if key == "dry_run":
            continue
        body["id" if key in ("reference", "grant") else key] = value
    return body, 201 if created else 200


def respond(handler, *args):
    """Run a handler body; refusals and unexpected failures become replies (a failure logs its type only)."""
    try:
        return handler(*args)
    except CredentialTaskError as exc:
        return error_reply(exc.code)
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential api: failed (%s)", type(exc).__name__)
        return error_reply("FAILED")


# --- who is calling, and may they do this -------------------------------------------------------------------------

def actor_id():
    """The signed-in user; 0 (refused downstream) when there is none."""
    user_id = (auth.current_user() or {}).get("id")
    return user_id if isinstance(user_id, int) and not isinstance(user_id, bool) else 0


def require_permission(permission, project_id):
    """Fail closed: anything but a clear yes is ``FORBIDDEN``."""
    try:
        current = auth.resolve_permissions(mode=c.ADMINISTRATION_MODE, project_id=project_id)
        allowed = auth.has_access(current, [permission])
    except Exception:  # pylint: disable=W0703
        allowed = False
    if not allowed:
        raise CredentialTaskError("FORBIDDEN")


# --- request bodies ----------------------------------------------------------------------------------------------

def read_json_object():
    """The JSON object of the request, read with a size bound before it is parsed: the declared length is checked
    first, and the server is told to stop reading at the bound where it supports that."""
    if request.content_length is not None and request.content_length > MAX_BODY_BYTES:
        raise CredentialTaskError("REQUEST_TOO_LARGE")
    request.max_content_length = MAX_BODY_BYTES
    try:
        raw = request.get_data(cache=False)
    except RequestEntityTooLarge:
        raise CredentialTaskError("REQUEST_TOO_LARGE") from None
    if len(raw) > MAX_BODY_BYTES:
        raise CredentialTaskError("REQUEST_TOO_LARGE")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise CredentialTaskError("INVALID_REQUEST") from None
    if not isinstance(data, dict):
        raise CredentialTaskError("INVALID_REQUEST")
    return data


def _uuid_text(value):
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise ValueError("not a uuid") from None


def _reference_text(value):
    value = value.strip()
    if not value or len(value) > MAX_REF_LENGTH:
        raise ValueError("bad reference")
    return value


class _Body(BaseModel):
    class Config:
        extra = Extra.forbid


class _Approval(_Body):
    """An action; ``approve`` carries the approval and nothing else does."""
    action: StrictStr
    approval_ref: Optional[StrictStr] = None
    policy_revision: Optional[StrictStr] = None
    allowed_actions: ClassVar[tuple] = ()

    @validator("action")
    def _known_action(cls, value):  # pylint: disable=E0213
        if value not in cls.allowed_actions:
            raise ValueError("unknown action")
        return value

    @validator("approval_ref", "policy_revision")
    def _clean(cls, value):  # pylint: disable=E0213
        return None if value is None else _reference_text(value)

    @root_validator
    def _approval_only_for_approve(cls, values):  # pylint: disable=E0213
        has = [values.get("approval_ref") is not None, values.get("policy_revision") is not None]
        if values.get("action") == "approve":
            if not all(has):
                raise ValueError("approval needs both references")
        elif any(has):
            raise ValueError("only approve takes an approval")
        return values


class ReferenceCreate(_Body):
    configuration_uuid: StrictStr
    store_kind: StrictStr
    ownership_class: StrictStr

    _uuid = validator("configuration_uuid", allow_reuse=True)(_uuid_text)

    @validator("store_kind")
    def _store_kind(cls, value):  # pylint: disable=E0213
        if value not in ONBOARD_STORE_KINDS:
            raise ValueError("unsupported store kind")
        return value

    @validator("ownership_class")
    def _ownership_class(cls, value):  # pylint: disable=E0213
        if value not in ONBOARD_OWNERSHIP_CLASSES:
            raise ValueError("unsupported ownership class")
        return value


class ReferenceAction(_Approval):
    allowed_actions: ClassVar[tuple] = tuple(name for name in REFERENCE_ACTIONS if name != "create")


class GrantCreate(_Body):
    agent_binding_ref: StrictStr
    toolkit_id: StrictInt
    credential_ref: StrictStr
    subject_user_id: StrictInt
    valid_until: Optional[StrictStr] = None

    _uuids = validator("agent_binding_ref", "credential_ref", allow_reuse=True)(_uuid_text)

    @validator("toolkit_id", "subject_user_id")
    def _positive(cls, value):  # pylint: disable=E0213
        if value <= 0:
            raise ValueError("must be positive")
        return value

    @validator("valid_until")
    def _future(cls, value):  # pylint: disable=E0213
        if value is not None and parse_valid_until(value)[1]:
            raise ValueError("needs an offset and must be in the future")
        return value


class GrantAction(_Approval):
    allowed_actions: ClassVar[tuple] = tuple(GRANT_ACTION_PERMISSION)


def parse_body(model, data):
    """The validated model, or ``INVALID_REQUEST`` (the reply never says which value was wrong)."""
    try:
        return model.parse_obj(data)
    except ValidationError:
        raise CredentialTaskError("INVALID_REQUEST") from None


# --- query parameters --------------------------------------------------------------------------------------------

def _int_arg(args, name):
    value = args.get(name)
    if value is None or value == "":
        return None
    try:
        number = int(value)
    except ValueError:
        raise CredentialTaskError("INVALID_REQUEST") from None
    if number <= 0:
        raise CredentialTaskError("INVALID_REQUEST")
    return number


def _choice_arg(args, name, choices):
    value = args.get(name)
    if value is None or value == "":
        return None
    if value not in choices:
        raise CredentialTaskError("INVALID_REQUEST")
    return value


def _uuid_arg(args, name):
    value = args.get(name)
    if value is None or value == "":
        return None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise CredentialTaskError("INVALID_REQUEST") from None


def parse_page(args, sorts):
    """``Page``: limit (default 20, at most 100), offset, search (at most 128 characters), a whitelisted ``sort_by``
    (anything else sorts by ``updated_at``) and ``sort_order``."""
    try:
        limit = int(args.get("limit", DEFAULT_LIMIT))
    except ValueError:
        limit = DEFAULT_LIMIT
    try:
        offset = int(args.get("offset", 0))
    except ValueError:
        offset = 0
    search = (args.get("search") or "").strip() or None
    if search is not None and len(search) > MAX_SEARCH:
        raise CredentialTaskError("INVALID_REQUEST")
    sort_by = args.get("sort_by")
    order = args.get("sort_order")
    return queries.Page(
        limit=min(max(limit, 1), MAX_LIMIT), offset=max(offset, 0), search=search,
        sort_by=sort_by if sort_by in sorts else "updated_at", sort_order=order if order in SORT_ORDERS else "desc")


def list_parameters(sorts, *filters):
    """OpenAPI query parameters of a list endpoint: paging, sorting and the filters given as ``(name, type, enum)``."""
    parameters = [
        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": DEFAULT_LIMIT, "maximum": MAX_LIMIT}},
        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
        {"name": "search", "in": "query", "schema": {"type": "string", "maxLength": MAX_SEARCH}},
        {"name": "sort_by", "in": "query", "schema": {"type": "string", "enum": list(sorts), "default": "updated_at"}},
        {"name": "sort_order", "in": "query",
         "schema": {"type": "string", "enum": list(SORT_ORDERS), "default": "desc"}},
    ]
    for name, kind, choices in filters:
        schema = {"type": kind, **({"enum": list(choices)} if choices else {})}
        parameters.append({"name": name, "in": "query", "schema": schema})
    return parameters


def reference_filters(args):
    return {"state": _choice_arg(args, "state", REFERENCE_STATES),
            "ownership_class": _choice_arg(args, "ownership_class", OWNERSHIP_CLASSES),
            "store_kind": _choice_arg(args, "store_kind", STORE_KINDS),
            "owner_user_id": _int_arg(args, "owner_user_id")}


def grant_filters(args):
    return {"state": _choice_arg(args, "state", GRANT_STATES),
            "agent_binding_ref": _uuid_arg(args, "agent_binding_ref"),
            "credential_ref": _uuid_arg(args, "credential_ref"),
            "toolkit_id": _int_arg(args, "toolkit_id"),
            "subject_user_id": _int_arg(args, "subject_user_id")}


# --- handler bodies ----------------------------------------------------------------------------------------------

def list_references(project_id):
    args = request.args
    return queries.list_references(project_id, parse_page(args, queries.REFERENCE_SORTS), reference_filters(args)), 200


def get_reference(project_id, ref_id):
    return queries.reference_detail(project_id, ref_id), 200


def create_reference(project_id):
    body = parse_body(ReferenceCreate, read_json_object())
    values = {"project_id": project_id, "action": "create", "configuration_uuid": body.configuration_uuid,
              "store_kind": body.store_kind, "ownership_class": body.ownership_class, "dry_run": False}
    return result_reply(run_reference_action(values, actor_id()), created=True)


def reference_action(project_id, ref_id):
    body = parse_body(ReferenceAction, read_json_object())
    require_permission(REFERENCE_ACTION_PERMISSION[body.action], project_id)
    values = {"project_id": project_id, "action": body.action, "ref": str(ref_id), "dry_run": False}
    if body.action == "approve":
        values.update(approval_ref=body.approval_ref, policy_revision=body.policy_revision)
    return result_reply(run_reference_action(values, actor_id()))


def list_grants(project_id):
    args = request.args
    return queries.list_grants(project_id, parse_page(args, queries.GRANT_SORTS), grant_filters(args)), 200


def create_grant(project_id):
    body = parse_body(GrantCreate, read_json_object())
    values = {"project_id": project_id, "action": "create", "binding_ref": body.agent_binding_ref,
              "toolkit_id": body.toolkit_id, "ref": body.credential_ref,
              "subject_ref": queries.subject_ref_of_user(body.subject_user_id), "dry_run": False}
    if body.valid_until is not None:
        values["valid_until"] = parse_valid_until(body.valid_until)[0]
    return result_reply(run_grant_action(values, actor_id()), created=True)


def grant_action(project_id, grant_id):
    body = parse_body(GrantAction, read_json_object())
    require_permission(GRANT_ACTION_PERMISSION[body.action], project_id)
    values = {"project_id": project_id, "action": body.action, "dry_run": False,
              **grant_key_by_id(project_id, grant_id)}
    if body.action == "approve":
        values.update(approval_ref=body.approval_ref, policy_revision=body.policy_revision)
    return result_reply(run_grant_action(values, actor_id()))
