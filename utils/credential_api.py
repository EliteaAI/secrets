"""REST skin over the credential lifecycle (#7119, C-1009): request validation, per-action permissions and the
mapping of lifecycle results to HTTP replies.

The state machines are not here. Every change goes through ``run_reference_action`` / ``run_grant_action``, the
same functions the admin tasks end in, so a REST call writes the same rows and the same audit event as the task.
Request bodies are strict: unknown fields, wrong types and a raw ``subject_ref`` are refused (400) before anything
runs, and no reply contains a value from the request, a store locator or secret material.

Personal references (#7119, PR 6): ``owner_user_id`` on create (the owner is resolved on the server), ``check_connection``
on probe, and the write-only value endpoint (``put_material``). The value is parsed once into ``SecretStr``; no reply, log
line or error carries it.
"""
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Dict, Optional

from flask import request
from pydantic.v1 import (
    BaseModel, Extra, SecretStr, StrictBool, StrictInt, StrictStr, ValidationError, root_validator, validator,
)
from pylon.core.tools import log
from tools import auth, config as c
from werkzeug.exceptions import RequestEntityTooLarge

from . import credential_queries as queries
from .credential_errors import MESSAGES, CredentialTaskError
from .credential_grants import grant_key_by_id, parse_valid_until, run_grant_action
from .credential_material import (
    MAX_BODY_BYTES as MAX_MATERIAL_BODY_BYTES, MAX_FIELD_NAME_CHARS, MAX_FIELD_VALUE_BYTES, MAX_FIELDS, write_material,
)
from .credential_onboarding import (
    ACTIONS as REFERENCE_ACTIONS, ONBOARD_OWNERSHIP_CLASSES, ONBOARD_STORE_KINDS, run_reference_action,
)
from ..models.credential_governance import GRANT_STATES, OWNERSHIP_CLASSES, REFERENCE_STATES, STORE_KINDS

VIEW, MANAGE, PROBE, APPROVE = "credentials.view", "credentials.manage", "credentials.probe", "credentials.approve"
# ``system`` is named everywhere: the role model defaults it to true, and these permissions are for operators only
_OPERATORS = {"system": False, "super_admin": True, "admin": True, "viewer": False, "editor": False}
# Read access exists in administration mode only; the project (default) mode has no handler in slice 1
VIEW_ROLES = {
    "administration": dict(_OPERATORS),
    "default": {"system": False, "super_admin": False, "admin": False, "viewer": False, "editor": False},
}
# What the permission registry (module.py) and the handlers recommend for manage, probe and approve
OPERATE_ROLES = {
    "administration": dict(_OPERATORS),
    "default": {"system": False, "admin": True, "viewer": False, "editor": False},
}
REFERENCE_ACTION_PERMISSION = {
    "import": MANAGE, "activate": MANAGE, "suspend": MANAGE, "resume": MANAGE, "retire": MANAGE,
    "probe": PROBE, "approve": APPROVE,
}
GRANT_ACTION_PERMISSION = {"approve": APPROVE, "suspend": MANAGE, "resume": MANAGE, "revoke": MANAGE}

MAX_BODY_BYTES = 8192
DEFAULT_LIMIT, MAX_LIMIT, MAX_SEARCH = 20, 100, 128
MAX_OFFSET = 10_000_000
MAX_INT32 = 2**31 - 1  # ids and limits are compared with 32-bit columns; a larger value would overflow in the database
MAX_GRANT_VALIDITY_DAYS = 365
REFERENCE_TEXT = re.compile(r"[A-Za-z0-9._:/@-]{1,128}")  # approval_ref and policy_revision, as in the mandate task
SORT_ORDERS = ("asc", "desc")

STATUS = {
    400: ("INVALID_REQUEST", "APPROVAL_REQUIRED", "CONFIGURATION_NOT_ELIGIBLE", "UNSUPPORTED_STORE_KIND",
          "UNSUPPORTED_OWNERSHIP_CLASS", "TOOLKIT_NOT_IN_BINDING", "MANDATE_BINDING_MISMATCH", "OWNER_NOT_MEMBER"),
    403: ("FORBIDDEN", "SELF_APPROVAL", "ACTOR_REQUIRED", "STORE_DENIED", "DENIED_RBAC"),
    404: ("NOT_FOUND", "REFERENCE_NOT_FOUND", "GRANT_NOT_FOUND", "CONFIGURATION_NOT_FOUND", "BINDING_NOT_FOUND",
          "MANDATE_NOT_FOUND", "SUBJECT_NOT_FOUND"),
    409: ("INVALID_STATE", "INVALID_TRANSITION", "CONCURRENT_CHANGE", "REFERENCE_EXISTS", "GRANT_EXISTS",
          "IMPORT_IN_FLIGHT", "CONFIGURATION_CHANGED", "MATERIAL_MISMATCH", "NO_SECRET_FIELDS", "SECRET_UNRESOLVED",
          "MANDATE_INACTIVE", "SUBJECT_UNLINKED", "STORE_VERSION_CONFLICT", "MIGRATION_REQUIRED", "OWNER_UNLINKED",
          "PERSONAL_ONLY", "USE_PERSONAL_VALUE", "SUBJECT_NOT_OWNER", "CHECK_CONNECTION_FAILED"),
    413: ("REQUEST_TOO_LARGE",),
    503: ("DEPENDENCY_UNAVAILABLE", "AUDIT_UNAVAILABLE", "CHECK_CONNECTION_REFUSED"),
}
_STATUS_OF = {code: status for status, codes in STATUS.items() for code in codes}


def status_of(code):
    """The HTTP status of a refusal code: a store code is 503 unless listed (denied, version conflict), anything
    else unlisted is 500."""
    if code in _STATUS_OF:
        return _STATUS_OF[code]
    return 503 if isinstance(code, str) and code.startswith("STORE_") else 500


# --- replies -----------------------------------------------------------------------------------------------------

def error_reply(code, message=None, status=None):
    """``({error, code}, status)`` with a fixed message that holds no id or request value."""
    return {"error": message or MESSAGES.get(code) or MESSAGES["FAILED"], "code": code}, status or status_of(code)


class UnsupportedMediaType(CredentialTaskError):
    """A request that is not JSON: ``INVALID_REQUEST`` with status 415."""

    def __init__(self):
        super().__init__("INVALID_REQUEST")
        self.status = 415


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


def require_project(module, project_id):
    """The project must exist (one lookup); an id no 32-bit column can hold does not."""
    if project_id > MAX_INT32:
        raise CredentialTaskError("NOT_FOUND")
    try:
        project = module.context.rpc_manager.call.project_get_by_id(project_id=project_id)
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    if not project:
        raise CredentialTaskError("NOT_FOUND")


def respond(module, handler, project_id, *args):
    """Run a handler body for an existing project; refusals and unexpected failures become replies (a failure
    logs its type only)."""
    try:
        require_project(module, project_id)
        return handler(project_id, *args)
    except CredentialTaskError as exc:
        return error_reply(exc.code, status=getattr(exc, "status", None))
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

def read_json_object(max_bytes=MAX_BODY_BYTES):
    """The JSON object of the request. Only a JSON content type is read (a form or text/plain post is refused with
    415), and the size is bound before parsing: the declared length is checked first, and the server is told to stop
    reading at the bound (a body without a length is read up to it)."""
    if not request.is_json:
        raise UnsupportedMediaType()
    if request.content_length is not None and request.content_length > max_bytes:
        raise CredentialTaskError("REQUEST_TOO_LARGE")
    request.max_content_length = max_bytes
    try:
        raw = request.get_data(cache=False)
    except RequestEntityTooLarge:
        raise CredentialTaskError("REQUEST_TOO_LARGE") from None
    if len(raw) > max_bytes:
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
    if not REFERENCE_TEXT.fullmatch(value):
        raise ValueError("bad reference")
    return value


def _bounded_id(value):
    if not 0 < value <= MAX_INT32:
        raise ValueError("bad id")
    return value


def _valid_until(value):
    """The aware UTC time for a ``valid_until`` text: ISO-8601 with an offset, in the future, at most
    ``MAX_GRANT_VALIDITY_DAYS`` ahead, and representable after the conversion to UTC. Parsed once, here."""
    if not isinstance(value, str):
        raise ValueError("not a time")
    try:
        until, problem = parse_valid_until(value)
        if problem:
            raise ValueError("bad time")
        until = until.astimezone(timezone.utc)
        if until > datetime.now(timezone.utc) + timedelta(days=MAX_GRANT_VALIDITY_DAYS):
            raise ValueError("too far ahead")
    except OverflowError:
        raise ValueError("bad time") from None
    return until


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
    owner_user_id: Optional[StrictInt] = None   # the owner of a personal reference: required for it, refused otherwise

    _uuid = validator("configuration_uuid", allow_reuse=True)(_uuid_text)

    @validator("owner_user_id")
    def _owner(cls, value):  # pylint: disable=E0213
        return None if value is None else _bounded_id(value)

    @root_validator
    def _owner_goes_with_personal(cls, values):  # pylint: disable=E0213
        if "ownership_class" in values and (values["ownership_class"] == "personal") != (values.get("owner_user_id") is not None):
            raise ValueError("an owner goes with a personal reference, and only with it")
        return values

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
    check_connection: Optional[StrictBool] = None   # probe of a personal reference: also test it against its provider

    @root_validator
    def _check_only_for_probe(cls, values):  # pylint: disable=E0213
        if values.get("check_connection") and values.get("action") != "probe":   # a false flag is ignored
            raise ValueError("only probe checks the connection")
        return values


def _secret_text(value):
    if not isinstance(value, str) or not 0 < len(value.encode("utf-8")) <= MAX_FIELD_VALUE_BYTES:
        raise ValueError("bad value")   # the message never holds the value
    return value


class MaterialBody(_Body):
    """The value of a personal reference: field name -> text, and the generation the caller last saw. Values are
    ``SecretStr`` from the moment they are parsed: a repr or a validation error never shows them."""
    fields: Dict[StrictStr, SecretStr]
    expected_generation: StrictInt

    @validator("fields", pre=True)
    def _bounded_fields(cls, value):  # pylint: disable=E0213
        if not isinstance(value, dict) or not 0 < len(value) <= MAX_FIELDS:
            raise ValueError("bad fields")
        for name, text in value.items():
            if not isinstance(name, str) or not 0 < len(name) <= MAX_FIELD_NAME_CHARS:
                raise ValueError("bad field name")
            _secret_text(text)
        return value

    @validator("expected_generation")
    def _generation(cls, value):  # pylint: disable=E0213
        if not 0 <= value <= MAX_INT32:
            raise ValueError("bad generation")
        return value


class GrantCreate(_Body):
    agent_binding_ref: StrictStr
    toolkit_id: StrictInt
    credential_ref: StrictStr
    subject_user_id: StrictInt
    valid_until: Optional[Any] = None

    _uuids = validator("agent_binding_ref", "credential_ref", allow_reuse=True)(_uuid_text)

    _ids = validator("toolkit_id", "subject_user_id", allow_reuse=True)(_bounded_id)

    @validator("valid_until")
    def _time(cls, value):  # pylint: disable=E0213
        return None if value is None else _valid_until(value)


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
    if not 0 < number <= MAX_INT32:
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


def _page_number(args, name, default, bound):
    """A paging number: not a number gives the default, a negative one 0, one above ``bound`` is refused."""
    try:
        number = int(args.get(name, default))
    except ValueError:
        return default
    if number > bound:
        raise CredentialTaskError("INVALID_REQUEST")
    return max(number, 0)


def parse_page(args, sorts):
    """``Page``: limit (default 20, at most 100), offset, search (at most 128 characters), a whitelisted ``sort_by``
    (anything else sorts by ``updated_at``) and ``sort_order``."""
    limit, offset = _page_number(args, "limit", DEFAULT_LIMIT, MAX_INT32), _page_number(args, "offset", 0, MAX_OFFSET)
    search = (args.get("search") or "").strip() or None
    if search is not None and len(search) > MAX_SEARCH:
        raise CredentialTaskError("INVALID_REQUEST")
    sort_by = args.get("sort_by")
    order = args.get("sort_order")
    return queries.Page(
        limit=min(max(limit, 1), MAX_LIMIT), offset=offset, search=search,
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
    if body.owner_user_id is not None:
        values["owner_user_id"] = body.owner_user_id
    return result_reply(run_reference_action(values, actor_id(), audit_code=True), created=True)


def reference_action(project_id, ref_id):
    body = parse_body(ReferenceAction, read_json_object())
    require_permission(REFERENCE_ACTION_PERMISSION[body.action], project_id)
    values = {"project_id": project_id, "action": body.action, "ref": str(ref_id), "dry_run": False}
    if body.action == "approve":
        values.update(approval_ref=body.approval_ref, policy_revision=body.policy_revision)
    if body.check_connection:
        values["check_connection"] = True
    return result_reply(run_reference_action(values, actor_id(), audit_code=True))


def put_material(project_id, ref_id):
    """Write the value of a personal reference. Write-only: the reply holds the new generation and state, never the value."""
    body = parse_body(MaterialBody, read_json_object(MAX_MATERIAL_BODY_BYTES))
    result = write_material(project_id, str(ref_id), body.fields, body.expected_generation, actor_id())
    return result_reply(result)


def list_grants(project_id):
    args = request.args
    return queries.list_grants(project_id, parse_page(args, queries.GRANT_SORTS), grant_filters(args)), 200


def create_grant(project_id):
    body = parse_body(GrantCreate, read_json_object())
    values = {"project_id": project_id, "action": "create", "binding_ref": body.agent_binding_ref,
              "toolkit_id": body.toolkit_id, "ref": body.credential_ref,
              "subject_ref": queries.subject_ref_of_user(body.subject_user_id), "dry_run": False}
    if body.valid_until is not None:
        values["valid_until"] = body.valid_until
    return result_reply(run_grant_action(values, actor_id(), audit_code=True), created=True)


def grant_action(project_id, grant_id):
    body = parse_body(GrantAction, read_json_object())
    require_permission(GRANT_ACTION_PERMISSION[body.action], project_id)
    values = {"project_id": project_id, "action": body.action, "dry_run": False,
              **grant_key_by_id(project_id, grant_id)}
    if body.action == "approve":
        values.update(approval_ref=body.approval_ref, policy_revision=body.policy_revision)
    return result_reply(run_grant_action(values, actor_id(), audit_code=True))
