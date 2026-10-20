"""Read side of the credential REST API (#7119, C-1009): lists and details of references and use grants.

Rows are built from an explicit allow-list of columns, so ``store_locator``, the staged generation and the
custodian record never reach a response. Every query carries the project of the request, so an id of another
project is simply not found. Names of users, applications, versions and toolkits are joined for the page
only (a bounded number of lookups, never one per row); a lookup that fails leaves the name empty instead of
failing the list.
"""
import uuid
from typing import NamedTuple, Optional

from pylon.core.tools import log
from sqlalchemy import Column, Integer, MetaData, String, Table, func, or_, select
from tools import auth, config as c, this

from ..models.credential_governance import CredentialReference, CredentialStoreLedger, CredentialUseGrant
from .credential_errors import CredentialTaskError
from .credential_grants import _BINDING, SUBJECT_PATTERN
from .credential_schema import project_tx

MAX_FACT_UUIDS = 64  # what configuration_credential_facts takes in one call
IN_FLIGHT = ("intent", "written")
LIVE_GRANT_STATES = ("pending_approval", "active", "suspended")

# Read-only views of tables of other plugins (names only), as in credential_grants
_VIEWS = MetaData()
_APPLICATION = Table(
    "applications", _VIEWS, Column("id", Integer, primary_key=True), Column("name", String),
    schema=c.POSTGRES_TENANT_SCHEMA)
_VERSION = Table(
    "application_versions", _VIEWS, Column("id", Integer, primary_key=True), Column("name", String),
    schema=c.POSTGRES_TENANT_SCHEMA)
_TOOL = Table(
    "elitea_tools", _VIEWS, Column("id", Integer, primary_key=True), Column("type", String), Column("name", String),
    schema=c.POSTGRES_TENANT_SCHEMA)

_REF = CredentialReference
_REFERENCE_COLUMNS = (
    _REF.id, _REF.configuration_uuid, _REF.configuration_generation, _REF.provider, _REF.ownership_class,
    _REF.custodian_ref, _REF.store_kind, _REF.state, _REF.generation, _REF.validated_generation, _REF.approval_ref,
    _REF.policy_revision, _REF.created_by, _REF.approved_by, _REF.expires_at, _REF.created_at, _REF.updated_at,
)
_GRANT = CredentialUseGrant
_GRANT_COLUMNS = (
    _GRANT.id, _GRANT.agent_binding_ref, _GRANT.toolkit_instance_id, _GRANT.credential_ref, _GRANT.subject_ref,
    _GRANT.state, _GRANT.valid_from, _GRANT.valid_until, _GRANT.approval_ref, _GRANT.created_by, _GRANT.approved_by,
    _GRANT.revocation_epoch,
)
REFERENCE_SORTS = {"updated_at": _REF.updated_at, "created_at": _REF.created_at, "state": _REF.state,
                   "provider": _REF.provider}
GRANT_SORTS = {"updated_at": _GRANT.updated_at, "created_at": _GRANT.created_at, "state": _GRANT.state}


class Page(NamedTuple):
    limit: int
    offset: int
    search: Optional[str]
    sort_by: str
    sort_order: str


def _like(text):
    """A LIKE pattern that matches ``text`` literally anywhere (``%``, ``_`` and ``\\`` are escaped)."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _order(columns, page, model):
    column = columns.get(page.sort_by, columns["updated_at"])
    return (column.desc() if page.sort_order == "desc" else column.asc()), model.id


def _iso(value):
    return value.isoformat() if value is not None else None


# --- users, subjects, configuration facts ------------------------------------------------------------------------

def subject_ref_of_user(user_id):
    """``idp:<tenant>:<object>`` of a platform user, resolved here from the identity service. A raw subject is
    never taken from a caller."""
    try:
        user = auth.get_user(user_id=user_id)
    except RuntimeError as exc:  # the identity service answers "No such user found" as a RuntimeError
        raise CredentialTaskError(
            "SUBJECT_NOT_FOUND" if str(exc).startswith("No such user found") else "DEPENDENCY_UNAVAILABLE") from None
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    user = user if isinstance(user, dict) else {}
    tid, oid = user.get("idp_tid"), user.get("idp_oid")
    subject = f"idp:{tid}:{oid}" if tid and oid else None
    if subject is None or not SUBJECT_PATTERN.match(subject):
        raise CredentialTaskError("SUBJECT_UNLINKED")
    return subject


def _users(user_ids, with_project=None):
    """``({id: {id, email}}, {subject_ref: {id, email}})`` for the given users (and the members of a project,
    to name subjects). One lookup; an unavailable identity service gives empty maps."""
    wanted = {i for i in user_ids if isinstance(i, int)}
    if with_project is not None:
        try:
            wanted |= {int(row["user_id"]) for row in auth.list_project_user_roles(with_project) or []}
        except Exception as exc:  # pylint: disable=W0703
            log.error("credential api: project members unavailable (%s)", type(exc).__name__)
    if not wanted:
        return {}, {}
    try:
        found = auth.list_users(user_ids=sorted(wanted)) or []
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential api: users unavailable (%s)", type(exc).__name__)
        return {}, {}
    by_id = {u["id"]: {"id": u["id"], "email": u.get("email")} for u in found}
    by_subject = {f"idp:{u.get('idp_tid')}:{u.get('idp_oid')}": by_id[u["id"]]
                  for u in found if u.get("idp_tid") and u.get("idp_oid")}
    return by_id, by_subject


def _user(by_id, user_id):
    return None if user_id is None else by_id.get(user_id, {"id": user_id, "email": None})


def _facts(project_id, configuration_uuids):
    """``{uuid: {title?, generation, ...}}`` of the configurations; empty where the service does not answer."""
    wanted = sorted({str(item) for item in configuration_uuids})
    found = {}
    try:
        service = this.for_module("configurations").module
        for start in range(0, len(wanted), MAX_FACT_UUIDS):
            found.update(service.configuration_credential_facts(project_id, wanted[start:start + MAX_FACT_UUIDS]) or {})
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential api: configuration facts unavailable (%s)", type(exc).__name__)
    return found


# --- references --------------------------------------------------------------------------------------------------

def _owner_id(custodian_ref):
    owner = custodian_ref.get("user_id") if isinstance(custodian_ref, dict) else None
    return owner if isinstance(owner, int) and not isinstance(owner, bool) else None


def _present_references(project_id, rows):
    facts = _facts(project_id, [row.configuration_uuid for row in rows])
    users, _ = _users({i for row in rows for i in (row.created_by, row.approved_by, _owner_id(row.custodian_ref))})
    present = []
    for row in rows:
        fact = facts.get(str(row.configuration_uuid))
        present.append({
            "id": str(row.id),
            "configuration": {"uuid": str(row.configuration_uuid), "title": (fact or {}).get("title")},
            "provider": row.provider,
            "ownership_class": row.ownership_class,
            "owner": _user(users, _owner_id(row.custodian_ref)),
            "store_kind": row.store_kind,
            "state": row.state,
            "generation": row.generation,
            "validated": row.validated_generation is not None and row.validated_generation == row.generation,
            "configuration_changed": (
                None if fact is None else
                row.configuration_generation is not None and fact.get("generation") != row.configuration_generation),
            "approval_ref": row.approval_ref,
            "policy_revision": row.policy_revision,
            "created_by": _user(users, row.created_by),
            "approved_by": _user(users, row.approved_by),
            "expires_at": _iso(row.expires_at),
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        })
    return present


def list_references(project_id, page, filters):
    """``{total, rows}`` of the project's references. ``filters``: state, ownership_class, store_kind, owner_user_id."""
    conditions = [_REF.project_id == project_id]
    for name in ("state", "ownership_class", "store_kind"):
        if filters.get(name):
            conditions.append(getattr(_REF, name) == filters[name])
    if filters.get("owner_user_id"):
        conditions.append(_REF.custodian_ref["user_id"].as_integer() == filters["owner_user_id"])
    if page.search:
        conditions.append(_REF.provider.ilike(_like(page.search), escape="\\"))
    with project_tx(project_id) as session:
        total = session.execute(select(func.count()).select_from(_REF).where(*conditions)).scalar_one()
        rows = session.execute(
            select(*_REFERENCE_COLUMNS).where(*conditions).order_by(*_order(REFERENCE_SORTS, page, _REF))
            .limit(page.limit).offset(page.offset)).all()
    return {"total": total, "rows": _present_references(project_id, rows)}


def reference_detail(project_id, ref_id):
    """One reference of the project with the number of live grants on it and whether a store write is in flight."""
    ref_uuid = uuid.UUID(str(ref_id))
    with project_tx(project_id) as session:
        row = session.execute(
            select(*_REFERENCE_COLUMNS).where(_REF.id == ref_uuid, _REF.project_id == project_id)).first()
        if row is None:
            raise CredentialTaskError("REFERENCE_NOT_FOUND")
        grants = session.execute(select(func.count()).select_from(_GRANT).where(
            _GRANT.credential_ref == ref_uuid, _GRANT.project_id == project_id,
            _GRANT.state.in_(LIVE_GRANT_STATES))).scalar_one()
        in_flight = session.execute(select(CredentialStoreLedger.id).where(
            CredentialStoreLedger.credential_ref == ref_uuid, CredentialStoreLedger.state.in_(IN_FLIGHT)).limit(1)
        ).first() is not None
    return {**_present_references(project_id, [row])[0], "grants_count": grants, "ledger_in_flight": in_flight}


# --- grants ------------------------------------------------------------------------------------------------------

def _lookup(session, query):
    return {row[0]: row for row in session.execute(query).all()}


def _name(rows, key):
    return rows[key].name if key in rows else None


def _grant_lookups(project_id, rows):
    """The bindings, applications, versions, toolkits and references a page of grants points at (a fixed number
    of queries, whatever the page size)."""
    binding_ids = {row.agent_binding_ref for row in rows}
    credential_ids = {row.credential_ref for row in rows}
    toolkit_ids = {int(row.toolkit_instance_id) for row in rows if row.toolkit_instance_id.isdecimal()}
    with project_tx(project_id) as session:
        bindings = _lookup(session, select(_BINDING.c.id, _BINDING.c.application_id, _BINDING.c.version_id).where(
            _BINDING.c.id.in_(binding_ids), _BINDING.c.project_id == project_id)) if binding_ids else {}
        application_ids = {b.application_id for b in bindings.values()}
        version_ids = {b.version_id for b in bindings.values()}
        applications = _lookup(session, select(_APPLICATION.c.id, _APPLICATION.c.name).where(
            _APPLICATION.c.id.in_(application_ids))) if bindings else {}
        versions = _lookup(session, select(_VERSION.c.id, _VERSION.c.name).where(
            _VERSION.c.id.in_(version_ids))) if bindings else {}
        tools = _lookup(session, select(_TOOL.c.id, _TOOL.c.type, _TOOL.c.name).where(
            _TOOL.c.id.in_(toolkit_ids))) if toolkit_ids else {}
        references = _lookup(session, select(
            _REF.id, _REF.provider, _REF.ownership_class, _REF.configuration_uuid,
        ).where(_REF.id.in_(credential_ids), _REF.project_id == project_id)) if credential_ids else {}
    return bindings, applications, versions, tools, references


def _present_grants(project_id, rows):
    bindings, applications, versions, tools, references = _grant_lookups(project_id, rows)
    facts = _facts(project_id, [ref.configuration_uuid for ref in references.values()])
    has_users = any(not row.subject_ref.startswith("mandate:") for row in rows)
    users, subjects = _users({i for row in rows for i in (row.created_by, row.approved_by)},
                             with_project=project_id if has_users else None)
    present = []
    for row in rows:
        binding = bindings.get(row.agent_binding_ref)
        tool = tools.get(int(row.toolkit_instance_id)) if row.toolkit_instance_id.isdecimal() else None
        ref = references.get(row.credential_ref)
        title = (facts.get(str(ref.configuration_uuid)) or {}).get("title") if ref else None
        present.append({
            "id": str(row.id),
            "binding": {
                "id": str(row.agent_binding_ref),
                "application_name": _name(applications, binding.application_id) if binding else None,
                "version_name": _name(versions, binding.version_id) if binding else None,
            },
            "toolkit": {"id": row.toolkit_instance_id, "name": tool.name if tool else None,
                        "type": tool.type if tool else None},
            "credential": {"id": str(row.credential_ref), "provider": ref.provider if ref else None,
                           "configuration_title": title, "ownership_class": ref.ownership_class if ref else None},
            "subject": {"ref": row.subject_ref, "user": subjects.get(row.subject_ref)},
            "state": row.state,
            "valid_from": _iso(row.valid_from),
            "valid_until": _iso(row.valid_until),
            "approval_ref": row.approval_ref,
            "created_by": _user(users, row.created_by),
            "approved_by": _user(users, row.approved_by),
            "revocation_epoch": row.revocation_epoch,
        })
    return present


def list_grants(project_id, page, filters):
    """``{total, rows}`` of the project's grants. ``filters``: state, agent_binding_ref, credential_ref, toolkit_id,
    subject_user_id (resolved to its subject here; a user that cannot have a subject has no grants)."""
    conditions = [_GRANT.project_id == project_id]
    if filters.get("state"):
        conditions.append(_GRANT.state == filters["state"])
    if filters.get("agent_binding_ref"):
        conditions.append(_GRANT.agent_binding_ref == uuid.UUID(filters["agent_binding_ref"]))
    if filters.get("credential_ref"):
        conditions.append(_GRANT.credential_ref == uuid.UUID(filters["credential_ref"]))
    if filters.get("toolkit_id"):
        conditions.append(_GRANT.toolkit_instance_id == str(filters["toolkit_id"]))
    if filters.get("subject_user_id"):
        try:
            conditions.append(_GRANT.subject_ref == subject_ref_of_user(filters["subject_user_id"]))
        except CredentialTaskError as exc:
            if exc.code not in ("SUBJECT_NOT_FOUND", "SUBJECT_UNLINKED"):
                raise
            return {"total": 0, "rows": []}
    if page.search:
        pattern = _like(page.search)
        conditions.append(or_(_GRANT.subject_ref.ilike(pattern, escape="\\"),
                              _GRANT.approval_ref.ilike(pattern, escape="\\")))
    with project_tx(project_id) as session:
        total = session.execute(select(func.count()).select_from(_GRANT).where(*conditions)).scalar_one()
        rows = session.execute(
            select(*_GRANT_COLUMNS).where(*conditions).order_by(*_order(GRANT_SORTS, page, _GRANT))
            .limit(page.limit).offset(page.offset)).all()
    return {"total": total, "rows": _present_grants(project_id, rows)}
