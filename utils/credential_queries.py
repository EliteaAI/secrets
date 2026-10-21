"""Read side of the credential REST API (#7119, C-1009): lists and details of references and use grants.

Rows are built from an explicit allow-list of columns, so ``store_locator``, the staged generation and the
custodian record never reach a response. Every query carries the project of the request, so an id of another
project is simply not found. Names of users, applications, versions and toolkits are joined for the page
only (a bounded number of lookups, never one per row); a lookup that fails leaves the name empty instead of
failing the list.

Configuration titles and generations come from a read-only join with the project's ``configuration`` table (the same
schema), so a page needs no call to the configurations plugin and a title search is one statement over all references
(perf review 2026-10-21, S6). A grant names its subject from its own ``subject_user_id`` with one ``auth.list_users`` call
for the page (S5); only a grant that has none yet (made before the column) falls back to the project's members, and
the user it resolves is stored on the grant, so the fallback happens once per grant.
"""
import uuid
from typing import NamedTuple, Optional

from pylon.core.tools import log
from sqlalchemy import Column, Integer, MetaData, String, Table, Uuid, bindparam, func, or_, select, update
from tools import auth, config as c

from ..models.credential_governance import CredentialReference, CredentialStoreLedger, CredentialUseGrant
from .credential_errors import CredentialTaskError
from .credential_grants import _BINDING, ANY_TARGET, SUBJECT_PATTERN
from .credential_schema import project_tx

MAX_USER_IDS = 100  # users asked of the identity service in one call
MAX_MEMBER_LOOKUP = 1000  # a project with more members does not get its subjects named
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

_CONFIGURATION = Table(  # the configurations plugin's table: the columns a reference list shows, nothing else
    "configuration", _VIEWS, Column("uuid", Uuid, primary_key=True), Column("elitea_title", String),
    Column("generation", Integer), schema=c.POSTGRES_TENANT_SCHEMA)

_REF = CredentialReference
_WITH_CONFIGURATION = _REF.__table__.outerjoin(_CONFIGURATION, _CONFIGURATION.c.uuid == _REF.configuration_uuid)
_CONFIGURATION_COLUMNS = (
    _CONFIGURATION.c.uuid.label("configuration_found"), _CONFIGURATION.c.elitea_title.label("configuration_title"),
    _CONFIGURATION.c.generation.label("configuration_current_generation"))
_REFERENCE_COLUMNS = (
    _REF.id, _REF.configuration_uuid, _REF.configuration_generation, _REF.provider, _REF.ownership_class,
    _REF.custodian_ref, _REF.store_kind, _REF.state, _REF.generation, _REF.validated_generation, _REF.approval_ref,
    _REF.policy_revision, _REF.created_by, _REF.approved_by, _REF.written_by, _REF.expires_at, _REF.created_at, _REF.updated_at,
)
_GRANT = CredentialUseGrant
_GRANT_COLUMNS = (
    _GRANT.id, _GRANT.agent_binding_ref, _GRANT.toolkit_instance_id, _GRANT.credential_ref, _GRANT.subject_ref,
    _GRANT.subject_user_id, _GRANT.state, _GRANT.valid_from, _GRANT.valid_until, _GRANT.approval_ref, _GRANT.created_by, _GRANT.approved_by,
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


# --- users and subjects ------------------------------------------------------------------------

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


def _list_users(user_ids):
    """The users with these ids, asked in chunks of at most ``MAX_USER_IDS``; none when there are no ids, and
    none (logged) when the identity service does not answer."""
    wanted = sorted({i for i in user_ids if isinstance(i, int) and not isinstance(i, bool)})
    found = []
    try:
        for start in range(0, len(wanted), MAX_USER_IDS):
            found.extend(auth.list_users(user_ids=wanted[start:start + MAX_USER_IDS]) or [])
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential api: users unavailable (%s)", type(exc).__name__)
        return []
    return found


def _subject_of(user):
    return f"idp:{user.get('idp_tid')}:{user.get('idp_oid')}" if user.get("idp_tid") and user.get("idp_oid") else None


def _users(user_ids, subjects_of_project=None):
    """``({id: {id, email}}, {subject_ref: {id, email}})`` for the given users. With ``subjects_of_project`` the
    members of that project are looked up too, to name the subjects of grants (the grant stores the subject, not the
    user id, and the identity service has no lookup by subject: at most ``MAX_MEMBER_LOOKUP`` members)."""
    wanted = set(user_ids)
    if subjects_of_project is not None:
        try:
            members = {int(row["user_id"]) for row in auth.list_project_user_roles(subjects_of_project) or []}
        except Exception as exc:  # pylint: disable=W0703
            log.error("credential api: project members unavailable (%s)", type(exc).__name__)
            members = set()
        if len(members) <= MAX_MEMBER_LOOKUP:
            wanted |= members
    found = _list_users(wanted)
    by_id = {u["id"]: {"id": u["id"], "email": u.get("email")} for u in found}
    return by_id, {_subject_of(u): by_id[u["id"]] for u in found if _subject_of(u)}


def _user(by_id, user_id):
    return None if user_id is None else by_id.get(user_id, {"id": user_id, "email": None})


# --- references --------------------------------------------------------------------------------------------------

def _owner_id(custodian_ref):
    owner = custodian_ref.get("user_id") if isinstance(custodian_ref, dict) else None
    return owner if isinstance(owner, int) and not isinstance(owner, bool) else None


def _present_references(rows):
    users, _ = _users({i for row in rows for i in (row.created_by, row.approved_by, row.written_by, _owner_id(row.custodian_ref))
                       if i is not None})
    present = []
    for row in rows:
        found = row.configuration_found is not None  # a configuration that was deleted has no title and no change to flag
        present.append({
            "id": str(row.id),
            "configuration": {"uuid": str(row.configuration_uuid), "title": row.configuration_title},
            "provider": row.provider,
            "ownership_class": row.ownership_class,
            "owner": _user(users, _owner_id(row.custodian_ref)),
            "store_kind": row.store_kind,
            "state": row.state,
            "generation": row.generation,
            "validated": row.validated_generation is not None and row.validated_generation == row.generation,
            "configuration_changed": (
                None if not found else
                row.configuration_generation is not None
                and row.configuration_current_generation != row.configuration_generation),
            "approval_ref": row.approval_ref,
            "policy_revision": row.policy_revision,
            "created_by": _user(users, row.created_by),
            "approved_by": _user(users, row.approved_by),
            "written_by": _user(users, row.written_by),
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
    counted = _REF
    if page.search:  # the provider, or the title of the configuration: one statement over all the references
        pattern = _like(page.search)
        conditions.append(or_(_REF.provider.ilike(pattern, escape="\\"),
                              _CONFIGURATION.c.elitea_title.ilike(pattern, escape="\\")))
        counted = _WITH_CONFIGURATION
    with project_tx(project_id) as session:
        total = session.execute(select(func.count()).select_from(counted).where(*conditions)).scalar_one()
        rows = session.execute(
            select(*_REFERENCE_COLUMNS, *_CONFIGURATION_COLUMNS).select_from(_WITH_CONFIGURATION).where(*conditions)
            .order_by(*_order(REFERENCE_SORTS, page, _REF)).limit(page.limit).offset(page.offset)).all()
    return {"total": total, "rows": _present_references(rows)}


def reference_custody(project_id, ref_id):
    """``(ownership_class, owner user id or None)`` of one reference of the project; a reference of another project is
    ``REFERENCE_NOT_FOUND`` like an unknown one."""
    with project_tx(project_id) as session:
        row = session.execute(select(_REF.ownership_class, _REF.custodian_ref).where(
            _REF.id == uuid.UUID(str(ref_id)), _REF.project_id == project_id)).first()
    if row is None:
        raise CredentialTaskError("REFERENCE_NOT_FOUND")
    return row.ownership_class, _owner_id(row.custodian_ref)


def reference_detail(project_id, ref_id):
    """One reference of the project with the number of live grants on it and whether a store write is in flight."""
    ref_uuid = uuid.UUID(str(ref_id))
    with project_tx(project_id) as session:
        row = session.execute(
            select(*_REFERENCE_COLUMNS, *_CONFIGURATION_COLUMNS).select_from(_WITH_CONFIGURATION)
            .where(_REF.id == ref_uuid, _REF.project_id == project_id)).first()
        if row is None:
            raise CredentialTaskError("REFERENCE_NOT_FOUND")
        grants = session.execute(select(func.count()).select_from(_GRANT).where(
            _GRANT.credential_ref == ref_uuid, _GRANT.project_id == project_id,
            _GRANT.state.in_(LIVE_GRANT_STATES))).scalar_one()
        in_flight = session.execute(select(CredentialStoreLedger.id).where(
            CredentialStoreLedger.credential_ref == ref_uuid, CredentialStoreLedger.state.in_(IN_FLIGHT)).limit(1)
        ).first() is not None
    return {**_present_references([row])[0], "grants_count": grants, "ledger_in_flight": in_flight}


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
            _REF.id, _REF.provider, _REF.ownership_class, _CONFIGURATION.c.elitea_title.label("configuration_title"),
        ).select_from(_WITH_CONFIGURATION).where(
            _REF.id.in_(credential_ids), _REF.project_id == project_id)) if credential_ids else {}
    return bindings, applications, versions, tools, references


def _remember_subjects(project_id, rows, subjects):
    """Store ``subject_user_id`` on the grants of this page that lack it and whose subject has just been resolved, so
    the next list needs no member lookup. One statement for the page; best effort, never fails the list."""
    wanted = {row.subject_ref: subjects[row.subject_ref]["id"] for row in rows
              if row.subject_user_id is None and row.subject_ref in subjects}
    if not wanted:
        return
    try:
        with project_tx(project_id) as session:
            grants = _GRANT.__table__   # the table, not the entity: a list of parameters would be an ORM bulk update by key
            session.execute(
                update(grants).where(
                    grants.c.project_id == project_id, grants.c.subject_ref == bindparam("b_subject"),
                    grants.c.subject_user_id.is_(None)).values(subject_user_id=bindparam("b_user")),
                [{"b_subject": subject, "b_user": user_id} for subject, user_id in wanted.items()])
            session.commit()
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential api: grant subjects not stored (%s)", type(exc).__name__)


def _present_grants(project_id, rows, known_subject=None):
    """``known_subject``: ``(subject_ref, user_id)`` when the list is for one user (no member lookup for that name)."""
    bindings, applications, versions, tools, references = _grant_lookups(project_id, rows)
    ids = {i for row in rows for i in (row.created_by, row.approved_by, row.subject_user_id) if i is not None}
    # a grant made before the column has a subject but no user id: its user is looked for among the project's members
    unknown = {row.subject_ref for row in rows if row.subject_user_id is None and not row.subject_ref.startswith("mandate:")}
    if known_subject:
        ids.add(known_subject[1])
        unknown.discard(known_subject[0])
    users, subjects = _users(ids, subjects_of_project=project_id if unknown else None)
    if known_subject and known_subject[1] in users:
        subjects.setdefault(known_subject[0], users[known_subject[1]])
    _remember_subjects(project_id, rows, subjects)
    present = []
    for row in rows:
        binding = bindings.get(row.agent_binding_ref)
        tool = tools.get(int(row.toolkit_instance_id)) if row.toolkit_instance_id.isdecimal() else None
        ref = references.get(row.credential_ref)
        title = ref.configuration_title if ref else None
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
            "subject": {"ref": row.subject_ref,
                        "user": _user(users, row.subject_user_id) if row.subject_user_id is not None
                        else subjects.get(row.subject_ref)},
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
    # grants for any other target cannot be acted on by the lifecycle functions, so they are not listed
    conditions = [_GRANT.project_id == project_id, _GRANT.target_ref == ANY_TARGET]
    known_subject = None
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
            subject = subject_ref_of_user(filters["subject_user_id"])
            known_subject = (subject, filters["subject_user_id"])
            conditions.append(_GRANT.subject_ref == subject)
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
    return {"total": total, "rows": _present_grants(project_id, rows, known_subject)}
