"""C-1009 (#7119, PR 6): personal credential references - a user's own credential, attributed to that user, whose value
goes in through a write-only endpoint.

The real services and handlers run over SQLite (see ``fixtures/governance.py``); the store, audit trail, configurations
and identity service are fakes. With ``ELITEA_TEST_PG_DSN`` set the same tests run on PostgreSQL, including the partial
indexes and their swap.
"""
import ast
import json
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from flask import Flask, g
from sqlalchemy.exc import IntegrityError

from fixtures.api_loader import load_api_module
from fixtures.governance import APPLICATION, BINDING, MANDATE, PG_DSN, TOOL, TOOL_MAPPING, VERSION, Crash
from run_tests import StubAuth, StubLog

app = Flask(__name__)
PROJECT, OTHER_PROJECT = 3, 4
CREATOR, APPROVER, OWNER, OTHER_OWNER, UNLINKED, OUTSIDER, WRITER = 10, 20, 30, 31, 40, 50, 60
SECRET = "sentinel-personal-value-0001"  # fake, test only
SECRET_2 = "sentinel-personal-value-0002"
TOOLKIT = 41
OWNER_SUBJECT, OTHER_SUBJECT = "idp:t1:o30", "idp:t1:o31"
MODULES = ("credential_references", "credential_reference", "credential_reference_action", "credential_material", "credential_grants",
           "credential_grant_action")


def user(user_id, oid):
    return {"id": user_id, "email": f"u{user_id}@x.test", "idp_tid": "t1" if oid else None, "idp_oid": oid}


class World:
    """The handlers called like the routes do, the services of the plugin and a small identity service."""

    def __init__(self, gov, monkeypatch):
        self.gov, self.monkeypatch = gov, monkeypatch
        self.mods = {name: load_api_module(name) for name in MODULES}
        self.material = gov.module("utils.credential_material")
        self.onboarding = gov.module("utils.credential_onboarding")
        self.schema = gov.module("utils.credential_schema")
        self.users = {WRITER: user(WRITER, "o60"), CREATOR: user(CREATOR, "o10"), APPROVER: user(APPROVER, "o20"), OWNER: user(OWNER, "o30"),
                      OTHER_OWNER: user(OTHER_OWNER, "o31"), UNLINKED: user(UNLINKED, None), OUTSIDER: user(OUTSIDER, "o50")}
        self.members = [CREATOR, APPROVER, OWNER, OTHER_OWNER, UNLINKED, WRITER]
        self.permissions = {"credentials.view", "credentials.manage", "credentials.probe", "credentials.approve"}
        self.identity_down = False
        self.actor = CREATOR
        self._install_auth()

    def _install_auth(self):
        def get_user(user_id=None, **_kw):
            if self.identity_down:
                raise ConnectionError("down")
            if user_id not in self.users:
                raise RuntimeError("No such user found")
            return dict(self.users[user_id])

        for name, func in dict(
                get_user=get_user, list_users=lambda user_ids=None: [dict(self.users[i]) for i in (user_ids or []) if i in self.users],
                resolve_permissions=lambda mode="administration", project_id=None, **_kw: set(self.permissions),
                list_project_user_roles=lambda project_id: [{"user_id": i, "role_id": 1} for i in self.members],
                has_access=lambda current, required: bool(set(required) & set(current))).items():
            self.monkeypatch.setattr(StubAuth, name, staticmethod(func), raising=False)

    def call(self, name, verb, *path, body=None, raw=None, actor=None, content_type=None, handler="AdminAPI", **kwargs):
        if actor is None and name == "credential_material":   # the writer of a value is its owner unless a test says otherwise
            actor = self.owner_of(path[1])
        self.monkeypatch.setattr(StubAuth, "user", {"id": self.actor if actor is None else actor} if (actor != 0) else {})
        request = {"method": verb.upper(), **kwargs}
        if raw is not None:
            request.update(data=raw, content_type=content_type or "application/json")
        elif body is not None:
            request["json"] = body
        module = types.SimpleNamespace(context=types.SimpleNamespace(rpc_manager=types.SimpleNamespace(
            call=types.SimpleNamespace(project_get_by_id=lambda project_id: {"id": project_id}))))
        with app.test_request_context(**request):
            g.auth = types.SimpleNamespace(type="user", id=CREATOR)
            mode = "administration" if handler == "AdminAPI" else "default"
            handler = getattr(self.mods[name], handler)(api=types.SimpleNamespace(module=module), mode=mode)
            return getattr(handler, verb)(*path)

    # -- references
    def create(self, owner=OWNER, config=None, project=PROJECT, actor=None, ownership_class="personal",
               store_kind="database", **extra):
        config = config or self.gov.configurations.add(project)
        body = {"configuration_uuid": config.uuid, "store_kind": store_kind, "ownership_class": ownership_class, **extra}
        if owner is not None:
            body["owner_user_id"] = owner
        reply = self.call("credential_references", "post", project, body=body, actor=actor)
        self.config = config
        return reply

    def personal(self, owner=OWNER, **kw):
        body, status = self.create(owner, **kw)
        assert status == 201, body
        return body["id"]

    def action(self, ref, action, project=PROJECT, actor=None, **fields):
        return self.call("credential_reference_action", "post", project, uuid.UUID(str(ref)),
                         body={"action": action, **fields}, actor=actor)

    def owner_of(self, ref):
        """Whoever may write this reference's value: its owner, for a personal one (an operator otherwise)."""
        try:
            custodian = self.row(ref).custodian_ref
        except (AttributeError, KeyError, ValueError):   # no such reference
            custodian = None
        return custodian["user_id"] if custodian else CREATOR

    def put(self, ref, fields=None, expected_generation=0, project=PROJECT, actor=None, **kw):
        body = {"fields": {"api_key": SECRET} if fields is None else fields, "expected_generation": expected_generation}
        return self.call("credential_material", "put", project, uuid.UUID(str(ref)), body=body, actor=actor, **kw)

    def lifecycle(self, ref, until="active"):
        """Write a value, then take the reference as far as ``until`` (validated, approved, active)."""
        assert self.put(ref)[1] == 200
        for step in ("probe", "approve", "activate")[:("validated", "approved", "active").index(until) + 1]:
            reply = (self.action(ref, "approve", actor=APPROVER, approval_ref="CHG-1", policy_revision="rev-1")
                     if step == "approve" else self.action(ref, step, actor=APPROVER if step == "activate" else None))
            assert reply[1] == 200, reply
        return ref

    def config_reads(self):
        return len(self.gov.configurations.bundle_calls)

    def row(self, ref, project=PROJECT):
        return self.gov.reference(project, uuid.UUID(str(ref)))

    def events(self, project=PROJECT):
        return self.gov.db.events(project)

    def reasons(self, project=PROJECT):
        return [event["reason_code"] for event in self.events(project)]

    def store(self, kind="database"):
        return self.gov.stores.stores[kind]

    def seed_binding(self, project=PROJECT, version_id=9):
        binding = uuid.uuid4()
        with self.gov.db.get_session(project) as session:
            session.execute(BINDING.insert().values(id=binding, project_id=project, application_id=5, version_id=version_id))
            session.execute(APPLICATION.insert().values(id=5, name="Agent"))
            session.execute(VERSION.insert().values(id=version_id, name="v1"))
            session.execute(TOOL_MAPPING.insert().values(tool_id=TOOLKIT, entity_version_id=version_id, entity_type="agent"))
            session.execute(TOOL.insert().values(id=TOOLKIT, type="jira", name="jira"))
            session.commit()
        return str(binding)

    def seed_mandate(self, binding, owner, project=PROJECT):
        mandate = uuid.uuid4()
        with self.gov.db.get_session(project) as session:
            session.execute(MANDATE.insert().values(
                id=mandate, project_id=project, agent_binding_ref=uuid.UUID(binding), owner_user_id=owner, state="active"))
            session.commit()
        return f"mandate:{mandate}"

    def legacy_indexes(self, project=PROJECT, drop_column=False):
        """The schema of a project that predates personal references: the one live-reference index (and no
        ``written_by`` column, with ``drop_column``: the model cannot be used on such a project until the step has run)."""
        self.gov.db.execute(project, "SELECT 1")  # make sure the engine and tables exist
        self.gov.db.execute(project, "DROP INDEX IF EXISTS tenant.uq_credential_reference_live_shared")
        self.gov.db.execute(project, "DROP INDEX IF EXISTS tenant.uq_credential_reference_live_personal")
        self.gov.db.execute(
            project, "CREATE UNIQUE INDEX uq_credential_reference_live_configuration "
                     "ON tenant.credential_reference (configuration_id) WHERE state <> 'retired'")
        if drop_column:
            self.gov.db.execute(project, "ALTER TABLE tenant.credential_reference DROP COLUMN written_by")

    def index_names(self, project=PROJECT):
        with self.gov.db.get_session(project) as session:
            return self.schema._index_names(session)  # pylint: disable=W0212

    def column_names(self, project=PROJECT):
        with self.gov.db.get_session(project) as session:
            return self.schema._column_names(session)  # pylint: disable=W0212


@pytest.fixture
def w(gov, monkeypatch):
    StubLog.records.clear()
    return World(gov, monkeypatch)


def everything_observable(w, *replies):
    """All the text a value could leak into: logs, replies, audit rows, ledger and reference rows."""
    gov = w.gov
    rows = [str(vars(entry)) for entry in gov.ledger(PROJECT)]
    with gov.db.get_session(PROJECT) as session:
        rows += [str({column.name: getattr(row, column.name) for column in row.__table__.columns})
                 for row in session.execute(sa.select(gov.module("models.credential_governance").CredentialReference)).scalars()]
    return "\n".join([*StubLog.records, json.dumps(w.events(), default=str), *rows, *(repr(r) for r in replies)])


# --- creating a personal reference ------------------------------------------------------------------------------------

def test_a_personal_reference_names_its_owner_and_every_event_is_attributed_to_them(w):
    body, status = w.create()
    assert status == 201 and body == {"ok": True, "action": "create", "id": body["id"], "state": "pending"}
    row = w.row(body["id"])
    assert (row.ownership_class, row.state, row.created_by) == ("personal", "pending", CREATOR)
    assert row.custodian_ref == {"user_id": OWNER, "subject_ref": OWNER_SUBJECT}
    (event,) = w.events()
    assert (event["reason_code"], event["user_ref"], event["caller_ref"]) == (
        "CREDENTIAL_REF_PENDING", OWNER_SUBJECT, f"operator:{CREATOR}")


def test_the_subject_is_resolved_on_the_server_and_never_taken_from_the_body(w):
    for extra in ({"subject_ref": OTHER_SUBJECT}, {"custodian_ref": {"user_id": 1}}):
        body, status = w.create(**extra)
        assert (status, body["code"]) == (400, "INVALID_REQUEST")
    assert w.events() == []


@pytest.mark.parametrize("owner, ownership_class, code, status", [
    (None, "personal", "INVALID_REQUEST", 400),         # a personal reference needs its owner
    (OWNER, "service", "INVALID_REQUEST", 400),         # and only a personal one has an owner
    (0, "personal", "INVALID_REQUEST", 400),
    (2 ** 31, "personal", "INVALID_REQUEST", 400),
    (OUTSIDER, "personal", "OWNER_NOT_MEMBER", 400),    # a user who exists but is not in the project
    (999, "personal", "OWNER_NOT_MEMBER", 400),         # an unknown user answers the same (no enumeration)
    (UNLINKED, "personal", "OWNER_UNLINKED", 409),      # a member with no identity-provider subject
])
def test_the_owner_must_be_a_linked_member_of_the_project(w, owner, ownership_class, code, status):
    body, got = w.create(owner, ownership_class=ownership_class)
    assert (got, body["code"]) == (status, code)
    assert w.events() == []


def test_a_bool_or_text_owner_is_refused(w):
    for owner in (True, "30", 30.5):
        body, status = w.create(owner)
        assert (status, body["code"]) == (400, "INVALID_REQUEST")


def test_an_identity_service_that_is_down_is_a_dependency_error(w):
    w.identity_down = True
    body, status = w.create()
    assert (status, body["code"]) == (503, "DEPENDENCY_UNAVAILABLE")
    assert w.events() == []


def test_a_personal_reference_stands_beside_the_shared_one_and_one_per_owner(w):
    config = w.gov.configurations.add(PROJECT)
    shared = w.create(None, config, ownership_class="service")[0]["id"]
    mine = w.personal(OWNER, config=config)
    theirs = w.personal(OTHER_OWNER, config=config)
    assert len({shared, mine, theirs}) == 3
    again, status = w.create(OWNER, config)
    assert (status, again["code"]) == (409, "REFERENCE_EXISTS")
    again, status = w.create(None, config, ownership_class="technical")   # the shared slot is taken as before
    assert (status, again["code"]) == (409, "REFERENCE_EXISTS")
    w.action(mine, "retire")
    assert w.create(OWNER, config)[1] == 201   # a retired one can be replaced


def test_the_task_takes_an_owner_too(w):
    config = w.gov.configurations.add(PROJECT)
    param = (f"project_id={PROJECT};action=create;configuration_uuid={config.uuid};store_kind=database;"
             f"ownership_class=personal;owner_user_id={OWNER}")
    dry = w.onboarding.manage_reference(param + ";dry_run", 0)
    assert dry == {"dry_run": True, "action": "create", "state": "pending", "provider": "api_cred"}
    created = w.onboarding.manage_reference(param, CREATOR)
    assert w.row(created["reference"]).custodian_ref == {"user_id": OWNER, "subject_ref": OWNER_SUBJECT}
    assert w.onboarding.manage_reference(param, CREATOR)["code"] == "REFERENCE_EXISTS"


def test_a_personal_reference_cannot_be_imported(w):
    ref = w.personal()
    body, status = w.action(ref, "import")
    assert (status, body["code"]) == (409, "USE_PERSONAL_VALUE")
    assert w.row(ref).generation == 0 and w.gov.configurations.bundle_calls == [] and w.store().calls == []


# --- the index migration ------------------------------------------------------------------------------------------------

def test_new_projects_get_the_pair_of_partial_indexes(w):
    w.create()
    assert {"uq_credential_reference_live_shared", "uq_credential_reference_live_personal"} <= w.index_names()
    assert "uq_credential_reference_live_configuration" not in w.index_names()


def test_personal_create_is_refused_until_the_index_swap_has_run(w):
    w.create(None, ownership_class="service")          # the tables exist
    w.legacy_indexes()
    assert w.index_names() >= {"uq_credential_reference_live_configuration"}
    body, status = w.create()
    assert (status, body["code"]) == (409, "MIGRATION_REQUIRED") and body["error"].startswith("Personal credential references need")
    config = w.gov.configurations.add(PROJECT)
    dry = w.onboarding.manage_reference(
        f"project_id={PROJECT};action=create;configuration_uuid={config.uuid};store_kind=database;"
        f"ownership_class=personal;owner_user_id={OWNER};dry_run", 0)
    assert dry["code"] == "MIGRATION_REQUIRED"
    assert w.create(None, ownership_class="project_shared")[1] == 201   # the other classes are unaffected


def test_the_legacy_index_allows_one_reference_per_configuration_and_the_swap_lifts_that(w):
    config = w.gov.configurations.add(PROJECT)
    w.create(None, config, ownership_class="service")
    w.legacy_indexes()
    models = w.gov.module("models.credential_governance")

    def add_personal(subject):
        with w.gov.db.get_session(PROJECT) as session:
            session.add(models.CredentialReference(
                project_id=PROJECT, configuration_id=config.id, configuration_uuid=uuid.UUID(config.uuid),
                provider="api_cred", ownership_class="personal", custodian_ref={"user_id": 1, "subject_ref": subject},
                store_kind="database", created_by=CREATOR))
            session.commit()

    with pytest.raises(IntegrityError):
        add_personal(OWNER_SUBJECT)
    assert w.schema.project_ids_missing_personal_index([PROJECT]) == [PROJECT]
    assert w.schema.apply_personal_index([PROJECT], dry_run=True) == ([PROJECT], [])   # a dry run changes nothing
    assert "uq_credential_reference_live_configuration" in w.index_names()
    assert w.schema.apply_personal_index([PROJECT]) == ([PROJECT], [])
    assert {"uq_credential_reference_live_shared", "uq_credential_reference_live_personal"} <= w.index_names()
    assert "uq_credential_reference_live_configuration" not in w.index_names()
    assert w.schema.project_ids_missing_personal_index([PROJECT]) == []
    add_personal(OWNER_SUBJECT)
    add_personal(OTHER_SUBJECT)
    with pytest.raises(IntegrityError):
        add_personal(OWNER_SUBJECT)   # one personal reference per owner
    with pytest.raises(IntegrityError):
        with w.gov.db.get_session(PROJECT) as session:   # and still one live shared reference
            session.add(models.CredentialReference(
                project_id=PROJECT, configuration_id=config.id, configuration_uuid=uuid.UUID(config.uuid),
                provider="api_cred", ownership_class="technical", store_kind="database", created_by=CREATOR))
            session.commit()
    assert w.schema.apply_personal_index([PROJECT]) == ([PROJECT], [])   # idempotent
    assert w.create()[1] == 201


def test_the_swap_step_of_the_table_task_reports_and_applies(w, monkeypatch):
    w.create(None, ownership_class="service")
    w.legacy_indexes()
    method = w.gov.module("methods.admin_tasks")
    schema = w.schema
    monkeypatch.setattr(schema, "project_ids_missing_credential_tables", lambda: [])
    module = types.SimpleNamespace()
    dry = method.Method.create_credential_governance_tables(module, param=f"project_id={PROJECT};dry_run")
    assert dry["personal_index"] == {"migrated": 1, "failed": 0, "failed_projects": []} and dry["dry_run"] is True
    assert "uq_credential_reference_live_configuration" in w.index_names()
    real = method.Method.create_credential_governance_tables(module, param=f"project_id={PROJECT}")
    assert real["personal_index"] == {"migrated": 1, "failed": 0, "failed_projects": []}
    again = method.Method.create_credential_governance_tables(module, param=f"project_id={PROJECT}")
    assert again["personal_index"] == {"migrated": 0, "failed": 0, "failed_projects": []}
    assert w.create()[1] == 201


def test_a_failing_swap_is_reported_per_project(w, monkeypatch):
    w.create(None, ownership_class="service")
    w.legacy_indexes()
    monkeypatch.setattr(w.schema.db, "get_session", lambda _pid: (_ for _ in ()).throw(RuntimeError("down")))
    assert w.schema.apply_personal_index([PROJECT]) == ([], [{"project_id": PROJECT}])


# --- the value endpoint -------------------------------------------------------------------------------------------------

def test_writing_the_value_stages_commits_and_answers_without_it(w):
    ref = w.personal()
    body, status = w.put(ref)
    assert (status, body) == (200, {"ok": True, "generation": 1, "state": "pending"})
    row = w.row(ref)
    assert (row.generation, row.pending_generation, row.state) == (1, None, "pending")
    assert row.configuration_generation == w.gov.configurations.rows[PROJECT][1].generation
    assert w.store().versions[uuid.UUID(ref)] == {1: {"api_key": SECRET}}
    assert [entry.state for entry in w.gov.ledger(PROJECT)] == ["committed"]
    events = {event["reason_code"]: event for event in w.events()}
    started, written = events["CREDENTIAL_MATERIAL_WRITE_STARTED"], events["CREDENTIAL_MATERIAL_WRITTEN"]
    assert (started["credential_generation"], written["credential_generation"], written["outcome"]) == (1, 1, "success")
    assert started["user_ref"] == written["user_ref"] == OWNER_SUBJECT and written["caller_ref"] == f"operator:{OWNER}"   # the owner wrote it
    assert w.store().calls == [("write", "onboard", started["event_id"])]


@pytest.mark.parametrize("store_kind", ["database", "corporate_vault"])
def test_both_store_kinds_take_a_personal_value(w, store_kind):
    ref = w.personal(store_kind=store_kind)
    assert w.put(ref)[1] == 200
    assert w.store(store_kind).versions[uuid.UUID(ref)] == {1: {"api_key": SECRET}}
    assert w.row(ref).store_kind == store_kind


def test_a_personal_reference_goes_through_the_whole_lifecycle_on_its_own_value(w):
    ref = w.personal()
    w.lifecycle(ref)
    row = w.row(ref)
    assert (row.state, row.generation, row.validated_generation, row.approved_by) == ("active", 1, 1, APPROVER)
    # the probe compared nothing with the configuration's own value, and read nothing from the store
    assert w.gov.configurations.bundle_calls == []
    assert [call[0] for call in w.store().calls] == ["write", "metadata"]
    assert "CREDENTIAL_REF_VALIDATED" in w.reasons()


def test_a_new_value_is_the_next_generation_and_asks_for_a_new_probe_and_approval(w):
    ref = w.personal()
    w.lifecycle(ref, until="approved")
    body, status = w.put(ref, {"api_key": SECRET_2}, expected_generation=1)
    assert (status, body) == (200, {"ok": True, "generation": 2, "state": "pending"})
    row = w.row(ref)
    assert (row.state, row.validated_generation, row.approved_by, row.approval_ref) == ("pending", None, None, None)
    assert w.store().versions[uuid.UUID(ref)] == {1: {"api_key": SECRET}, 2: {"api_key": SECRET_2}}


def test_an_active_reference_takes_no_new_value(w):
    ref = w.personal()
    w.lifecycle(ref)
    body, status = w.put(ref, expected_generation=1)
    assert (status, body["code"]) == (409, "INVALID_STATE")
    assert w.row(ref).generation == 1


def test_only_a_personal_reference_takes_a_value(w):
    shared = w.create(None, ownership_class="service")[0]["id"]
    body, status = w.put(shared)
    assert (status, body["code"]) == (409, "PERSONAL_ONLY") and w.store().calls == []
    assert w.put(uuid.uuid4())[1] == 404                                       # unknown
    ref = w.personal()
    assert w.put(ref, project=OTHER_PROJECT)[1] == 404                         # another project's id: not found
    assert w.row(ref).generation == 0 and w.store().calls == []


@pytest.mark.parametrize("fields", [
    {"password": SECRET},                       # not a secret field of the type
    {"api_key": SECRET, "other": SECRET_2},     # one unknown among known ones
    {"api_key.sub": SECRET},                    # a key under a field that is not a map
    {},                                         # nothing to write
    {"api_key": ""},                            # an empty value
    {"api_key": 7}, {"api_key": None}, {"api_key": ["x"]},
    {"": SECRET},
])
def test_unknown_fields_and_malformed_values_are_a_400_and_write_nothing(w, fields):
    ref = w.personal()
    body, status = w.put(ref, fields)
    assert (status, body) == (400, {"error": "The request is not valid.", "code": "INVALID_REQUEST"})
    assert w.row(ref).pending_generation is None and w.store().calls == [] and w.gov.ledger(PROJECT) == []
    assert SECRET not in everything_observable(w, body)


def test_a_map_of_secrets_takes_any_key_under_its_wildcard(w):
    w.gov.configurations.secret_paths["api_cred"] = ["api_key", "headers.*"]
    ref = w.personal()
    fields = {"api_key": SECRET, "headers.X-Token": SECRET_2}
    assert w.put(ref, fields)[1] == 200
    assert w.store().versions[uuid.UUID(ref)][1] == fields
    for bad in ({"headers.": SECRET}, {"headers": SECRET}, {"headersX-Token": SECRET}):
        assert w.put(ref, bad, expected_generation=1)[1] == 400, bad


def test_a_type_with_no_known_secret_fields_or_no_schema_service_is_refused(w):
    ref = w.personal()
    w.gov.configurations.secret_paths.clear()
    assert w.put(ref)[1] == 400
    w.gov.configurations.secret_fields_error = RuntimeError("down")
    body, status = w.put(ref)
    assert (status, body["code"]) == (503, "DEPENDENCY_UNAVAILABLE")
    assert w.store().calls == []


def raw_body(values, generation):
    return json.dumps({"fields": {f"f.{i}": value for i, value in enumerate(values)}, "expected_generation": generation},
                      separators=(",", ":"))


def test_the_body_is_bounded_before_it_is_parsed(w):
    ref = w.personal()
    w.gov.configurations.secret_paths["api_cred"] = ["f.*"]
    assert w.put(ref, {"f.0": "x" * 8192})[1] == 200                                      # the largest single value
    assert w.put(ref, {"f.0": "x" * 8193}, expected_generation=1)[0]["code"] == "INVALID_REQUEST"   # one more
    assert w.put(ref, {"f.0": "é" * 4096}, expected_generation=1)[1] == 200               # 8 KiB as UTF-8
    assert w.put(ref, {"f.0": "é" * 4097}, expected_generation=2)[0]["code"] == "INVALID_REQUEST"    # more bytes, fewer characters
    many = {f"f.{i}": "v" for i in range(32)}
    assert w.put(ref, many, expected_generation=2)[1] == 200                              # 32 fields
    assert w.put(ref, {**many, "f.32": "v"}, expected_generation=3)[0]["code"] == "INVALID_REQUEST"   # 33
    cap = 32 * 1024
    big = ["x" * 8192] * 3
    padding = cap - len(raw_body([*big, ""], 3))
    at_cap = raw_body([*big, "y" * padding], 3)
    assert len(at_cap.encode()) == cap
    reply = w.call("credential_material", "put", PROJECT, uuid.UUID(ref), raw=at_cap)
    assert reply[1] == 200                                                                # the body at the cap is read
    over = raw_body([*big, "y" * (padding + 1)], 4)
    assert len(over.encode()) == cap + 1
    body, status = w.call("credential_material", "put", PROJECT, uuid.UUID(ref), raw=over)
    assert (status, body["code"]) == (413, "REQUEST_TOO_LARGE")                           # one byte more is not
    assert w.row(ref).generation == 4 and "y" * 50 not in everything_observable(w, body)


@pytest.mark.parametrize("raw, content_type, status", [
    ("not json", None, 400), ("[]", None, 400), ("null", None, 400), ('{"fields": {"api_key": "x"}', None, 400),
    ('{"fields": {"api_key": "x"}, "expected_generation": 0}', "text/plain", 415),
    ('{"fields": {"api_key": "x"}, "expected_generation": 0}', "application/x-www-form-urlencoded", 415),
])
def test_only_a_json_object_is_read(w, raw, content_type, status):
    ref = w.personal()
    body, got = w.call("credential_material", "put", PROJECT, uuid.UUID(ref), raw=raw, content_type=content_type or "application/json")
    assert got == status and w.store().calls == []


@pytest.mark.parametrize("change", [
    lambda b: b.update(extra=1), lambda b: b.pop("expected_generation"), lambda b: b.pop("fields"),
    lambda b: b.update(expected_generation="0"), lambda b: b.update(expected_generation=True),
    lambda b: b.update(expected_generation=-1), lambda b: b.update(expected_generation=2 ** 31),
    lambda b: b.update(fields="api_key"), lambda b: b.update(fields=[["api_key", "x"]]),
    lambda b: b.update(secret_ref="x"),
])
def test_a_malformed_body_is_a_400(w, change):
    ref = w.personal()
    body = {"fields": {"api_key": SECRET}, "expected_generation": 0}
    change(body)
    reply = w.call("credential_material", "put", PROJECT, uuid.UUID(ref), body=body)
    assert reply[1] == 400 and reply[0]["code"] == "INVALID_REQUEST" and SECRET not in str(reply)
    assert w.store().calls == []


def test_a_stale_generation_is_a_conflict_and_nothing_is_written(w):
    ref = w.personal()
    w.put(ref)
    body, status = w.put(ref, {"api_key": SECRET_2}, expected_generation=0)
    assert (status, body["code"]) == (409, "CONCURRENT_CHANGE")
    body, status = w.put(ref, {"api_key": SECRET_2}, expected_generation=5)
    assert (status, body["code"]) == (409, "CONCURRENT_CHANGE")
    assert w.row(ref).generation == 1 and list(w.store().versions[uuid.UUID(ref)]) == [1]


def test_a_second_writer_while_one_is_staged_is_told_to_reconcile(w):
    ref = w.personal()
    w.store().crash_before_write = True
    with pytest.raises(Crash):
        w.put(ref)
    w.store().crash_before_write = False
    body, status = w.put(ref)
    assert (status, body["code"]) == (409, "IMPORT_IN_FLIGHT")


def test_a_lost_commit_race_is_a_conflict_and_leaves_the_ledger_for_the_reconciler(w, monkeypatch):
    ref = w.personal()
    monkeypatch.setattr(w.material, "commit_generation", lambda *a, **k: False)
    body, status = w.put(ref)
    assert (status, body["code"]) == (409, "CONCURRENT_CHANGE")
    assert w.gov.ledger(PROJECT)[0].state == "written"


def test_a_store_that_refuses_releases_the_stage_and_a_timeout_leaves_it_for_the_reconciler(w):
    ref = w.personal()
    w.store().fail["write"] = "DENIED"
    body, status = w.put(ref)
    assert (status, body["code"]) == (403, "STORE_DENIED")
    assert (w.row(ref).generation, w.row(ref).pending_generation) == (0, None)
    assert [entry.state for entry in w.gov.ledger(PROJECT)] == ["abandoned"]
    w.store().fail.clear()
    w.store().fail_after_effect["write"] = "UNAVAILABLE"
    body, status = w.put(ref)
    assert (status, body["code"]) == (503, "STORE_UNAVAILABLE")
    assert (w.row(ref).generation, w.row(ref).pending_generation) == (0, 1)
    assert SECRET not in everything_observable(w, body)


def test_a_down_audit_trail_is_a_503_and_keeps_nothing(w):
    ref = w.personal()
    w.gov.tracing.fail = True
    body, status = w.put(ref)
    assert (status, body["code"]) == (503, "AUDIT_UNAVAILABLE")
    w.gov.tracing.fail = False
    assert (w.row(ref).pending_generation, w.gov.ledger(PROJECT), w.store().calls) == (None, [], [])


# --- the value is never anywhere but the store ---------------------------------------------------------------------------------

def test_the_value_is_in_no_log_reply_event_or_row_on_any_path(w, monkeypatch):
    replies = []
    ref = w.personal()
    replies.append(w.put(ref))                                                     # success
    replies.append(w.put(ref, {"api_key": SECRET_2}, expected_generation=0))       # CAS conflict
    replies.append(w.put(ref, {"nope": SECRET_2}, expected_generation=1))          # unknown field
    replies.append(w.put(ref, {"api_key": SECRET_2 * 400}, expected_generation=1)) # too long
    w.store().fail["write"] = "DENIED"
    replies.append(w.put(ref, {"api_key": SECRET_2}, expected_generation=1))       # store refusal
    w.store().fail.clear()
    monkeypatch.setattr(w.material, "write_to_store", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(SECRET_2)))
    replies.append(w.put(ref, {"api_key": SECRET_2}, expected_generation=1))       # an unexpected failure
    assert [status for _, status in replies] == [200, 409, 400, 400, 403, 500]
    seen = everything_observable(w, *replies)
    assert SECRET not in seen and SECRET_2 not in seen and "sentinel" not in seen
    assert w.store().versions[uuid.UUID(ref)][1] == {"api_key": SECRET}   # only the store has it


def test_nothing_in_the_reply_or_repr_of_the_parsed_body_shows_the_value(w):
    api = w.gov.module("utils.credential_api")
    body = api.MaterialBody.parse_obj({"fields": {"api_key": SECRET}, "expected_generation": 0})
    assert SECRET not in repr(body) and SECRET not in str(body) and SECRET not in str(body.dict()) and SECRET not in body.json()
    with pytest.raises(Exception) as err:
        api.MaterialBody.parse_obj({"fields": {"api_key": SECRET}, "expected_generation": "x"})
    assert SECRET not in str(err.value)
    reply = w.put(w.personal())
    assert SECRET not in json.dumps(reply[0])


def test_the_endpoint_is_write_only(w):
    handler = w.mods["credential_material"].AdminAPI
    assert [verb for verb in ("get", "post", "delete", "patch", "head", "options") if hasattr(handler, verb)] == []
    assert hasattr(handler, "put")
    ref = w.personal()
    with pytest.raises(AttributeError):
        w.call("credential_material", "get", PROJECT, uuid.UUID(ref))
    api = w.mods["credential_material"].API
    assert api.url_params == ["<int:project_id>/<uuid:ref_id>"] and set(api.mode_handlers) == {"administration", "default"}


def test_the_value_write_needs_manage_and_a_signed_in_operator(w):
    descriptor = StubAuth.decorators.requirements[
        f"{w.mods['credential_material'].__name__}:AdminAPI.put"]
    assert descriptor["permissions"] == ["credentials.manage", "credentials.set_own_value"]
    api = w.gov.module("utils.credential_api")
    assert descriptor["recommended_roles"] == api.OPERATE_ROLES
    ref = w.personal()
    body, status = w.put(ref, actor=0)
    assert (status, body["code"]) == (403, "ACTOR_REQUIRED") and w.store().calls == []


def test_the_only_code_that_writes_the_store_stays_in_the_custody_modules():
    root = Path(__file__).resolve().parents[2]
    tree = ast.parse((root / "utils" / "credential_material.py").read_text(encoding="utf-8"))
    attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not attrs & {"write", "read", "metadata", "delete_all", "mint", "get_store"}


# --- crash windows (the harness of the import tests) -----------------------------------------------------------------------

@pytest.fixture
def reconcile(w, monkeypatch):
    reconciler = w.gov.module("utils.credential_reconcile")
    monkeypatch.setattr(reconciler, "project_ids_missing_credential_tables", lambda: [])

    class Module:   # the reconciler lists projects through the module's context
        class context:  # noqa: N801
            class rpc_manager:  # noqa: N801
                class call:  # noqa: N801
                    @staticmethod
                    def project_list(filter_=None):
                        return [{"id": PROJECT}]

    def run():
        w.gov.age_ledger(PROJECT, 60)
        return reconciler.reconcile_store(Module(), f"project_id={PROJECT};older_than_s=0", CREATOR)
    return run


def test_a_crash_before_the_store_write_is_abandoned_and_the_write_can_be_repeated(w, reconcile):
    ref = w.personal()
    w.store().crash_before_write = True
    with pytest.raises(Crash):
        w.put(ref)
    assert (w.row(ref).generation, w.row(ref).pending_generation) == (0, 1)
    w.store().crash_before_write = False
    result = reconcile()
    assert result["abandoned"] == 1 and result["failed"] == 0
    assert (w.row(ref).generation, w.row(ref).pending_generation) == (0, None)
    assert [entry.state for entry in w.gov.ledger(PROJECT)] == ["abandoned"]
    assert w.put(ref)[1] == 200 and list(w.store().versions[uuid.UUID(ref)]) == [1]


def test_a_crash_after_the_store_write_is_rolled_forward_to_one_generation(w, reconcile):
    ref = w.personal()
    w.store().crash_after_write = True
    with pytest.raises(Crash):
        w.put(ref)
    w.store().crash_after_write = False
    assert list(w.store().versions[uuid.UUID(ref)]) == [1] and w.row(ref).generation == 0
    result = reconcile()
    assert result["rolled_forward"] == 1 and result["failed"] == 0
    row = w.row(ref)
    assert (row.generation, row.pending_generation, row.state) == (1, None, "pending")
    assert row.configuration_generation == w.gov.configurations.rows[PROJECT][1].generation
    assert [entry.state for entry in w.gov.ledger(PROJECT)] == ["committed"]
    assert w.put(ref, {"api_key": SECRET_2}, expected_generation=1)[0]["generation"] == 2   # and it goes on
    assert w.action(ref, "probe")[1] == 200


def test_a_crash_after_the_ledger_was_marked_written_is_rolled_forward_too(w, reconcile, monkeypatch):
    ref = w.personal()
    real = w.material.commit_generation

    def die(*args, **kwargs):
        raise Crash()
    monkeypatch.setattr(w.material, "commit_generation", die)
    with pytest.raises(Crash):
        w.put(ref)
    monkeypatch.setattr(w.material, "commit_generation", real)
    assert w.gov.ledger(PROJECT)[0].state == "written"
    assert reconcile()["rolled_forward"] == 1
    assert (w.row(ref).generation, w.row(ref).pending_generation) == (1, None)


# --- the probe of a personal reference -------------------------------------------------------------------------------------

def test_the_probe_checks_the_store_and_that_the_configuration_has_not_changed(w):
    ref = w.personal()
    assert w.action(ref, "probe")[0]["code"] == "INVALID_STATE"                # no value yet
    w.put(ref)
    w.gov.configurations.edit_secret(next(iter(w.gov.configurations.rows[PROJECT].values())), api_key="elsewhere")
    body, status = w.action(ref, "probe")
    assert (status, body["code"]) == (409, "CONFIGURATION_CHANGED")           # the configuration moved on
    assert [e["outcome"] for e in w.events() if e["event_type"] == "probe"][-1] == "failed"
    assert w.put(ref, expected_generation=1)[1] == 200                         # write the value again at the new generation
    assert w.action(ref, "probe")[1] == 200 and w.row(ref).state == "validated"


def test_a_probe_with_no_such_version_in_the_store_is_a_store_error(w):
    ref = w.personal()
    w.put(ref)
    w.store().versions.clear()
    body, status = w.action(ref, "probe")
    assert (status, body["code"]) == (503, "STORE_NOT_FOUND")
    assert w.row(ref).state == "pending"


def test_an_ordinary_probe_is_unchanged_for_a_shared_reference(w):
    config = w.gov.configurations.add(PROJECT)
    ref = w.create(None, config, ownership_class="service")[0]["id"]
    assert w.action(ref, "import")[1] == 200
    assert w.action(ref, "probe")[1] == 200
    assert [c[2] for c in w.gov.configurations.bundle_calls] == ["onboard", "probe"]


# --- check_connection --------------------------------------------------------------------------------------------------------

def test_check_connection_tests_the_stored_value_as_its_owner_and_validates(w):
    ref = w.personal()
    w.put(ref)
    body, status = w.action(ref, "probe", check_connection=True)
    assert (status, body) == (200, {"ok": True, "action": "probe", "id": ref, "generation": 1, "state": "validated",
                                    "connection_checked": True})
    # the operator probes; the custodian's reference is the one probed; the pending value is admitted for it
    assert w.gov.core.checks == [(PROJECT, w.config.uuid, "api_cred", OWNER, CREATOR, True)]
    assert w.row(ref).state == "validated"
    reasons = w.reasons()
    assert reasons.index("CREDENTIAL_CONNECTION_CHECKED") < reasons.index("CREDENTIAL_REF_VALIDATED")   # checked first


def test_a_provider_that_refuses_the_credential_sends_the_reference_back_to_pending(w):
    ref = w.personal()
    w.put(ref)
    w.gov.core.check_answer = {"success": False, "message": f"401 for key {SECRET}"}
    body, status = w.action(ref, "probe", check_connection=True)
    assert (status, body) == (409, {"error": "The provider did not accept the stored credential.",
                                    "code": "CHECK_CONNECTION_FAILED"})
    row = w.row(ref)
    assert (row.state, row.validated_generation) == ("pending", None)           # it was never validated: nothing to revert
    assert "CREDENTIAL_REF_VALIDATED" not in w.reasons()
    failed = [e for e in w.events() if e["reason_code"] == "CREDENTIAL_CONNECTION_CHECK_FAILED"]
    assert failed and failed[0]["outcome"] == "failed" and failed[0]["event_type"] == "probe"
    assert SECRET not in everything_observable(w, body)                          # the provider's text is not repeated


def test_an_operator_who_may_not_probe_is_told_so_with_a_403(w):
    ref = w.personal()
    w.put(ref)
    w.gov.core.check_answer = {"success": False, "code": "DENIED_RBAC", "message": "m"}
    body, status = w.action(ref, "probe", check_connection=True)
    assert (status, body) == (403, {"error": "You do not have permission to test saved credentials.",
                                    "code": "DENIED_RBAC"})
    assert w.row(ref).state == "pending" and "CREDENTIAL_CONNECTION_CHECK_FAILED" in w.reasons()


@pytest.mark.parametrize("answer, error", [
    ({"success": False, "code": "WORKER_CAPABILITY_UNAVAILABLE", "message": "m"}, None),
    ({"success": False, "requires_authorization": True, "message": "m"}, None),
    ("nonsense", None), ({}, None), (None, None),
    (None, RuntimeError("worker down")),
])
def test_a_check_that_could_not_run_is_a_refusal_and_not_a_pass(w, answer, error):
    ref = w.personal()
    w.put(ref)
    w.gov.core.check_answer, w.gov.core.check_error = answer, error
    body, status = w.action(ref, "probe", check_connection=True)
    assert (status, body["code"]) == (503, "CHECK_CONNECTION_REFUSED")
    assert w.row(ref).state == "pending"


def test_a_reference_that_is_already_validated_or_active_is_checked_again_without_changing_state(w):
    ref = w.personal()
    w.lifecycle(ref)
    w.gov.core.check_answer = {"success": False, "message": "no"}
    body, status = w.action(ref, "probe", check_connection=True)
    assert (status, body["code"]) == (409, "CHECK_CONNECTION_FAILED") and w.row(ref).state == "active"
    w.gov.core.check_answer = {"success": True}
    body, status = w.action(ref, "probe", check_connection=True)
    assert (status, body["state"], body["connection_checked"]) == (200, "active", True)
    assert w.action(ref, "probe")[0]["code"] == "INVALID_STATE"                # a plain probe is for a pending one only


def test_check_connection_is_for_probe_of_a_personal_reference_only(w):
    shared = w.create(None, ownership_class="service")[0]["id"]
    w.action(shared, "import")
    body, status = w.action(shared, "probe", check_connection=True)
    assert (status, body["code"]) == (400, "INVALID_REQUEST") and w.gov.core.checks == []
    ref = w.personal()
    for action in ("import", "activate", "retire"):
        assert w.action(ref, action, check_connection=True)[1] == 400
    assert w.action(ref, "probe", check_connection=False)[0]["code"] == "INVALID_STATE"   # accepted, nothing to probe yet
    assert w.action(ref, "probe", check_connection="yes")[1] == 400


# --- what the lists show -------------------------------------------------------------------------------------------------

def test_the_lists_name_the_owner_and_never_show_the_custody_record_or_the_subject(w):
    config = w.gov.configurations.add(PROJECT)
    ref = w.personal(config=config)
    w.lifecycle(ref)
    listed, status = w.call("credential_references", "get", PROJECT)
    assert status == 200 and listed["total"] == 1
    [row] = listed["rows"]
    assert (row["ownership_class"], row["owner"]) == ("personal", {"id": OWNER, "email": f"u{OWNER}@x.test"})
    detail, _ = w.call("credential_reference", "get", PROJECT, uuid.UUID(ref))
    text = json.dumps([listed, detail])
    for hidden in (OWNER_SUBJECT, "custodian", "subject_ref", "store_locator", SECRET, "credential_store"):
        assert hidden not in text
    filtered, _ = w.call("credential_references", "get", PROJECT, query_string={"owner_user_id": OTHER_OWNER})
    assert filtered["total"] == 0
    filtered, _ = w.call("credential_references", "get", PROJECT, query_string={"owner_user_id": OWNER})
    assert filtered["total"] == 1


# --- grants of a personal credential ------------------------------------------------------------------------------------------

def test_a_personal_credential_is_granted_to_its_owner_only(w):
    ref = w.lifecycle(w.personal())
    binding = w.seed_binding()

    def grant(subject_user):
        body = {"agent_binding_ref": binding, "toolkit_id": TOOLKIT, "credential_ref": ref, "subject_user_id": subject_user}
        return w.call("credential_grants", "post", PROJECT, body=body)

    body, status = grant(OTHER_OWNER)
    assert (status, body) == (409, {"error": "A personal credential can be granted only to its owner.",
                                    "code": "SUBJECT_NOT_OWNER"})
    assert "GRANT_PENDING_APPROVAL" not in w.reasons()
    body, status = grant(OWNER)
    assert status == 201 and body["state"] == "pending_approval"
    task = w.gov.module("utils.credential_grants").manage_grant(
        f"project_id={PROJECT};action=create;binding_ref={binding};toolkit_id={TOOLKIT};ref={ref};subject_ref={OTHER_SUBJECT}",
        CREATOR)
    assert task["code"] == "SUBJECT_NOT_OWNER"


def test_a_mandate_may_hold_a_personal_credential_only_through_its_owner(w):
    ref = w.lifecycle(w.personal())
    binding = w.seed_binding()
    run = lambda subject: w.gov.module("utils.credential_grants").manage_grant(   # noqa: E731
        f"project_id={PROJECT};action=create;binding_ref={binding};toolkit_id={TOOLKIT};ref={ref};subject_ref={subject}",
        CREATOR)
    assert run(w.seed_mandate(binding, OTHER_OWNER))["code"] == "SUBJECT_NOT_OWNER"
    assert "error" not in run(w.seed_mandate(binding, OWNER))


def test_a_shared_credential_is_granted_to_anyone_as_before(w):
    config = w.gov.configurations.add(PROJECT)
    ref = str(w.gov.add_reference(PROJECT, state="active", configuration_id=config.id, configuration_uuid=uuid.UUID(config.uuid)))
    binding = w.seed_binding()
    body = {"agent_binding_ref": binding, "toolkit_id": TOOLKIT, "credential_ref": ref, "subject_user_id": OTHER_OWNER}
    assert w.call("credential_grants", "post", PROJECT, body=body)[1] == 201


# --- the facts admission reads -------------------------------------------------------------------------------------------------

@pytest.fixture
def facts(w):
    method = w.gov.module("methods.credential_facts")
    return lambda *args, **kw: method.Method.credential_use_facts(object(), *args, **kw)


def trio(w, with_shared=True):
    """One configuration with a shared reference and the personal references of two owners, all active."""
    config = w.gov.configurations.add(PROJECT)
    ids = {"config": config.id}
    common = dict(configuration_id=config.id, configuration_uuid=uuid.UUID(config.uuid))
    if with_shared:
        ids["shared"] = str(w.gov.add_reference(PROJECT, state="active", ownership_class="service", **common))
    ids["mine"] = str(w.gov.add_reference(
        PROJECT, state="active", ownership_class="personal",
        custodian_ref={"user_id": OWNER, "subject_ref": OWNER_SUBJECT}, **common))
    ids["theirs"] = str(w.gov.add_reference(
        PROJECT, state="active", ownership_class="personal",
        custodian_ref={"user_id": OTHER_OWNER, "subject_ref": OTHER_SUBJECT}, **common))
    return ids


def picked(result, config_id):
    return result["references"][config_id]["ref_id"]


def test_the_facts_prefer_the_callers_personal_reference_else_the_shared_one(w, facts):
    ids = trio(w)
    assert picked(facts(PROJECT, [ids["config"]], [], personal_subject_ref=OWNER_SUBJECT), ids["config"]) == ids["mine"]
    assert picked(facts(PROJECT, [ids["config"]], [], personal_user_id=OWNER), ids["config"]) == ids["mine"]
    assert picked(facts(PROJECT, [ids["config"]], [], personal_subject_ref=OTHER_SUBJECT), ids["config"]) == ids["theirs"]
    assert picked(facts(PROJECT, [ids["config"]], [], personal_subject_ref="idp:t1:nobody"), ids["config"]) == ids["shared"]
    assert picked(facts(PROJECT, [ids["config"]], []), ids["config"]) == ids["shared"]    # no caller: never a stranger's personal one


def test_the_facts_return_another_owners_personal_reference_only_when_nothing_else_exists(w, facts):
    config = w.gov.configurations.add(PROJECT)
    common = dict(configuration_id=config.id, configuration_uuid=uuid.UUID(config.uuid), state="active",
                  ownership_class="personal")
    older = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = str(w.gov.add_reference(
        PROJECT, custodian_ref={"user_id": OTHER_OWNER, "subject_ref": OTHER_SUBJECT}, created_at=older, **common))
    w.gov.add_reference(
        PROJECT, custodian_ref={"user_id": OWNER, "subject_ref": OWNER_SUBJECT}, created_at=older + timedelta(days=1),
        **common)
    for kwargs in ({"personal_subject_ref": "idp:t1:nobody"}, {}):
        got = facts(PROJECT, [config.id], [], **kwargs)["references"][config.id]
        assert (got["ref_id"], got["custodian_subject_ref"]) == (first, OTHER_SUBJECT)   # the oldest, always the same


def test_a_personal_reference_that_is_not_active_says_so_in_one_sentence(w, facts):
    ids = trio(w)
    assert w.action(ids["mine"], "suspend")[1] == 200
    mine = facts(PROJECT, [ids["config"]], [], personal_subject_ref=OWNER_SUBJECT)["references"][ids["config"]]
    assert mine["ref_id"] == ids["mine"] and mine["state"] == "suspended"   # it wins even though it is not in use
    assert mine["note"] == "personal reference suspended: runs of its owner are refused until it is active"
    other = facts(PROJECT, [ids["config"]], [], personal_subject_ref=OTHER_SUBJECT)["references"][ids["config"]]
    assert "note" not in other and "note" not in facts(PROJECT, [], [], ref_ids=[ids["shared"]])["references"][ids["config"]]


def test_the_facts_by_reference_id_return_exactly_that_reference_and_name_its_owner(w, facts):
    ids = trio(w)
    got = facts(PROJECT, [], [], ref_ids=[ids["theirs"]], personal_subject_ref=OWNER_SUBJECT)["references"][ids["config"]]
    assert (got["ref_id"], got["custodian_user_id"], got["custodian_subject_ref"], got["ownership_class"]) == (
        ids["theirs"], OTHER_OWNER, OTHER_SUBJECT, "personal")
    shared = facts(PROJECT, [], [], ref_ids=[ids["shared"]])["references"][ids["config"]]
    assert (shared["custodian_subject_ref"], shared["custodian_user_id"]) == (None, None)


def test_retired_and_foreign_project_references_are_not_returned(w, facts):
    ids = trio(w)
    w.action(ids["mine"], "retire")
    assert picked(facts(PROJECT, [ids["config"]], [], personal_subject_ref=OWNER_SUBJECT), ids["config"]) == ids["shared"]
    assert facts(OTHER_PROJECT, [ids["config"]], [], personal_subject_ref=OWNER_SUBJECT)["references"] == {}


@pytest.mark.parametrize("kwargs", [
    {"personal_subject_ref": ""}, {"personal_subject_ref": "x" * 161}, {"personal_subject_ref": 7},
    {"personal_user_id": True}, {"personal_user_id": "30"},
])
def test_a_malformed_caller_is_a_value_error(w, facts, kwargs):
    with pytest.raises(ValueError):
        facts(PROJECT, [1], [], **kwargs)


def test_many_configurations_are_read_in_a_fixed_number_of_queries(w, facts):
    ids = [trio(w) for _ in range(6)]
    queries = []
    engine = w.gov.db.engine(PROJECT)
    sa.event.listen(engine, "before_cursor_execute", lambda *a, **k: queries.append(a[2]))
    result = facts(PROJECT, [i["config"] for i in ids], [], personal_subject_ref=OWNER_SUBJECT)
    assert {picked(result, i["config"]) for i in ids} == {i["mine"] for i in ids}
    assert len(queries) <= 2


# --- review fixes: the schema step -----------------------------------------------------------------------------------------

def test_the_step_is_not_applied_while_the_legacy_index_is_still_there(w):
    w.create(None, ownership_class="service")
    w.gov.db.execute(PROJECT, "CREATE UNIQUE INDEX uq_credential_reference_live_configuration "
                              "ON tenant.credential_reference (configuration_id) WHERE state <> 'retired'")
    names = w.index_names()
    assert {"uq_credential_reference_live_shared", "uq_credential_reference_live_personal"} <= names
    with w.gov.db.get_session(PROJECT) as session:
        assert w.schema.personal_index_applied(session) is False and w.schema.personal_schema_applied(session) is False
    assert w.create()[0]["code"] == "MIGRATION_REQUIRED"
    assert w.schema.apply_personal_index([PROJECT]) == ([PROJECT], [])
    assert "uq_credential_reference_live_configuration" not in w.index_names() and w.create()[1] == 201


def test_a_project_without_the_written_by_column_is_swapped_and_gets_it(w):
    w.create(None, ownership_class="service")
    w.legacy_indexes(drop_column=True)
    assert "written_by" not in w.column_names()
    assert w.schema.project_ids_missing_personal_index([PROJECT]) == [PROJECT]
    assert w.schema.apply_personal_index([PROJECT], dry_run=True) == ([PROJECT], []) and "written_by" not in w.column_names()
    assert w.schema.apply_personal_index([PROJECT]) == ([PROJECT], [])
    assert "written_by" in w.column_names() and w.schema.project_ids_missing_personal_index([PROJECT]) == []
    assert w.create()[1] == 201


def test_the_column_alone_is_added_by_the_startup_safety_net_function(w):
    w.create(None, ownership_class="service")
    w.gov.db.execute(PROJECT, "ALTER TABLE tenant.credential_reference DROP COLUMN written_by")
    assert w.schema.apply_written_by([PROJECT]) == ([PROJECT], [])
    assert "written_by" in w.column_names()
    assert w.schema.apply_written_by([PROJECT]) == ([PROJECT], [])   # idempotent


def test_the_swap_takes_a_lock_timeout_on_postgresql_only(w):
    class Connection:
        def __init__(self, name):
            self.dialect, self.statements = types.SimpleNamespace(name=name), []

        def execute(self, statement):
            self.statements.append(str(statement))

    postgres, sqlite = Connection("postgresql"), Connection("sqlite")
    w.schema._set_lock_timeout(postgres)   # pylint: disable=W0212
    w.schema._set_lock_timeout(sqlite)     # pylint: disable=W0212
    assert postgres.statements == ["SET LOCAL lock_timeout = '5s'"] and sqlite.statements == []


@pytest.mark.skipif(not PG_DSN, reason="needs PostgreSQL (ELITEA_TEST_PG_DSN)")
def test_a_busy_table_fails_that_project_alone_after_the_lock_timeout(w, monkeypatch):
    w.create(None, ownership_class="service")
    w.legacy_indexes()
    monkeypatch.setattr(w.schema, "LOCK_TIMEOUT", "300ms")
    engine = w.gov.db.engine(PROJECT)
    with engine.connect() as holder:   # another session holds the table
        schema = engine.get_execution_options()["schema_translate_map"]["tenant"]
        holder.execute(sa.text(f'LOCK TABLE "{schema}".credential_reference IN ACCESS EXCLUSIVE MODE'))
        migrated, failed = w.schema.apply_personal_index([PROJECT])
        holder.rollback()
    assert (migrated, failed) == ([], [{"project_id": PROJECT}])
    assert "uq_credential_reference_live_configuration" in w.index_names()   # nothing half-applied
    assert w.schema.apply_personal_index([PROJECT]) == ([PROJECT], [])        # and the step is repeated


# --- review fixes: who writes, who approves, rotation -----------------------------------------------------------------

def test_whoever_wrote_the_value_cannot_approve_it(w):
    ref = w.personal(WRITER)   # the owner writes the value of their own credential
    assert w.put(ref)[1] == 200
    assert w.row(ref).written_by == WRITER and w.row(ref).created_by == CREATOR
    assert w.action(ref, "probe", actor=APPROVER)[1] == 200
    body, status = w.action(ref, "approve", actor=WRITER, approval_ref="CHG-1", policy_revision="rev-1")
    assert (status, body["code"]) == (403, "SELF_APPROVAL")
    body, status = w.action(ref, "approve", actor=CREATOR, approval_ref="CHG-1", policy_revision="rev-1")
    assert (status, body["code"]) == (403, "SELF_APPROVAL")
    assert w.action(ref, "approve", actor=APPROVER, approval_ref="CHG-1", policy_revision="rev-1")[1] == 200


def test_an_import_records_its_writer_too(w):
    shared = w.create(None, ownership_class="service")[0]["id"]
    assert w.action(shared, "import", actor=WRITER)[1] == 200 and w.row(shared).written_by == WRITER
    w.action(shared, "probe")
    body, status = w.action(shared, "approve", actor=WRITER, approval_ref="CHG-1", policy_revision="rev-1")
    assert (status, body["code"]) == (403, "SELF_APPROVAL")


def test_the_lists_name_the_writer(w):
    ref = w.personal(WRITER)
    w.put(ref)
    [row] = w.call("credential_references", "get", PROJECT)[0]["rows"]
    assert row["written_by"] == {"id": WRITER, "email": f"u{WRITER}@x.test"}


def test_a_suspended_reference_takes_a_new_value_and_keeps_its_grants(w):
    ref = w.personal()
    w.lifecycle(ref)
    binding = w.seed_binding()
    grant = w.call("credential_grants", "post", PROJECT, body={
        "agent_binding_ref": binding, "toolkit_id": TOOLKIT, "credential_ref": ref, "subject_user_id": OWNER})[0]["id"]
    assert w.put(ref, {"api_key": SECRET_2}, expected_generation=1)[0]["code"] == "INVALID_STATE"   # not while it is in use
    assert w.action(ref, "suspend")[1] == 200
    body, status = w.put(ref, {"api_key": SECRET_2}, expected_generation=1)
    assert (status, body) == (200, {"ok": True, "generation": 2, "state": "pending"})
    for step, who in (("probe", CREATOR),):
        assert w.action(ref, step, actor=who)[1] == 200
    assert w.action(ref, "approve", actor=APPROVER, approval_ref="CHG-2", policy_revision="rev-2")[1] == 200
    assert w.action(ref, "activate", actor=APPROVER)[0]["state"] == "active"
    row = w.row(ref)
    assert (row.generation, row.validated_generation, row.written_by) == (2, 2, OWNER)
    assert w.gov.grant(PROJECT, uuid.UUID(grant)).credential_ref == uuid.UUID(ref)
    assert w.store().versions[uuid.UUID(ref)] == {1: {"api_key": SECRET}, 2: {"api_key": SECRET_2}}


def test_a_retired_reference_takes_no_value(w):
    ref = w.personal()
    w.action(ref, "retire")
    assert w.put(ref)[0]["code"] == "INVALID_STATE"


# --- review fixes: the value is complete, and the flags --------------------------------------------------------------------

def test_a_value_needs_at_least_one_secret_field_of_the_type_and_no_others(w):
    """A type can offer alternative ways to authenticate (access token, password, private key): a credential uses one."""
    w.gov.configurations.secret_paths["api_cred"] = ["access_token", "password", "app_private_key", "headers.*"]
    ref = w.personal()
    for refused in ({}, {"token": SECRET}, {"access_token": SECRET, "token": SECRET_2}, {"headers": SECRET}, {"headers.": SECRET}):
        body, status = w.put(ref, refused)
        assert (status, body) == (400, {"error": "The request is not valid.", "code": "INVALID_REQUEST"}), refused
    assert w.store().calls == [] and w.gov.ledger(PROJECT) == []
    assert w.put(ref, {"password": SECRET})[1] == 200                                    # one alternative is enough
    assert w.put(ref, {"app_private_key": SECRET_2}, expected_generation=1)[1] == 200    # another one, later
    assert w.put(ref, {"headers.X": "h"}, expected_generation=2)[1] == 200               # a key under a wildcard counts
    assert w.put(ref, {"access_token": SECRET, "password": SECRET_2}, expected_generation=3)[1] == 200   # and so do several
    assert w.store().versions[uuid.UUID(ref)][1] == {"password": SECRET}


def test_a_type_with_no_secret_fields_takes_no_value(w):
    w.gov.configurations.secret_paths["api_cred"] = []
    assert w.put(w.personal())[0]["code"] == "INVALID_REQUEST"


def test_a_false_check_connection_is_accepted_and_ignored_on_any_action(w):
    shared = w.create(None, ownership_class="service")[0]["id"]
    assert w.action(shared, "import", check_connection=False)[1] == 200
    assert w.action(shared, "probe", check_connection=False)[1] == 200
    assert w.action(shared, "suspend", check_connection=True)[0]["code"] == "INVALID_REQUEST"


# --- review fixes: the onboarding probe may release a pending value ------------------------------------------------------------

def test_the_release_serves_a_pending_value_only_to_the_onboarding_probe(w):
    ref = w.personal()
    w.put(ref)
    release = w.gov.module("utils.credential_release")
    args = (PROJECT, ref, 1, str(uuid.uuid4()), "user:1")
    assert release.release_material(*args) == {"ok": False, "reason_code": "CREDENTIAL_REFERENCE_INACTIVE"}
    assert release.release_material(*args, allow_validated=True)["reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"
    got = release.release_material(*args, allow_pending=True)
    assert got["ok"] is True and got["value"].fields["api_key"].get_secret_value() == SECRET
    assert release.release_material(PROJECT, ref, 2, str(uuid.uuid4()), "user:1", allow_pending=True)["reason_code"] \
        == "CREDENTIAL_GENERATION_MISMATCH"
    w.action(ref, "retire")
    assert release.release_material(*args, allow_pending=True)["reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"


# --- a personal value is set by its owner only ---------------------------------------------------------------------------

MODES = ("AdminAPI", "ProjectAPI")


@pytest.mark.parametrize("handler", MODES)
def test_the_owner_writes_their_value_in_either_mode(w, handler):
    ref = w.personal()
    body, status = w.put(ref, actor=OWNER, handler=handler)
    assert (status, body) == (200, {"ok": True, "generation": 1, "state": "pending"})
    assert w.row(ref).written_by == OWNER and w.store().versions[uuid.UUID(ref)] == {1: {"api_key": SECRET}}


@pytest.mark.parametrize("handler", MODES)
@pytest.mark.parametrize("actor, label", [
    (CREATOR, "an administrator (who created it)"), (APPROVER, "another administrator"),
    (OTHER_OWNER, "another project member"), (OUTSIDER, "someone outside the project"),
])
def test_no_one_but_the_owner_can_type_a_personal_value(w, handler, actor, label):
    ref = w.personal()
    body, status = w.put(ref, actor=actor, handler=handler)
    assert (status, body) == (403, {"error": "Only the owner of a personal credential can set its value.",
                                    "code": "OWNER_ONLY"}), label
    assert w.row(ref).generation == 0 and w.row(ref).pending_generation is None
    assert w.store().calls == [] and w.gov.ledger(PROJECT) == [] and w.config_reads() == 0


@pytest.mark.parametrize("handler", MODES)
def test_a_personal_value_is_refused_before_the_body_is_read(w, handler):
    ref = w.personal()
    body, status = w.call("credential_material", "put", PROJECT, uuid.UUID(ref), raw="{not json", actor=APPROVER,
                          handler=handler)
    assert (status, body["code"]) == (403, "OWNER_ONLY")   # not a 400 for the body, and nothing parsed


@pytest.mark.parametrize("handler", MODES)
def test_a_reference_of_another_project_is_not_found_for_everyone(w, handler):
    ref = w.personal()
    for actor in (OWNER, CREATOR, OTHER_OWNER):
        assert w.put(ref, actor=actor, project=OTHER_PROJECT, handler=handler)[1] == 404
    assert w.put(uuid.uuid4(), actor=OWNER, handler=handler)[1] == 404


@pytest.mark.parametrize("handler", MODES)
def test_an_unidentified_caller_is_refused(w, handler):
    ref = w.personal()
    body, status = w.put(ref, actor=0, handler=handler)
    assert (status, body["code"]) == (403, "ACTOR_REQUIRED")


def test_a_shared_reference_is_still_for_credentials_manage_in_the_administration_route(w):
    shared = w.create(None, ownership_class="service")[0]["id"]
    body, status = w.put(shared, actor=CREATOR)
    assert (status, body["code"]) == (409, "PERSONAL_ONLY")                      # as before: it takes no value
    w.permissions = {"credentials.set_own_value"}                                # the owner's permission is not manage
    assert w.put(shared, actor=OWNER)[0]["code"] == "FORBIDDEN"
    assert w.put(shared, actor=OWNER)[1] == 403
    w.permissions = {"credentials.manage"}
    assert w.put(shared, actor=CREATOR)[0]["code"] == "PERSONAL_ONLY"


def test_a_shared_reference_takes_nothing_through_the_default_mode_route(w):
    shared = w.create(None, ownership_class="service")[0]["id"]
    for actor in (OWNER, CREATOR):
        body, status = w.put(shared, actor=actor, handler="ProjectAPI")
        assert (status, body["code"]) == (403, "FORBIDDEN")
    assert w.store().calls == []


def test_an_administrator_who_is_the_owner_may_write_their_own_value(w):
    ref = w.personal(CREATOR)
    assert w.put(ref, actor=CREATOR)[1] == 200
    assert w.put(ref, {"api_key": SECRET_2}, expected_generation=1, actor=CREATOR, handler="ProjectAPI")[1] == 200


def test_the_owner_needs_neither_manage_nor_any_operator_permission(w):
    ref = w.personal()
    w.permissions = {"credentials.set_own_value"}
    assert w.put(ref, actor=OWNER)[1] == 200
    assert w.put(ref, {"api_key": SECRET_2}, expected_generation=1, actor=OWNER, handler="ProjectAPI")[1] == 200


def test_the_routes_declare_the_permissions_and_the_modes(w):
    api = w.gov.module("utils.credential_api")
    material = w.mods["credential_material"]
    admin = StubAuth.decorators.requirements[f"{material.__name__}:AdminAPI.put"]
    project = StubAuth.decorators.requirements[f"{material.__name__}:ProjectAPI.put"]
    assert admin["permissions"] == [api.MANAGE, api.SET_OWN_VALUE] and project["permissions"] == [api.SET_OWN_VALUE]
    assert project["recommended_roles"] == api.OWN_VALUE_ROLES
    assert set(material.API.mode_handlers) == {"default", "administration"}
    assert material.API.url_params == ["<int:project_id>/<uuid:ref_id>"]
    mine = StubAuth.decorators.requirements[f"{w.mods['credential_references'].__name__}:ProjectAPI.get"]
    assert mine["permissions"] == [api.SET_OWN_VALUE]
    assert set(w.mods["credential_references"].API.mode_handlers) == {"default", "administration"}
    for handler in (material.ProjectAPI,):   # write-only in this mode too
        assert [verb for verb in ("get", "post", "delete", "patch") if hasattr(handler, verb)] == []


def test_the_own_value_permission_is_recommended_to_every_member_in_default_mode_and_to_admins_otherwise(gov, monkeypatch):
    from unittest.mock import MagicMock  # pylint: disable=C0415
    from fixtures.permissions import effective_roles  # pylint: disable=C0415
    registered = []
    monkeypatch.setattr(StubAuth, "register_permissions", staticmethod(registered.append), raising=False)
    descriptor_ = MagicMock()
    descriptor_.metadata = {}
    gov.module("module").Module(context=MagicMock(), descriptor=descriptor_).init()
    roles = {e["permissions"][0]: effective_roles(e["recommended_roles"]) for e in registered}["credentials.set_own_value"]
    assert roles["default"] == {**roles["default"], "admin": True, "editor": True, "viewer": True, "system": False}
    assert roles["administration"]["admin"] is True and roles["administration"]["editor"] is False
    assert roles["administration"]["viewer"] is False and roles["administration"]["system"] is False


# --- the owner's own list ------------------------------------------------------------------------------------------------------

def mine(w, actor, project=PROJECT, **query):
    return w.call("credential_references", "get", project, actor=actor, handler="ProjectAPI", query_string=query)


def test_the_owner_sees_only_their_own_personal_references(w):
    config = w.gov.configurations.add(PROJECT)
    mine_ref = w.personal(OWNER, config=config)
    w.personal(OTHER_OWNER, config=config)
    w.create(None, config, ownership_class="service")
    w.personal(OWNER)
    body, status = mine(w, OWNER, mine="true")
    assert status == 200 and body["total"] == 2 and mine_ref in {row["id"] for row in body["rows"]}
    assert all(row["ownership_class"] == "personal" and row["owner"]["id"] == OWNER for row in body["rows"])
    other, _ = mine(w, OTHER_OWNER, mine="true")
    assert other["total"] == 1 and other["rows"][0]["owner"]["id"] == OTHER_OWNER
    nobody, _ = mine(w, APPROVER, mine="true")
    assert nobody == {"total": 0, "rows": []}


def test_the_owners_list_is_metadata_without_operators_or_approvals(w):
    ref = w.personal()
    w.lifecycle(ref)
    [row] = mine(w, OWNER, mine="true")[0]["rows"]
    assert set(row) == {"id", "configuration", "provider", "ownership_class", "owner", "store_kind", "state", "generation",
                        "validated", "configuration_changed", "expires_at", "created_at", "updated_at",
                        "auth_mode", "delegation"}   # the kind and its descriptor (#6756 step 4)
    assert row["state"] == "active"
    text = json.dumps(row)
    for hidden in ("u10@x.test", "u20@x.test", "approval", "policy", "written_by", OWNER_SUBJECT, "store_locator", SECRET):
        assert hidden not in text


@pytest.mark.parametrize("query", [{}, {"mine": "false"}, {"mine": "1"}, {"mine": "TRUE"}])
def test_the_owners_list_needs_mine_true(w, query):
    w.personal()
    body, status = mine(w, OWNER, **query)
    assert (status, body["code"]) == (400, "INVALID_REQUEST")


def test_the_owners_list_cannot_be_widened_by_the_filters_it_shares_with_the_operator_list(w):
    w.personal(OTHER_OWNER)
    body, _ = mine(w, OWNER, mine="true", owner_user_id=str(OTHER_OWNER), ownership_class="service")
    assert body == {"total": 0, "rows": []}
    assert mine(w, OWNER, mine="true", owner_user_id="x")[1] == 400   # still a validated filter


def test_the_owners_list_is_per_project_and_needs_a_signed_in_user(w):
    w.personal()
    assert mine(w, OWNER, project=OTHER_PROJECT, mine="true")[0] == {"total": 0, "rows": []}
    assert mine(w, 0, mine="true")[1] == 400


def test_the_administration_list_is_unchanged_and_still_shows_everything(w):
    w.personal(OWNER)
    w.personal(OTHER_OWNER)
    body, status = w.call("credential_references", "get", PROJECT)
    assert status == 200 and body["total"] == 2 and "written_by" in body["rows"][0]


# --- the secret-field-path cache (perf review 2026-10-21, S2) ---------------------------------------------------------

def test_the_secret_fields_of_a_type_are_asked_once_until_the_registry_changes(w):
    configurations = w.gov.configurations
    ref = w.personal()
    assert w.put(ref, {"api_key": SECRET})[1] == 200
    assert w.put(ref, {"api_key": SECRET_2}, expected_generation=1)[1] == 200
    assert w.put(ref, {"api_key": SECRET}, expected_generation=2)[1] == 200
    assert configurations.secret_fields_calls == [["api_cred"]]
    configurations.registry_version += 1
    configurations.secret_paths["api_cred"] = ["api_key", "token"]
    assert w.put(ref, {"token": SECRET}, expected_generation=3)[1] == 200   # the changed schema is seen at once
    assert configurations.secret_fields_calls == [["api_cred"], ["api_cred"]]


def test_an_unknown_type_and_a_failing_service_are_not_remembered(w):
    configurations = w.gov.configurations
    ref = w.personal()
    configurations.secret_paths.clear()
    assert w.put(ref)[1] == 400 and w.put(ref)[1] == 400
    configurations.secret_paths["api_cred"] = ["api_key"]
    assert w.put(ref)[1] == 200                                             # the type is known now, same version
    configurations.registry_version += 1
    configurations.secret_fields_error = RuntimeError("down")
    assert w.put(ref, expected_generation=1)[1] == 503
    configurations.secret_fields_error = None
    assert w.put(ref, expected_generation=1)[1] == 200


def test_without_a_registry_version_the_paths_are_asked_every_time(w, monkeypatch):
    configurations = w.gov.configurations
    monkeypatch.setattr(type(configurations), "configuration_registry_version", None)   # an older configurations plugin
    ref = w.personal()
    assert w.put(ref)[1] == 200 and w.put(ref, expected_generation=1)[1] == 200
    assert configurations.secret_fields_calls == [["api_cred"], ["api_cred"]]


# --- old generations are pruned when a new one goes live (review of the perf PR) ----------------------------------------

def _rotate(w, ref, generation, value):
    assert w.action(ref, "suspend")[1] == 200
    assert w.put(ref, {"api_key": value}, expected_generation=generation)[1] == 200
    assert w.action(ref, "probe", actor=CREATOR)[1] == 200
    assert w.action(ref, "approve", actor=APPROVER, approval_ref="CHG-2", policy_revision="rev-2")[1] == 200
    assert w.action(ref, "activate", actor=APPROVER)[1] == 200


def test_three_rotations_leave_the_two_newest_generations_in_the_store(w):
    ref = w.personal()
    w.lifecycle(ref)
    for generation, value in ((1, "fixture-rot-2"), (2, "fixture-rot-3"), (3, "fixture-rot-4")):
        _rotate(w, ref, generation, value)
    assert w.row(ref).generation == 4 and w.row(ref).state == "active"
    assert w.store().versions[uuid.UUID(ref)] == {3: {"api_key": "fixture-rot-3"}, 4: {"api_key": "fixture-rot-4"}}
    started = [call for call in w.store().calls if call[0] == "prune"]
    assert [call[1] for call in started] == ["reconcile", "reconcile"]   # the port allows prune to retire|reconcile only
    activations = [e["event_id"] for e in w.events() if e["reason_code"] == "CREDENTIAL_REF_ACTIVE"]
    assert [call[2] for call in started] == activations[2:]   # the activation event is the decision id (g3 and g4 prune)


def test_generations_staged_above_the_live_one_stop_a_prune_and_are_never_counted(w):
    ref_id = w.gov.add_reference(PROJECT, state="validated", generation=3, validated_generation=3, approved_by=20,
                                 approval_ref="CHG-1", policy_revision="rev-1", ownership_class="service")
    w.store().versions[ref_id] = {n: {"api_key": f"fixture-{n}"} for n in (1, 2, 3, 4, 5)}   # 4 and 5 are staged
    assert w.action(ref_id, "activate", actor=APPROVER)[1] == 200
    assert sorted(w.store().versions[ref_id]) == [1, 2, 3, 4, 5]
    assert [call[0] for call in w.store().calls] == ["metadata"]
    w.store().versions[ref_id] = {n: {"api_key": f"fixture-{n}"} for n in (1, 2, 3)}   # nothing above: now it prunes
    assert w.onboarding.prune_superseded(w.row(ref_id), 3, CREATOR, str(uuid.uuid4())) is True
    assert sorted(w.store().versions[ref_id]) == [2, 3]


def test_a_failing_prune_leaves_the_activation_as_it_was(w):
    ref_id = w.gov.add_reference(PROJECT, state="validated", generation=3, validated_generation=3, approved_by=20,
                                 approval_ref="CHG-1", policy_revision="rev-1", ownership_class="service")
    w.store().versions[ref_id] = {n: {"api_key": f"fixture-{n}"} for n in (1, 2, 3)}
    w.store().prune = lambda *a, **k: (_ for _ in ()).throw(w.gov.stores.StoreError("UNAVAILABLE"))
    reply = w.action(ref_id, "activate", actor=APPROVER)
    assert reply[1] == 200 and w.row(ref_id).state == "active" and sorted(w.store().versions[ref_id]) == [1, 2, 3]
