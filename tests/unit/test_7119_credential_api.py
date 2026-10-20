"""C-1009 (#7119): the operator REST API for credential references and use grants.

The handlers run for real (Flask request context, the real services over SQLite); the collaborators are the same
fakes the task tests use, plus a small identity service and a permission switch. ``check_api`` itself cannot run
here: what each endpoint declares to it is asserted from the recorded descriptors, and the per-action permission
the handlers check themselves is exercised with the permission set the fake hands out.
"""
import json
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask

from fixtures.api_loader import load_api_module
from fixtures.governance import APPLICATION, BINDING, FIXTURE_VALUE, TOOL, TOOL_MAPPING, VERSION
from run_tests import StubAuth, StubLog

app = Flask(__name__)
MODULES = ("credential_references", "credential_reference", "credential_reference_action", "credential_grants",
           "credential_grant_action")
CREATOR, APPROVER, MEMBER, UNLINKED = 10, 20, 30, 40
ALL_PERMISSIONS = {"credentials.view", "credentials.manage", "credentials.probe", "credentials.approve"}
TOOLKIT = 41
P1, P2 = 1, 2


def user(user_id, email, tid="t1", oid=None):
    return {"id": user_id, "email": email, "name": email, "idp_issuer": "https://issuer.test" if tid else None,
            "idp_tid": tid, "idp_oid": oid if tid else None}


class Rest:
    """Calls the handlers like the route does, and owns the fake identity service."""

    def __init__(self, gov, monkeypatch):
        self.gov, self.monkeypatch = gov, monkeypatch
        self.mods = {name: load_api_module(name) for name in MODULES}
        self.users = {
            CREATOR: user(CREATOR, "creator@x.test", oid="o10"), APPROVER: user(APPROVER, "approver@x.test", oid="o20"),
            MEMBER: user(MEMBER, "member@x.test", oid="o30"), UNLINKED: user(UNLINKED, "unlinked@x.test", tid=None),
        }
        self.members = [CREATOR, APPROVER, MEMBER, UNLINKED]
        self.permissions = set(ALL_PERMISSIONS)
        self.permission_calls = []
        self.identity_down = False
        self.onboarding = gov.module("utils.credential_onboarding")
        self.grants = gov.module("utils.credential_grants")
        self.set_actor(CREATOR)
        self._install_auth()

    def set_actor(self, actor):
        self.monkeypatch.setattr(StubAuth, "user", {"id": actor} if actor else {})

    def _install_auth(self):
        def get_user(user_id=None, **_kw):
            if self.identity_down:
                raise ConnectionError("down")
            if user_id not in self.users:
                raise RuntimeError("No such user found")
            return dict(self.users[user_id])

        def list_users(user_ids=None):
            if self.identity_down:
                raise ConnectionError("down")
            return [dict(self.users[i]) for i in (user_ids or self.users) if i in self.users]

        def resolve_permissions(mode="administration", project_id=None, **_kw):
            self.permission_calls.append((mode, project_id))
            if self.permissions is None:
                raise RuntimeError("auth down")
            return set(self.permissions)

        for name, func in dict(
                get_user=get_user, list_users=list_users, resolve_permissions=resolve_permissions,
                list_project_user_roles=lambda project_id: [{"user_id": i, "role_id": 1} for i in self.members],
                has_access=lambda current, required: bool(set(required) & set(current))).items():
            self.monkeypatch.setattr(StubAuth, name, staticmethod(func), raising=False)

    def call(self, name, verb, *path, body=None, raw=None, query=None, actor=None):
        self.set_actor(CREATOR if actor is None else actor)
        kwargs = {"method": "GET" if verb == "get" else "POST", "query_string": query or {}}
        if raw is not None:
            kwargs.update(data=raw, content_type="application/json")
        elif body is not None:
            kwargs["json"] = body
        with app.test_request_context(**kwargs):
            handler = self.mods[name].AdminAPI(api=types.SimpleNamespace(module=None), mode="administration")
            return getattr(handler, verb)(*path)

    # -- references
    def list_refs(self, project=P1, **query):
        return self.call("credential_references", "get", project, query=query)

    def get_ref(self, ref_id, project=P1):
        return self.call("credential_reference", "get", project, uuid.UUID(str(ref_id)))

    def create_ref(self, project=P1, configuration=None, actor=None, **overrides):
        configuration = configuration or self.gov.configurations.add(project)
        body = {"configuration_uuid": configuration.uuid, "store_kind": "database", "ownership_class": "service"}
        body.update(overrides)
        return self.call("credential_references", "post", project, body=body, actor=actor)

    def ref_action(self, ref_id, action, project=P1, actor=None, **fields):
        return self.call("credential_reference_action", "post", project, uuid.UUID(str(ref_id)),
                         body={"action": action, **fields}, actor=actor)

    def approve_ref(self, ref_id, project=P1, actor=APPROVER):
        return self.ref_action(ref_id, "approve", project, actor, approval_ref="CHG-1", policy_revision="rev-1")

    def new_ref(self, project=P1, until="pending", **kw):
        """A reference taken through the lifecycle to ``until`` (pending, validated, approved, active)."""
        body, status = self.create_ref(project, **kw)
        assert status == 201, body
        ref_id = body["id"]
        steps = ["import", "probe", "approve", "activate"]
        for step in steps[:{"pending": 0, "imported": 1, "validated": 2, "approved": 3, "active": 4}[until]]:
            reply = self.approve_ref(ref_id, project) if step == "approve" else self.ref_action(ref_id, step, project)
            assert reply[1] == 200, reply
        return ref_id

    # -- grants
    def seed_binding(self, project=P1, application_id=5, version_id=9, tools=(TOOLKIT,)):
        binding_ref = uuid.uuid4()
        with self.gov.db.get_session(project) as session:
            session.execute(BINDING.insert().values(
                id=binding_ref, project_id=project, application_id=application_id, version_id=version_id))
            session.execute(APPLICATION.insert().values(id=application_id, name=f"Agent {application_id}"))
            session.execute(VERSION.insert().values(id=version_id, name=f"v{version_id}"))
            for tool_id in tools:
                session.execute(TOOL_MAPPING.insert().values(tool_id=tool_id, entity_version_id=version_id,
                                                             entity_type="agent"))
                session.execute(TOOL.insert().values(id=tool_id, type="jira", name=f"jira-{tool_id}"))
            session.commit()
        return str(binding_ref)

    def create_grant(self, binding, ref, project=P1, subject_user_id=MEMBER, actor=None, toolkit_id=TOOLKIT, **extra):
        body = {"agent_binding_ref": binding, "toolkit_id": toolkit_id, "credential_ref": ref,
                "subject_user_id": subject_user_id, **extra}
        return self.call("credential_grants", "post", project, body=body, actor=actor)

    def grant_action(self, grant_id, action, project=P1, actor=None, **fields):
        return self.call("credential_grant_action", "post", project, uuid.UUID(str(grant_id)),
                         body={"action": action, **fields}, actor=actor)

    def list_grants(self, project=P1, **query):
        return self.call("credential_grants", "get", project, query=query)

    def events(self, project=P1):
        return self.gov.db.events(project)


@pytest.fixture
def rest(gov, monkeypatch):
    return Rest(gov, monkeypatch)


def normalized(events):
    """Events without the ids that differ between two projects."""
    drop = {"event_id", "credential_ref", "project_id", "agent_binding_ref"}
    return [{key: value for key, value in event.items() if key not in drop} for event in events]


REFERENCE_ROW_KEYS = {
    "id", "configuration", "provider", "ownership_class", "owner", "store_kind", "state", "generation", "validated",
    "configuration_changed", "approval_ref", "policy_revision", "created_by", "approved_by", "expires_at",
    "created_at", "updated_at"}
GRANT_ROW_KEYS = {
    "id", "binding", "toolkit", "credential", "subject", "state", "valid_from", "valid_until", "approval_ref",
    "created_by", "approved_by", "revocation_epoch"}


# --- the tasks still behave as before (regression) ------------------------------------------------------------

def test_the_reference_task_is_parse_then_run_and_keeps_its_outputs(rest):
    onboarding, config = rest.onboarding, rest.gov.configurations.add(P1)
    param = f"project_id={P1};action=create;configuration_uuid={config.uuid};store_kind=database;ownership_class=service"
    assert onboarding.manage_reference(param + ";dry_run", 0) == {
        "dry_run": True, "action": "create", "state": "pending", "provider": "api_cred"}
    values, _ = onboarding.parse_reference_param(param + ";dry_run")
    assert onboarding.run_reference_action(values, 0) == onboarding.manage_reference(param + ";dry_run", 0)
    created = onboarding.manage_reference(param, CREATOR)
    assert created == {"action": "create", "reference": created["reference"], "state": "pending", "dry_run": False}
    parse_error = onboarding.manage_reference("nonsense", CREATOR)
    assert set(parse_error) == {"error"} and parse_error["error"].startswith("unknown parameter 'nonsense'")
    assert onboarding.manage_reference(param, 0) == {
        "error": "ACTOR_REQUIRED: This action needs an identified operator.", "code": "ACTOR_REQUIRED"}


def test_the_grant_task_is_parse_then_run_and_keeps_its_outputs(rest):
    binding, ref = rest.seed_binding(), str(rest.gov.add_reference(P1, state="active"))
    param = f"project_id={P1};action=create;binding_ref={binding};toolkit_id={TOOLKIT};ref={ref};subject_ref=idp:t1:o30"
    created = rest.grants.manage_grant(param, CREATOR)
    assert created == {"action": "create", "grant": created["grant"], "state": "pending_approval", "dry_run": False}
    assert rest.grants.manage_grant(param.replace("create", "approve") + ";approval_ref=A;policy_revision=B", CREATOR) == {
        "error": "SELF_APPROVAL: The creator of a record cannot approve it.", "code": "SELF_APPROVAL"}
    assert rest.grants.manage_grant("nonsense", CREATOR)["error"].startswith("unknown parameter")


def test_valid_until_is_checked_by_one_function_for_the_task_and_the_api(rest):
    soon = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert rest.grants.parse_valid_until(soon)[1] is None
    assert rest.grants.parse_valid_until("tomorrow") == (None, "format")
    assert rest.grants.parse_valid_until("2020-01-01T00:00:00+00:00") == (None, "range")
    assert rest.grants.parse_valid_until("2999-01-01T00:00:00") == (None, "range")  # no offset
    assert rest.grants.parse_grant_param("project_id=1;action=create;binding_ref=" + str(uuid.uuid4())
                                         + ";toolkit_id=1;ref=" + str(uuid.uuid4()) + ";subject_ref=idp:a:b;valid_until=tomorrow") == (
        None, "invalid valid_until: 'tomorrow'")


# --- every action through REST writes what the task writes -------------------------------------------------------

def test_the_reference_lifecycle_over_rest_writes_the_same_audit_events_as_the_task(rest):
    onboarding, gov = rest.onboarding, rest.gov
    config = gov.configurations.add(P1)
    task = lambda param, actor: onboarding.manage_reference(f"project_id={P1};{param}", actor)  # noqa: E731
    created = task(f"action=create;configuration_uuid={config.uuid};store_kind=database;ownership_class=service", CREATOR)
    ref = created["reference"]
    for step, actor in (("import", CREATOR), ("probe", CREATOR)):
        assert "error" not in task(f"action={step};ref={ref}", actor)
    assert "error" not in task(f"action=approve;ref={ref};approval_ref=CHG-1;policy_revision=rev-1", APPROVER)
    for step in ("activate", "suspend", "resume", "retire"):
        assert "error" not in task(f"action={step};ref={ref}", CREATOR)
    #
    bodies = []
    config2 = gov.configurations.add(P2)
    body, status = rest.create_ref(P2, config2)
    bodies.append((status, body))
    ref2 = body["id"]
    for step, actor in (("import", CREATOR), ("probe", CREATOR)):
        bodies.append(rest.ref_action(ref2, step, P2, actor)[::-1])
    bodies.append(rest.approve_ref(ref2, P2, APPROVER)[::-1])
    for step in ("activate", "suspend", "resume", "retire"):
        bodies.append(rest.ref_action(ref2, step, P2, CREATOR)[::-1])
    assert [status for status, _ in bodies] == [201] + [200] * 7
    assert all(body["ok"] is True for _, body in bodies)
    assert len(rest.events(P1)) >= 10
    assert normalized(rest.events(P2)) == normalized(rest.events(P1))
    assert gov.reference(P2, uuid.UUID(ref2)).state == gov.reference(P1, uuid.UUID(ref)).state == "retired"
    assert gov.reference(P2, uuid.UUID(ref2)).generation == gov.reference(P1, uuid.UUID(ref)).generation == 1


def test_the_grant_lifecycle_over_rest_writes_the_same_audit_events_as_the_task(rest):
    gov = rest.gov
    results = {}
    for project, via in ((P1, "task"), (P2, "rest")):
        binding, ref = rest.seed_binding(project), str(gov.add_reference(project, state="active"))
        if via == "task":
            key = f"project_id={project};binding_ref={binding};toolkit_id={TOOLKIT};ref={ref};subject_ref=idp:t1:o30"
            created = rest.grants.manage_grant(f"{key};action=create", CREATOR)
            outcomes = [created]
            outcomes.append(rest.grants.manage_grant(f"{key};action=approve;approval_ref=CHG-2;policy_revision=rev-2", APPROVER))
            outcomes += [rest.grants.manage_grant(f"{key};action={step}", CREATOR) for step in ("suspend", "resume", "revoke")]
            assert all("error" not in outcome for outcome in outcomes), outcomes
        else:
            body, status = rest.create_grant(binding, ref, project)
            assert status == 201 and body["state"] == "pending_approval", body
            replies = [rest.grant_action(body["id"], "approve", project, APPROVER, approval_ref="CHG-2", policy_revision="rev-2")]
            replies += [rest.grant_action(body["id"], step, project, CREATOR) for step in ("suspend", "resume", "revoke")]
            assert [reply[1] for reply in replies] == [200] * 4, replies
            assert [reply[0]["state"] for reply in replies] == ["active", "suspended", "active", "revoked"]
        results[project] = normalized(rest.events(project))
    assert len(results[P1]) == 5 and results[P2] == results[P1]


def test_the_replies_are_the_task_results_reshaped(rest):
    body, status = rest.create_ref()
    assert status == 201 and body == {"ok": True, "action": "create", "id": body["id"], "state": "pending"}
    imported = rest.ref_action(body["id"], "import")
    assert imported == ({"ok": True, "action": "import", "id": body["id"], "generation": 1, "state": "pending"}, 200)
    assert rest.ref_action(body["id"], "probe")[0] == {
        "ok": True, "action": "probe", "id": body["id"], "generation": 1, "state": "validated"}
    assert rest.approve_ref(body["id"])[0] == {
        "ok": True, "action": "approve", "id": body["id"], "state": "validated", "approved": True}
    assert rest.ref_action(body["id"], "activate")[0] == {"ok": True, "action": "activate", "id": body["id"], "state": "active"}
    assert rest.ref_action(body["id"], "retire")[0] == {
        "ok": True, "action": "retire", "id": body["id"], "state": "retired", "material_deleted": True}


def test_a_failed_probe_is_a_readable_conflict_and_leaves_its_audit_event(rest):
    ref = rest.new_ref(until="imported")
    rest.gov.configurations.edit_secret(next(iter(rest.gov.configurations.rows[P1].values())), api_key="changed")
    body, status = rest.ref_action(ref, "probe")
    assert status == 409 and body == {"error": "The stored material does not match the configuration.",
                                      "code": "MATERIAL_MISMATCH"}
    assert [e["reason_code"] for e in rest.events() if e["event_type"] == "probe"] == ["MATERIAL_MISMATCH"]
    assert "CREDENTIAL_PROBE_STARTED" in [e["reason_code"] for e in rest.events()]


def test_a_store_outage_is_a_503_with_the_stores_own_code(rest):
    rest.gov.stores.unavailable.add("database")
    body, status = rest.create_ref()
    assert status == 503 and body["code"] == "STORE_UNAVAILABLE" and body["error"] == "The secret store is unavailable."
    assert rest.gov.db.events(P1) == []


# --- lists ---------------------------------------------------------------------------------------------------

def test_the_reference_list_is_per_project_with_a_total(rest):
    mine = [rest.new_ref(P1) for _ in range(3)]
    rest.new_ref(P2)
    body, status = rest.list_refs(P1)
    assert status == 200 and body["total"] == 3 and {row["id"] for row in body["rows"]} == set(mine)
    assert rest.list_refs(P2)[0]["total"] == 1


def test_the_reference_list_filters_by_state_class_store_and_owner(rest):
    pending = rest.new_ref(P1)
    active = rest.new_ref(P1, until="active", ownership_class="project_shared")
    ids = lambda **q: {row["id"] for row in rest.list_refs(P1, **q)[0]["rows"]}  # noqa: E731
    assert ids(state="active") == {active} and ids(state="pending") == {pending}
    assert ids(ownership_class="project_shared") == {active} and ids(ownership_class="service") == {pending}
    assert ids(store_kind="database") == {pending, active} and ids(store_kind="corporate_vault") == set()
    owned = str(rest.gov.add_reference(P1, custodian_ref={"user_id": MEMBER, "subject_ref": "idp:t1:o30"},
                                       ownership_class="personal"))
    assert ids(owner_user_id=MEMBER) == {owned} and ids(owner_user_id=UNLINKED) == set()
    assert ids(state="active", ownership_class="service") == set()


def test_pagination_caps_the_limit_and_whitelists_the_sort(rest):
    names = ("a_cfg", "b_cfg", "c_cfg", "d_cfg", "e_cfg")
    ids = {rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, type_=name)): name for name in names}
    pages = [rest.list_refs(P1, limit=2, offset=offset, sort_by="provider")[0] for offset in (0, 2, 4)]
    assert [page["total"] for page in pages] == [5, 5, 5]
    assert [row["provider"] for page in pages for row in page["rows"]] == sorted(ids.values(), reverse=True)  # newest-first default order is by sort_order
    asc = rest.list_refs(P1, sort_by="provider", sort_order="asc")[0]["rows"]
    assert [row["provider"] for row in asc] == list(names)
    page = rest.mods["credential_references"].api.parse_page
    assert page({"limit": "100000"}, {"state": 1}).limit == 100
    assert page({"limit": "0"}, {}).limit == 1 and page({"limit": "abc", "offset": "-4"}, {}).limit == 20
    assert page({"offset": "-4"}, {}).offset == 0
    assert page({"sort_by": "store_locator"}, {"state": 1}).sort_by == "updated_at"
    assert page({"sort_by": "state", "sort_order": "sideways"}, {"state": 1}) == (20, 0, None, "state", "desc")
    assert rest.list_refs(P1, sort_by="store_locator")[1] == 200  # unknown sort column: the default, not an error
    assert rest.list_refs(P1, limit=100000)[0]["total"] == 5


def test_search_is_a_literal_case_insensitive_match_on_the_provider(rest):
    rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, type_="GitHub_cfg"))
    rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, type_="jira"))
    rows = lambda search: rest.list_refs(P1, search=search)[0]["rows"]  # noqa: E731
    assert [row["provider"] for row in rows("github")] == ["GitHub_cfg"]
    assert rows("%") == [] and rows("_") != [] and len(rows("_")) == 1 and rows("\\") == []
    assert rest.list_refs(P1, search="x" * 129) == ({"error": "The request is not valid.", "code": "INVALID_REQUEST"}, 400)


@pytest.mark.parametrize("query", [
    {"state": "bogus"}, {"ownership_class": "bogus"}, {"store_kind": "bogus"}, {"owner_user_id": "abc"},
    {"owner_user_id": "0"}])
def test_an_invalid_reference_filter_is_a_400(rest, query):
    assert rest.list_refs(P1, **query) == ({"error": "The request is not valid.", "code": "INVALID_REQUEST"}, 400)


def test_a_reference_row_names_its_people_and_flags_a_changed_configuration(rest):
    config = rest.gov.configurations.add(P1, title="GitHub prod")
    ref = rest.new_ref(P1, until="approved", configuration=config)
    row = rest.list_refs(P1)[0]["rows"][0]
    assert set(row) == REFERENCE_ROW_KEYS and row["id"] == ref
    assert row["configuration"] == {"uuid": config.uuid, "title": "GitHub prod"}
    assert row["created_by"] == {"id": CREATOR, "email": "creator@x.test"}
    assert row["approved_by"] == {"id": APPROVER, "email": "approver@x.test"} and row["owner"] is None
    assert row["validated"] is True and row["configuration_changed"] is False and row["generation"] == 1
    assert (row["state"], row["store_kind"], row["ownership_class"]) == ("validated", "database", "service")
    assert (row["approval_ref"], row["policy_revision"]) == ("CHG-1", "rev-1")
    rest.gov.configurations.edit_secret(config, api_key="rotated")
    assert rest.list_refs(P1)[0]["rows"][0]["configuration_changed"] is True


def test_the_list_survives_services_that_do_not_answer(rest):
    rest.new_ref(P1)
    rest.identity_down = True
    del rest.gov.this.modules["configurations"]
    body, status = rest.list_refs(P1)
    row = body["rows"][0]
    assert status == 200 and row["created_by"] == {"id": CREATOR, "email": None}
    assert row["configuration"]["title"] is None and row["configuration_changed"] is None


def test_the_reference_detail_counts_live_grants_and_shows_a_write_in_flight(rest):
    ref = rest.new_ref(P1, until="active")
    binding = rest.seed_binding()
    first = rest.create_grant(binding, ref)[0]["id"]
    rest.create_grant(binding, ref, subject_user_id=APPROVER)
    rest.grant_action(first, "revoke")
    body, status = rest.get_ref(ref)
    assert status == 200 and set(body) == REFERENCE_ROW_KEYS | {"grants_count", "ledger_in_flight"}
    assert body["grants_count"] == 1 and body["ledger_in_flight"] is False
    rest.gov.add_ledger(P1, uuid.UUID(ref), 2, state="written")
    assert rest.get_ref(ref)[0]["ledger_in_flight"] is True


def test_the_grant_list_names_binding_toolkit_credential_and_subject(rest):
    ref = rest.new_ref(P1, until="active", configuration=rest.gov.configurations.add(P1, title="Jira prod"))
    binding = rest.seed_binding()
    created = rest.create_grant(binding, ref)[0]["id"]
    rest.grant_action(created, "approve", actor=APPROVER, approval_ref="CHG-9", policy_revision="rev-9")
    body, status = rest.list_grants()
    (row,) = body["rows"]
    assert status == 200 and body["total"] == 1 and set(row) == GRANT_ROW_KEYS and row["id"] == created
    assert row["binding"] == {"id": binding, "application_name": "Agent 5", "version_name": "v9"}
    assert row["toolkit"] == {"id": str(TOOLKIT), "name": "jira-41", "type": "jira"}
    assert row["credential"] == {"id": ref, "provider": "api_cred", "configuration_title": "Jira prod",
                                 "ownership_class": "service"}
    assert row["subject"] == {"ref": "idp:t1:o30", "user": {"id": MEMBER, "email": "member@x.test"}}
    assert row["created_by"]["id"] == CREATOR and row["approved_by"]["id"] == APPROVER
    assert row["state"] == "active" and row["approval_ref"] == "CHG-9" and row["revocation_epoch"] == 0


def test_the_grant_list_filters_per_project_and_per_user(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    other_ref, other_binding = rest.new_ref(P2, until="active"), rest.seed_binding(P2)
    mine = rest.create_grant(binding, ref, subject_user_id=MEMBER)[0]["id"]
    theirs = rest.create_grant(binding, ref, subject_user_id=APPROVER)[0]["id"]
    foreign = rest.create_grant(other_binding, other_ref, P2, subject_user_id=MEMBER)[0]["id"]
    ids = lambda project=P1, **q: {row["id"] for row in rest.list_grants(project, **q)[0]["rows"]}  # noqa: E731
    assert ids() == {mine, theirs} and ids(P2) == {foreign}
    assert ids(subject_user_id=MEMBER) == {mine} and ids(subject_user_id=APPROVER) == {theirs}
    assert ids(P2, subject_user_id=MEMBER) == {foreign}
    assert ids(subject_user_id=UNLINKED) == set() and ids(subject_user_id=999) == set()  # cannot hold a grant
    assert ids(state="pending_approval") == {mine, theirs} and ids(state="active") == set()
    assert ids(agent_binding_ref=binding) == {mine, theirs} and ids(agent_binding_ref=str(uuid.uuid4())) == set()
    assert ids(credential_ref=ref) == {mine, theirs} and ids(toolkit_id=TOOLKIT) == {mine, theirs}
    assert ids(toolkit_id=7) == set()
    rest.grant_action(mine, "revoke")
    assert ids(state="revoked") == {mine}
    assert rest.list_grants(subject_user_id=MEMBER, limit=1, offset=1)[0] == {"total": 1, "rows": []}


def test_a_mandate_subject_or_a_non_member_has_no_user(rest):
    ref, binding = str(rest.gov.add_reference(P1, state="active")), rest.seed_binding()
    for subject in (f"mandate:{uuid.uuid4()}", "idp:t9:stranger"):
        rest.gov.add_grant(P1, credential_ref=uuid.UUID(ref), agent_binding_ref=uuid.UUID(binding), subject_ref=subject)
    rows = rest.list_grants()[0]["rows"]
    assert len(rows) == 2 and all(row["subject"]["user"] is None for row in rows)
    assert {row["subject"]["ref"][:6] for row in rows} == {"mandat", "idp:t9"}


def test_grant_search_matches_the_subject_or_the_approval_literally(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    member = rest.create_grant(binding, ref, subject_user_id=MEMBER)[0]["id"]
    other = rest.create_grant(binding, ref, subject_user_id=APPROVER)[0]["id"]
    rest.grant_action(other, "approve", actor=APPROVER, approval_ref="CHG-777", policy_revision="rev")
    ids = lambda search: {row["id"] for row in rest.list_grants(search=search)[0]["rows"]}  # noqa: E731
    assert ids("o30") == {member} and ids("O20") == {other} and ids("chg-777") == {other}
    assert ids("%") == set() and ids("idp:t1") == {member, other}


@pytest.mark.parametrize("query", [{"state": "bogus"}, {"agent_binding_ref": "x"}, {"credential_ref": "1"},
                                   {"toolkit_id": "-1"}, {"subject_user_id": "x"}])
def test_an_invalid_grant_filter_is_a_400(rest, query):
    assert rest.list_grants(**query)[1] == 400


def test_no_response_carries_a_store_locator_or_custody_record(rest):
    marker = "LOCATOR-MARKER-7119"
    ref = str(rest.gov.add_reference(P1, state="active", store_locator={"section": marker, "mount": marker},
                                     pending_generation=None, custodian_ref={"user_id": MEMBER, "locator": marker}))
    binding = rest.seed_binding()
    grant = rest.create_grant(binding, ref)[0]["id"]
    replies = [rest.list_refs(), rest.get_ref(ref), rest.list_grants(), rest.ref_action(ref, "suspend"),
               rest.ref_action(ref, "resume"), rest.grant_action(grant, "revoke")]
    blob = json.dumps(replies, default=str)
    assert marker not in blob
    for forbidden in ("store_locator", "locator", "pending_generation", "custodian", "section", "mount"):
        assert forbidden not in blob, forbidden
    # the snapshot of what a reference row and a grant row may hold
    assert set(replies[0][0]["rows"][0]) == REFERENCE_ROW_KEYS and set(replies[2][0]["rows"][0]) == GRANT_ROW_KEYS
    assert set(replies[1][0]) == REFERENCE_ROW_KEYS | {"grants_count", "ledger_in_flight"}
    assert replies[0][0]["rows"][0]["owner"] == {"id": MEMBER, "email": "member@x.test"}


def test_the_queries_select_an_explicit_list_of_columns(rest):
    queries = rest.gov.module("utils.credential_queries")
    columns = {column.key for column in queries._REFERENCE_COLUMNS} | {column.key for column in queries._GRANT_COLUMNS}  # pylint: disable=W0212
    assert not columns & {"store_locator", "pending_generation", "target_ref", "resource_constraints", "obligations"}
    assert "custodian_ref" in columns  # read to name the owner, never returned as is


# --- request validation --------------------------------------------------------------------------------------

BAD_REQUEST = ({"error": "The request is not valid.", "code": "INVALID_REQUEST"}, 400)


def test_a_raw_subject_ref_in_the_body_is_a_400_and_writes_nothing(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    before = len(rest.events())
    body = {"agent_binding_ref": binding, "toolkit_id": TOOLKIT, "credential_ref": ref, "subject_ref": "idp:t1:o30"}
    assert rest.call("credential_grants", "post", P1, body=body) == BAD_REQUEST
    body["subject_user_id"] = MEMBER  # the user is named by id as well: still refused while subject_ref is present
    assert rest.call("credential_grants", "post", P1, body=body) == BAD_REQUEST
    assert rest.list_grants()[0]["total"] == 0 and len(rest.events()) == before


@pytest.mark.parametrize("change", [
    {"toolkit_id": "41"}, {"toolkit_id": True}, {"toolkit_id": 0}, {"toolkit_id": 4.5}, {"subject_user_id": "30"},
    {"subject_user_id": -1}, {"agent_binding_ref": "nope"}, {"credential_ref": 7}, {"valid_until": "tomorrow"},
    {"valid_until": "2020-01-01T00:00:00+00:00"}, {"valid_until": 5}, {"mandate_ref": "x"}, {"state": "active"},
    {"created_by": 1}])
def test_a_malformed_grant_body_is_a_400(rest, change):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    assert rest.create_grant(binding, ref, **change) == BAD_REQUEST
    assert rest.list_grants()[0]["total"] == 0


@pytest.mark.parametrize("change", [
    {"store_kind": "managed_vault"}, {"store_kind": 1}, {"ownership_class": "personal"}, {"ownership_class": "scheduled"},
    {"configuration_uuid": "nope"}, {"owner_user_id": MEMBER}, {"state": "active"}, {"store_locator": {"a": 1}},
    {"dry_run": True}])
def test_a_malformed_reference_body_is_a_400(rest, change):
    assert rest.create_ref(**change) == BAD_REQUEST
    assert rest.list_refs()[0]["total"] == 0


def test_the_body_must_be_a_json_object_within_the_size_bound(rest):
    path = (P1,)
    assert rest.call("credential_references", "post", *path, raw=b"") == BAD_REQUEST
    assert rest.call("credential_references", "post", *path, raw=b"{not json") == BAD_REQUEST
    assert rest.call("credential_references", "post", *path, raw=b"[1, 2]") == BAD_REQUEST
    assert rest.call("credential_references", "post", *path, raw=b"null") == BAD_REQUEST
    assert rest.call("credential_references", "post", *path, raw=b"[" * 5000) == BAD_REQUEST
    big = json.dumps({"configuration_uuid": "x" * 9000}).encode()
    assert rest.call("credential_references", "post", *path, raw=big) == (
        {"error": "The request is too large.", "code": "REQUEST_TOO_LARGE"}, 413)
    assert rest.list_refs()[0]["total"] == 0


@pytest.mark.parametrize("action, fields", [
    ("create", {}), ("bogus", {}), ("approve", {}), ("approve", {"approval_ref": "A"}),
    ("approve", {"approval_ref": " ", "policy_revision": "B"}), ("approve", {"approval_ref": "x" * 129, "policy_revision": "B"}),
    ("suspend", {"approval_ref": "A", "policy_revision": "B"}), ("probe", {"check_connection": True}),
    ("import", {"dry_run": True}), (None, {})])
def test_a_malformed_reference_action_is_a_400_and_changes_nothing(rest, action, fields):
    ref = rest.new_ref(P1, until="validated")
    before = (rest.gov.reference(P1, uuid.UUID(ref)).state, len(rest.events()))
    body = {"action": action, **fields} if action is not None else {}
    assert rest.call("credential_reference_action", "post", P1, uuid.UUID(ref), body=body) == BAD_REQUEST
    assert (rest.gov.reference(P1, uuid.UUID(ref)).state, len(rest.events())) == before


@pytest.mark.parametrize("action, fields", [
    ("create", {}), ("approve", {}), ("revoke", {"approval_ref": "A", "policy_revision": "B"}),
    ("approve", {"approval_ref": "A", "policy_revision": "B", "subject_ref": "idp:t1:o30"}), ("delete", {})])
def test_a_malformed_grant_action_is_a_400(rest, action, fields):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    grant = rest.create_grant(binding, ref)[0]["id"]
    assert rest.grant_action(grant, action, **fields) == BAD_REQUEST
    assert rest.gov.grant(P1, uuid.UUID(grant)).state == "pending_approval"


def test_the_subject_is_resolved_on_the_server(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    unlinked = rest.create_grant(binding, ref, subject_user_id=UNLINKED)
    assert unlinked == ({"error": "The user has no linked identity-provider subject.", "code": "SUBJECT_UNLINKED"}, 409)
    assert rest.create_grant(binding, ref, subject_user_id=999) == (
        {"error": "The user does not exist.", "code": "SUBJECT_NOT_FOUND"}, 404)
    rest.identity_down = True
    assert rest.create_grant(binding, ref)[1] == 503
    rest.identity_down = False
    body, status = rest.create_grant(binding, ref)
    assert status == 201 and rest.gov.grant(P1, uuid.UUID(body["id"])).subject_ref == "idp:t1:o30"
    assert rest.gov.grant(P1, uuid.UUID(body["id"])).subject_kind == "user_delegation"


def test_valid_until_is_kept_on_a_grant(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    until = datetime.now(timezone.utc) + timedelta(days=3)
    body, status = rest.create_grant(binding, ref, valid_until=until.isoformat())
    assert status == 201
    stored = rest.gov.grant(P1, uuid.UUID(body["id"])).valid_until
    assert abs((stored.replace(tzinfo=timezone.utc) - until).total_seconds()) < 1
    assert rest.list_grants()[0]["rows"][0]["valid_until"] is not None


def test_lifecycle_refusals_keep_their_codes(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    config = rest.gov.configurations.rows[P1][1]
    duplicate = rest.create_ref(P1, config)
    assert duplicate == ({"error": "A live credential reference already exists for this configuration.",
                          "code": "REFERENCE_EXISTS"}, 409)
    assert rest.create_grant(binding, ref, toolkit_id=999) == (
        {"error": "The toolkit does not belong to the binding's agent version.", "code": "TOOLKIT_NOT_IN_BINDING"}, 400)
    first = rest.create_grant(binding, ref)
    assert rest.create_grant(binding, ref) == (
        {"error": "This credential use grant already exists.", "code": "GRANT_EXISTS"}, 409)
    assert rest.grant_action(first[0]["id"], "resume") == (
        {"error": "The record is not in a state this action can start from.", "code": "INVALID_STATE"}, 409)
    section = rest.gov.configurations.add(P1, section="variables")
    assert rest.create_ref(P1, section)[0]["code"] == "CONFIGURATION_NOT_ELIGIBLE"
    assert rest.ref_action(ref, "approve", approval_ref="A", policy_revision="B")[0]["code"] == "INVALID_STATE"


# --- authorization --------------------------------------------------------------------------------------------

def descriptor(rest, module, verb):
    return StubAuth.decorators.requirements[f"{rest.mods[module].__name__}:AdminAPI.{verb}"]


ENDPOINTS = (
    ("credential_references", "get", ["credentials.view"]), ("credential_references", "post", ["credentials.manage"]),
    ("credential_reference", "get", ["credentials.view"]),
    ("credential_reference_action", "post", ["credentials.manage", "credentials.probe", "credentials.approve"]),
    ("credential_grants", "get", ["credentials.view"]), ("credential_grants", "post", ["credentials.manage"]),
    ("credential_grant_action", "post", ["credentials.manage", "credentials.approve"]))


@pytest.mark.parametrize("module, verb, permissions", ENDPOINTS)
def test_every_endpoint_declares_its_permissions_and_the_operator_roles(rest, module, verb, permissions):
    declared = descriptor(rest, module, verb)
    assert declared["permissions"] == permissions
    admin = declared["recommended_roles"]["administration"]
    assert admin == {"super_admin": True, "admin": True, "viewer": False, "editor": False}
    default = declared["recommended_roles"]["default"]
    assert not default.get("super_admin", False) and not default.get("viewer", False) and not default.get("editor", False)
    if permissions == ["credentials.view"]:
        assert not any(default.values())  # the project mode does not see these endpoints at all
    handler = rest.mods[module]
    assert list(handler.API.mode_handlers) == ["administration"] and handler.API.mode_handlers["administration"] is handler.AdminAPI


def test_the_route_shapes_match_the_design(rest):
    urls = {name: rest.mods[name].API.url_params for name in MODULES}  # with_modes adds the <string:mode>/ variants
    assert urls == {
        "credential_references": ["<int:project_id>"], "credential_reference": ["<int:project_id>/<uuid:ref_id>"],
        "credential_reference_action": ["<int:project_id>/<uuid:ref_id>"], "credential_grants": ["<int:project_id>"],
        "credential_grant_action": ["<int:project_id>/<uuid:grant_id>"]}


def test_reveal_is_read_by_no_route():
    import pathlib  # pylint: disable=C0415
    root = pathlib.Path(__file__).resolve().parents[2]
    for path in [*(root / "api" / "v2").glob("*.py"), *(root / "utils").glob("*.py")]:
        assert "credentials.reveal" not in path.read_text(), path.name


ACTION_PERMISSIONS = {
    "import": "credentials.manage", "activate": "credentials.manage", "suspend": "credentials.manage",
    "resume": "credentials.manage", "retire": "credentials.manage", "probe": "credentials.probe",
    "approve": "credentials.approve"}


def test_each_reference_action_needs_its_own_permission(rest):
    api = rest.mods["credential_references"].api
    assert api.REFERENCE_ACTION_PERMISSION == ACTION_PERMISSIONS
    assert api.GRANT_ACTION_PERMISSION == {"approve": "credentials.approve", "suspend": "credentials.manage",
                                           "resume": "credentials.manage", "revoke": "credentials.manage"}
    for action, needed in ACTION_PERMISSIONS.items():
        until = {"import": "pending", "probe": "imported", "approve": "validated", "activate": "approved"}.get(action, "active")
        ref = rest.new_ref(P1, until=until)
        if action == "resume":
            assert rest.ref_action(ref, "suspend")[1] == 200
        rest.permissions = ALL_PERMISSIONS - {needed}  # everything but the one this action needs
        before = (rest.gov.reference(P1, uuid.UUID(ref)).state, len(rest.events()))
        extra = {"approval_ref": "A", "policy_revision": "B"} if action == "approve" else {}
        reply = rest.ref_action(ref, action, actor=APPROVER, **extra)
        assert reply == ({"error": "You do not have permission to do this.", "code": "FORBIDDEN"}, 403), action
        assert (rest.gov.reference(P1, uuid.UUID(ref)).state, len(rest.events())) == before, action
        rest.permissions = {needed}  # and the one permission is enough
        assert rest.ref_action(ref, action, actor=APPROVER, **extra)[1] == 200, action
        rest.permissions = set(ALL_PERMISSIONS)


def test_each_grant_action_needs_its_own_permission(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    grant = rest.create_grant(binding, ref)[0]["id"]
    rest.permissions = {"credentials.manage", "credentials.view", "credentials.probe"}
    assert rest.grant_action(grant, "approve", actor=APPROVER, approval_ref="A", policy_revision="B")[1] == 403
    rest.permissions = {"credentials.approve"}
    assert rest.grant_action(grant, "revoke", actor=APPROVER)[1] == 403
    assert rest.grant_action(grant, "approve", actor=APPROVER, approval_ref="A", policy_revision="B")[1] == 200
    assert rest.gov.grant(P1, uuid.UUID(grant)).state == "active"
    rest.permissions = {"credentials.manage"}
    assert rest.grant_action(grant, "suspend", actor=APPROVER)[1] == 200


def test_the_permission_check_asks_for_administration_mode_and_the_project_and_fails_closed(rest):
    ref = rest.new_ref(P1, until="active")
    assert rest.ref_action(ref, "suspend")[1] == 200
    assert rest.permission_calls[-1] == ("administration", P1)
    rest.permissions = None  # the authorization service raises
    assert rest.ref_action(ref, "resume")[1] == 403
    assert rest.gov.reference(P1, uuid.UUID(ref)).state == "suspended"
    rest.permissions = set()
    assert rest.ref_action(ref, "resume")[1] == 403


def test_a_call_without_a_signed_in_user_is_refused_and_writes_nothing(rest):
    ref = rest.new_ref(P1, until="active")
    before = len(rest.events())
    assert rest.ref_action(ref, "suspend", actor=0)[0]["code"] == "ACTOR_REQUIRED"
    assert rest.ref_action(ref, "suspend", actor=0)[1] == 403
    assert rest.create_ref(actor=0)[1] == 403
    assert len(rest.events()) == before and rest.gov.reference(P1, uuid.UUID(ref)).state == "active"


def test_the_creator_cannot_approve_a_reference_or_a_grant(rest):
    ref = rest.new_ref(P1, until="validated")
    reply = rest.approve_ref(ref, actor=CREATOR)
    assert reply == ({"error": "The creator of a record cannot approve it.", "code": "SELF_APPROVAL"}, 403)
    assert rest.gov.reference(P1, uuid.UUID(ref)).approved_by is None
    rest.approve_ref(ref)
    rest.ref_action(ref, "activate")
    grant = rest.create_grant(rest.seed_binding(), ref)[0]["id"]
    again = rest.grant_action(grant, "approve", actor=CREATOR, approval_ref="A", policy_revision="B")
    assert again == ({"error": "The creator of a record cannot approve it.", "code": "SELF_APPROVAL"}, 403)
    assert rest.gov.grant(P1, uuid.UUID(grant)).state == "pending_approval"


def test_an_id_of_another_project_is_a_404_and_nothing_is_written(rest):
    foreign_ref, foreign_binding = rest.new_ref(P2, until="active"), rest.seed_binding(P2)
    foreign_grant = rest.create_grant(foreign_binding, foreign_ref, P2)[0]["id"]
    ref = rest.new_ref(P1, until="active")
    binding = rest.seed_binding(P1, application_id=6, version_id=10)
    snapshot = (rest.gov.reference(P2, uuid.UUID(foreign_ref)), rest.gov.grant(P2, uuid.UUID(foreign_grant)))
    events = (len(rest.events(P1)), len(rest.events(P2)))
    not_found = lambda code, reply: reply[1] == 404 and reply[0]["code"] == code  # noqa: E731
    assert not_found("REFERENCE_NOT_FOUND", rest.get_ref(foreign_ref, P1))
    for action in ("suspend", "retire", "probe", "import", "activate"):
        assert not_found("REFERENCE_NOT_FOUND", rest.ref_action(foreign_ref, action, P1)), action
    assert not_found("REFERENCE_NOT_FOUND", rest.approve_ref(foreign_ref, P1))
    for action in ("suspend", "revoke", "resume"):
        assert not_found("GRANT_NOT_FOUND", rest.grant_action(foreign_grant, action, P1)), action
    assert not_found("GRANT_NOT_FOUND", rest.grant_action(foreign_grant, "approve", P1, APPROVER,
                                                          approval_ref="A", policy_revision="B"))
    assert not_found("REFERENCE_NOT_FOUND", rest.create_grant(binding, foreign_ref, P1))
    assert not_found("BINDING_NOT_FOUND", rest.create_grant(foreign_binding, ref, P1))
    foreign_config = rest.gov.configurations.add(P2)
    assert not_found("CONFIGURATION_NOT_FOUND", rest.create_ref(P1, foreign_config))
    assert not_found("REFERENCE_NOT_FOUND", rest.get_ref(str(uuid.uuid4())))  # an unknown id answers the same
    assert snapshot == (rest.gov.reference(P2, uuid.UUID(foreign_ref)), rest.gov.grant(P2, uuid.UUID(foreign_grant)))
    assert events == (len(rest.events(P1)), len(rest.events(P2)))
    assert rest.list_refs(P1)[0]["total"] == 1 and rest.list_grants(P1)[0]["total"] == 0


def test_refusals_hold_a_fixed_message_without_ids_or_request_values(rest):
    ref = rest.new_ref(P1, until="active")
    probes = [rest.get_ref(str(uuid.uuid4())), rest.ref_action(ref, "approve", approval_ref="SECRET-APPROVAL-REF",
                                                               policy_revision="SECRET-REV"),
              rest.create_ref(P1, rest.gov.configurations.add(P1), store_kind="SECRET-KIND"),
              rest.grant_action(uuid.uuid4(), "revoke")]
    for body, status in probes:
        assert status in (400, 404, 409) and set(body) == {"error", "code"}
        assert body["error"] in set(rest.mods["credential_references"].api.MESSAGES.values())
        assert "SECRET" not in json.dumps(body) and ref not in json.dumps(body)


def test_the_status_of_a_code(rest):
    status_of = rest.mods["credential_references"].api.status_of
    assert [status_of(code) for code in (
        "INVALID_REQUEST", "APPROVAL_REQUIRED", "FORBIDDEN", "SELF_APPROVAL", "ACTOR_REQUIRED", "REFERENCE_NOT_FOUND",
        "GRANT_NOT_FOUND", "INVALID_STATE", "CONCURRENT_CHANGE", "REFERENCE_EXISTS", "GRANT_EXISTS", "REQUEST_TOO_LARGE",
        "DEPENDENCY_UNAVAILABLE", "STORE_DENIED", "STORE_UNAVAILABLE", "FAILED", "SOMETHING_NEW", None)] == [
        400, 400, 403, 403, 403, 404, 404, 409, 409, 409, 409, 413, 503, 503, 503, 500, 500, 500]


def test_a_row_filed_under_another_project_is_not_found_even_in_the_same_schema(rest):
    models = rest.gov.module("models.credential_governance")
    with rest.gov.db.get_session(P1) as session:
        reference = models.CredentialReference(
            project_id=P2, configuration_id=777, configuration_uuid=uuid.uuid4(), provider="x", ownership_class="service",
            store_kind="database", store_locator={}, created_by=CREATOR, state="pending")
        session.add(reference)
        session.flush()
        grant = models.CredentialUseGrant(
            project_id=P2, application_id=5, subject_kind="user_delegation", subject_ref="idp:t1:o30",
            agent_binding_ref=uuid.uuid4(), toolkit_instance_id=str(TOOLKIT), credential_ref=reference.id,
            created_by=CREATOR, state="pending_approval")
        session.add(grant)
        session.commit()
        ref_id, grant_id = reference.id, grant.id
    assert rest.get_ref(ref_id)[1] == 404 and rest.ref_action(ref_id, "retire")[1] == 404
    assert rest.grant_action(grant_id, "revoke")[1] == 404
    assert rest.list_refs()[0]["total"] == 0 and rest.list_grants()[0]["total"] == 0
    assert rest.gov.reference(P1, ref_id).state == "pending" and rest.gov.grant(P1, grant_id).state == "pending_approval"
    assert rest.events() == []


# --- failure and secrecy ---------------------------------------------------------------------------------------

def test_an_unexpected_failure_is_a_500_with_no_detail(rest, monkeypatch):
    queries = rest.gov.module("utils.credential_queries")
    StubLog.records.clear()

    def explode(*_a, **_kw):
        raise RuntimeError("password=hunter2 postgres://user:pw@db/secret")
    monkeypatch.setattr(queries, "list_references", explode)
    assert rest.list_refs() == ({"error": "The request failed.", "code": "FAILED"}, 500)
    assert "hunter2" not in "\n".join(StubLog.records) and "RuntimeError" in "\n".join(StubLog.records)


def test_a_full_lifecycle_over_rest_never_shows_the_secret(rest):
    StubLog.records.clear()
    ref = rest.new_ref(P1, until="active")
    binding = rest.seed_binding()
    grant = rest.create_grant(binding, ref)[0]["id"]
    replies = [rest.list_refs(), rest.get_ref(ref), rest.list_grants(), rest.grant_action(grant, "revoke"),
               rest.ref_action(ref, "retire")]
    blob = json.dumps(replies) + "\n".join(StubLog.records) + json.dumps(rest.events())
    assert FIXTURE_VALUE not in blob


def test_the_permissions_are_registered_for_the_operator_api(gov, monkeypatch):
    registered = []
    monkeypatch.setattr(StubAuth, "register_permissions", staticmethod(registered.append), raising=False)
    from unittest.mock import MagicMock  # pylint: disable=C0415
    descriptor_ = MagicMock()
    descriptor_.metadata = {}
    gov.module("module").Module(context=MagicMock(), descriptor=descriptor_).init()
    roles = {entry["permissions"][0]: entry["recommended_roles"] for entry in registered
             if entry["permissions"][0].startswith("credentials.")}
    assert roles["credentials.view"]["administration"] == {"super_admin": True, "admin": True, "viewer": False, "editor": False}
    assert not any(roles["credentials.view"]["default"].values())
    for name in ("credentials.manage", "credentials.probe", "credentials.approve"):
        assert roles[name]["administration"]["super_admin"] is True and roles[name]["administration"]["admin"] is True
    assert not any(any(roles["credentials.reveal"][mode].values()) for mode in ("default", "administration"))
    assert "super_admin" not in roles["credentials.use"]["administration"]  # unchanged
