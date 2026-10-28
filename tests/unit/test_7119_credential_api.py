"""C-1009 (#7119): the operator REST API for credential references and use grants.

The handlers run for real (Flask request context, the real services over SQLite); the collaborators are the same
fakes the task tests use, plus a small identity service and a permission switch. ``check_api`` itself cannot run
here: what each endpoint declares to it is asserted from the recorded descriptors, and the per-action permission
the handlers check themselves is exercised with the permission set the fake hands out.
"""
import io
import json
import queue
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask, g

from fixtures.api_loader import load_api_module
from fixtures.governance import APPLICATION, BINDING, FIXTURE_VALUE, TOOL, TOOL_MAPPING, VERSION
from fixtures.permissions import effective_roles
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
        self.token_permissions = set()
        self.permission_calls = []
        self.identity_down = False
        self.projects = {P1, P2}
        self.project_rpc_down = False
        self.user_calls, self.member_calls, self.subject_calls = [], 0, []
        self.bulk_calls, self.bulk_timeouts, self.bulk_mode = [], [], "ok"
        # bulk mode: ok | missing (pylon_auth without the handler) | error (the handler refuses) | non_dict | wrong_user
        self.bulk_fail_on = None   # the number of the bulk call that raises a RuntimeError
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
            self.user_calls.append(list(user_ids or []))
            if self.identity_down:
                raise ConnectionError("down")
            return [dict(self.users[i]) for i in (user_ids or self.users) if i in self.users]

        def resolve_permissions(mode="administration", project_id=None, **_kw):
            self.permission_calls.append((mode, project_id))
            if self.permissions is None:
                raise RuntimeError("auth down")
            if getattr(getattr(g, "auth", None), "type", "user") == "token":
                return set(self.token_permissions)
            return set(self.permissions)

        def get_user_by_idp_subject(issuer, tid, oid):
            self.subject_calls.append((issuer, tid, oid))
            if self.identity_down:
                raise ConnectionError("down")
            found = [u for u in self.users.values() if (u["idp_issuer"], u["idp_tid"], u["idp_oid"]) == (issuer, tid, oid)]
            return dict(found[0]) if found else None

        def auth_get_users_by_idp_subjects(issuer, subjects):
            self.bulk_calls.append((issuer, [(item["tid"], item["oid"]) for item in subjects]))
            if self.bulk_mode == "missing":
                raise queue.Empty()
            if self.bulk_mode == "error" or self.bulk_fail_on == len(self.bulk_calls):
                raise RuntimeError("At most 200 subjects per call")
            if self.identity_down:
                raise ConnectionError("down")
            if self.bulk_mode == "non_dict":
                return []
            if self.bulk_mode == "wrong_user":   # every key answered with the record of somebody else
                return {f"{item['tid']}:{item['oid']}": dict(self.users[CREATOR]) for item in subjects}
            wanted = {(item["tid"], item["oid"]) for item in subjects}
            return {f"{u['idp_tid']}:{u['idp_oid']}": dict(u) for u in self.users.values()
                    if u["idp_issuer"] == issuer and (u["idp_tid"], u["idp_oid"]) in wanted}

        def with_timeout(seconds):
            self.bulk_timeouts.append(seconds)
            return types.SimpleNamespace(auth_get_users_by_idp_subjects=auth_get_users_by_idp_subjects)

        rpc = types.SimpleNamespace(timeout=with_timeout)
        self.monkeypatch.setitem(self.gov.this.modules, "secrets", types.SimpleNamespace(
            module=types.SimpleNamespace(context=types.SimpleNamespace(rpc_manager=rpc))))

        def list_project_user_roles(project_id):
            self.member_calls += 1
            return [{"user_id": i, "role_id": 1} for i in self.members]

        for name, func in dict(
                get_user=get_user, list_users=list_users, resolve_permissions=resolve_permissions,
                list_project_user_roles=list_project_user_roles, get_user_by_idp_subject=get_user_by_idp_subject,
                has_access=lambda current, required: bool(set(required) & set(current))).items():
            self.monkeypatch.setattr(StubAuth, name, staticmethod(func), raising=False)

    def _project_by_id(self, project_id):
        if self.project_rpc_down:
            raise TimeoutError("rpc down")
        return {"id": project_id} if project_id in self.projects else None

    def call(self, name, verb, *path, body=None, raw=None, query=None, actor=None, auth_type="user", **request_kwargs):
        self.set_actor(CREATOR if actor is None else actor)
        kwargs = {"method": "GET" if verb == "get" else "POST", "query_string": query or {}, **request_kwargs}
        if raw is not None:
            kwargs.update(data=raw)
            kwargs.setdefault("content_type", "application/json")
        elif body is not None:
            kwargs["json"] = body
        module = types.SimpleNamespace(context=types.SimpleNamespace(rpc_manager=types.SimpleNamespace(
            call=types.SimpleNamespace(project_get_by_id=lambda project_id: self._project_by_id(project_id)))))
        with app.test_request_context(**kwargs):
            g.auth = types.SimpleNamespace(type=auth_type, id=CREATOR)
            handler = self.mods[name].AdminAPI(api=types.SimpleNamespace(module=module), mode="administration")
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
    "configuration_changed", "approval_ref", "policy_revision", "created_by", "approved_by", "written_by", "expires_at",
    "created_at", "updated_at", "auth_mode", "delegation"}   # the kind and its descriptor (#6756 step 4)
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
        "error": "SELF_APPROVAL: The creator of a record, or whoever wrote its value, cannot approve it.", "code": "SELF_APPROVAL"}
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
    rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, title="GitHub prod"))
    rest.identity_down = True
    del rest.gov.this.modules["configurations"]  # the titles come from the project's own table, not from the service
    body, status = rest.list_refs(P1)
    row = body["rows"][0]
    assert status == 200 and row["created_by"] == {"id": CREATOR, "email": None}
    assert row["configuration"]["title"] == "GitHub prod" and row["configuration_changed"] is False


def test_a_deleted_configuration_has_no_title_and_no_change_flag(rest):
    config = rest.gov.configurations.add(P1, title="GitHub prod")
    rest.new_ref(P1, configuration=config)
    rest.gov.db.execute(P1, "DELETE FROM tenant.configuration")
    row = rest.list_refs(P1)[0]["rows"][0]
    assert row["configuration"] == {"uuid": config.uuid, "title": None} and row["configuration_changed"] is None


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
    assert admin == {"system": False, "super_admin": True, "admin": True, "viewer": False, "editor": False}
    effective = effective_roles(declared["recommended_roles"])
    assert effective["administration"] == {"system": False, "super_admin": True, "admin": True, "viewer": False,
                                           "editor": False}
    assert not effective["default"]["system"] and not effective["default"]["viewer"] and not effective["default"]["editor"]
    if permissions == ["credentials.view"]:
        assert not any(effective["default"].values())  # the project mode does not see these endpoints at all
    handler = rest.mods[module]
    assert handler.API.mode_handlers["administration"] is handler.AdminAPI
    # only the owner's own list has a default-mode handler here (#7119 PR 6); the rest is for operators
    assert set(handler.API.mode_handlers) == ({"administration", "default"} if module == "credential_references" else {"administration"})


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
    assert reply == ({"error": "The creator of a record, or whoever wrote its value, cannot approve it.", "code": "SELF_APPROVAL"}, 403)
    assert rest.gov.reference(P1, uuid.UUID(ref)).approved_by is None
    rest.approve_ref(ref)
    rest.ref_action(ref, "activate")
    grant = rest.create_grant(rest.seed_binding(), ref)[0]["id"]
    again = rest.grant_action(grant, "approve", actor=CREATOR, approval_ref="A", policy_revision="B")
    assert again == ({"error": "The creator of a record, or whoever wrote its value, cannot approve it.", "code": "SELF_APPROVAL"}, 403)
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
        "DEPENDENCY_UNAVAILABLE", "STORE_DENIED", "STORE_UNAVAILABLE", "FAILED", "SOMETHING_NEW", None,
        "STORE_VERSION_CONFLICT", "STORE_SEALED", "AUDIT_UNAVAILABLE", "NOT_FOUND")] == [
        400, 400, 403, 403, 403, 404, 404, 409, 409, 409, 409, 413, 503, 403, 503, 500, 500, 500, 409, 503, 503, 404]


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
    """What the auth plugin ends up granting: super_admin and admin, never editor, viewer or the system role."""
    registered = []
    monkeypatch.setattr(StubAuth, "register_permissions", staticmethod(registered.append), raising=False)
    from unittest.mock import MagicMock  # pylint: disable=C0415
    descriptor_ = MagicMock()
    descriptor_.metadata = {}
    gov.module("module").Module(context=MagicMock(), descriptor=descriptor_).init()
    roles = {entry["permissions"][0]: effective_roles(entry["recommended_roles"]) for entry in registered
             if entry["permissions"][0].startswith("credentials.")}
    operators = {"system": False, "super_admin": True, "admin": True, "viewer": False, "editor": False}
    for name in ("credentials.view", "credentials.manage", "credentials.probe", "credentials.approve"):
        assert roles[name]["administration"] == operators, name
        assert roles[name]["default"]["system"] is False and roles[name]["default"]["editor"] is False, name
    assert not any(roles["credentials.view"]["default"].values())
    assert roles["credentials.manage"]["default"]["admin"] is True  # as before
    for modes in roles["credentials.reveal"].values():  # untouched, and read by no route
        assert not (modes["admin"] or modes["editor"] or modes["viewer"])
    assert roles["credentials.use"]["administration"]["system"] is True  # credentials.use is exactly as it was
    assert roles["credentials.use"]["default"] == {**roles["credentials.use"]["default"], "admin": True, "viewer": True,
                                                   "editor": True}


# --- review fixes -----------------------------------------------------------------------------------------------

DOCUMENTED_FACT_KEYS = {"id", "project_id", "type", "section", "generation", "title"}


def test_the_fake_configuration_facts_have_the_documented_shape(rest):
    """Contract: ``configuration_credential_facts`` answers exactly these keys (``title`` is the configuration's
    ``elitea_title``, null when it has none). A fake that drifts from it would hide a field that is null in production."""
    for title in (None, "GitHub prod"):
        config = rest.gov.configurations.add(P1, title=title)
        fact = rest.gov.configurations.configuration_credential_facts(P1, [config.uuid])[config.uuid]
        assert set(fact) == DOCUMENTED_FACT_KEYS and fact["title"] == title


def test_a_configuration_without_a_title_gives_a_null_title_and_the_search_still_works(rest):
    config = rest.gov.configurations.add(P1)
    rest.new_ref(P1, configuration=config)
    row = rest.list_refs(P1)[0]["rows"][0]
    assert row["configuration"]["title"] is None and rest.list_refs(P1, search="x")[0]["rows"] == []


def test_a_reference_search_matches_the_configuration_title_as_well_as_the_provider(rest):
    pretty = rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, type_="jira", title="Payments Jira"))
    plain = rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, type_="github"))
    ids = lambda search: {row["id"] for row in rest.list_refs(P1, search=search)[0]["rows"]}  # noqa: E731
    assert ids("payments") == {pretty} and ids("PAYM") == {pretty} and ids("github") == {plain} and ids("jira") == {pretty}
    assert ids("%") == set() and ids("nothing like it") == set()
    assert rest.list_refs(P1, search="payments")[0]["total"] == 1


def test_valid_until_is_the_validated_value_not_a_second_parse(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    soon = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    body, _ = rest.create_grant(binding, ref, valid_until=soon)
    stored = rest.gov.grant(P1, uuid.UUID(body["id"])).valid_until
    assert stored is not None and abs((stored.replace(tzinfo=timezone.utc) - datetime.fromisoformat(soon)).total_seconds()) < 1
    # a time that has passed by the time the body is looked at is refused, never turned into "no end"
    api = rest.mods["credential_grants"].api
    assert api.GrantCreate.parse_obj({
        "agent_binding_ref": binding, "toolkit_id": 1, "credential_ref": ref, "subject_user_id": 1,
        "valid_until": soon}).valid_until == datetime.fromisoformat(soon).astimezone(timezone.utc)


@pytest.mark.parametrize("value", [
    lambda: (datetime.now(timezone.utc) + timedelta(days=366)).isoformat(),
    lambda: "9999-12-31T23:59:59-23:59", lambda: "9999-12-31T23:59:59+00:00", lambda: "0001-01-01T00:00:00+23:59",
    lambda: "2999-01-01T00:00:00+00:00"])
def test_valid_until_is_bounded_ahead_and_representable(rest, value):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    assert rest.create_grant(binding, ref, valid_until=value()) == BAD_REQUEST
    assert rest.list_grants()[0]["total"] == 0


def test_valid_until_a_year_ahead_is_accepted(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    ahead = (datetime.now(timezone.utc) + timedelta(days=364)).isoformat()
    assert rest.create_grant(binding, ref, valid_until=ahead)[1] == 201
    assert rest.mods["credential_grants"].api.MAX_GRANT_VALIDITY_DAYS == 365


def test_only_a_json_body_is_read(rest):
    body = json.dumps({"configuration_uuid": rest.gov.configurations.add(P1).uuid, "store_kind": "database",
                       "ownership_class": "service"}).encode()
    for content_type in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        reply = rest.call("credential_references", "post", P1, raw=body, content_type=content_type)
        assert reply == ({"error": "The request is not valid.", "code": "INVALID_REQUEST"}, 415), content_type
    assert rest.call("credential_references", "post", P1, raw=body, content_type="application/vnd.api+json")[1] == 201
    assert rest.list_refs()[0]["total"] == 1


def test_a_body_of_exactly_the_cap_is_read_and_one_byte_more_is_refused(rest):
    config = rest.gov.configurations.add(P1)
    exact = json.dumps({"configuration_uuid": config.uuid, "store_kind": "database", "ownership_class": "service"}).encode()
    exact += b" " * (8192 - len(exact))
    assert len(exact) == 8192 and rest.call("credential_references", "post", P1, raw=exact)[1] == 201
    over = exact + b" "
    assert len(over) == 8193
    assert rest.call("credential_references", "post", P1, raw=over) == (
        {"error": "The request is too large.", "code": "REQUEST_TOO_LARGE"}, 413)


def test_a_chunked_body_without_a_length_is_read_up_to_the_cap(rest):
    """No Content-Length (chunked transfer behind a server that terminates the input): read, not refused outright."""
    config = rest.gov.configurations.add(P1)
    exact = json.dumps({"configuration_uuid": config.uuid, "store_kind": "database", "ownership_class": "service"}).encode()
    exact += b" " * (8192 - len(exact))
    chunked = dict(content_type="application/json", environ_overrides={"wsgi.input_terminated": True})
    ok = rest.call("credential_references", "post", P1, input_stream=io.BytesIO(exact), **chunked)
    assert ok[1] == 201
    too_big = rest.call("credential_references", "post", P1, input_stream=io.BytesIO(exact + b" " * 5000), **chunked)
    assert too_big == ({"error": "The request is too large.", "code": "REQUEST_TOO_LARGE"}, 413)


@pytest.mark.parametrize("query", [
    {"offset": "10000001"}, {"limit": str(2**31)}, {"owner_user_id": str(2**31)}, {"owner_user_id": "99999999999999999999"}])
def test_numbers_that_a_column_cannot_hold_are_a_400_not_a_database_error(rest, query):
    assert rest.list_refs(**query) == BAD_REQUEST
    assert rest.list_grants(**{k: v for k, v in query.items() if k != "owner_user_id"} or {"toolkit_id": str(2**31)}) == BAD_REQUEST


def test_the_largest_accepted_numbers(rest):
    assert rest.list_refs(offset=10_000_000, limit=2**31 - 1)[1] == 200
    assert rest.list_grants(toolkit_id=2**31 - 1, subject_user_id=2**31 - 1)[1] == 200
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    assert rest.create_grant(binding, ref, toolkit_id=2**31)[1] == 400
    assert rest.create_grant(binding, ref, subject_user_id=2**31)[1] == 400
    assert rest.mods["credential_references"].api.MAX_OFFSET == 10_000_000


@pytest.mark.parametrize("value", ["a b", "a;b", "a\nb", "ünï", "x" * 129, ""])
def test_approval_references_use_the_task_alphabet(rest, value):
    ref = rest.new_ref(P1, until="validated")
    other = rest.call("credential_reference_action", "post", P1, uuid.UUID(ref),
                      body={"action": "approve", "approval_ref": value, "policy_revision": "rev-1"}, actor=APPROVER)
    assert other == BAD_REQUEST


def test_an_unknown_project_is_a_404_and_a_failing_lookup_a_503(rest):
    assert rest.list_refs(77) == ({"error": "The project does not exist.", "code": "NOT_FOUND"}, 404)
    assert rest.list_grants(77)[1] == 404 and rest.create_ref(77)[1] == 404
    assert rest.list_refs(2**40)[1] == 404  # not looked up at all
    rest.project_rpc_down = True
    assert rest.list_refs(P1) == ({"error": "A required service is unavailable; nothing was changed.",
                                   "code": "DEPENDENCY_UNAVAILABLE"}, 503)


def test_a_down_audit_trail_is_a_503_and_nothing_is_kept(rest):
    ref = rest.new_ref(P1, until="active")
    binding = rest.seed_binding()
    grant = rest.create_grant(binding, ref)[0]["id"]
    events = len(rest.events())
    rest.gov.tracing.fail = True
    expected = ({"error": "The audit trail is unavailable.", "code": "AUDIT_UNAVAILABLE"}, 503)
    assert rest.ref_action(ref, "suspend") == expected
    assert rest.grant_action(grant, "revoke") == expected
    assert rest.create_ref() == expected
    assert rest.create_grant(binding, ref, subject_user_id=APPROVER) == expected
    rest.gov.tracing.fail = False
    assert rest.gov.reference(P1, uuid.UUID(ref)).state == "active"
    assert rest.gov.grant(P1, uuid.UUID(grant)).state == "pending_approval"
    assert rest.list_refs()[0]["total"] == 1 and rest.list_grants()[0]["total"] == 1
    assert len(rest.events()) == events


def test_the_task_still_reports_a_down_audit_trail_as_failed(rest):
    """The REST code is a mapping of the same failure: the task's text and code are unchanged."""
    ref = str(rest.gov.add_reference(P1, state="active"))
    rest.gov.tracing.fail = True
    result = rest.onboarding.manage_reference(f"project_id={P1};action=suspend;ref={ref}", CREATOR)
    assert result == {"error": "failed; if an import was running, run reconcile_credential_store", "code": "FAILED"}
    assert rest.gov.reference(P1, uuid.UUID(ref)).state == "active"


def test_a_lost_race_is_a_409_through_rest_and_writes_no_event(rest, monkeypatch):
    ref = rest.new_ref(P1, until="active")
    binding = rest.seed_binding()
    grant = rest.create_grant(binding, ref)[0]["id"]
    events = len(rest.events())
    monkeypatch.setattr(rest.onboarding, "transition_reference", lambda *a, **k: False)
    monkeypatch.setattr(rest.grants, "transition_grant", lambda *a, **k: False)
    monkeypatch.setattr(rest.grants, "approve_grant", lambda *a, **k: False)
    expected = ({"error": "The record changed while this ran; read it again and retry.", "code": "CONCURRENT_CHANGE"}, 409)
    assert rest.ref_action(ref, "suspend") == expected
    assert rest.grant_action(grant, "revoke") == expected
    assert rest.grant_action(grant, "approve", actor=APPROVER, approval_ref="A", policy_revision="B") == expected
    assert rest.gov.reference(P1, uuid.UUID(ref)).state == "active" and len(rest.events()) == events


def test_a_token_caller_is_held_to_the_permissions_of_the_token(rest):
    """The in-handler check resolves permissions for the caller's own auth context (``flask.g.auth``), so a token
    that lacks a permission is refused even though the user behind it has it. What this cannot prove: that the real
    ``check_api`` refuses a token at the descriptor level (the stub never runs it) - only that nothing here lets a
    token past the per-action check."""
    ref = rest.new_ref(P1, until="validated")
    binding = rest.seed_binding()
    before = len(rest.events())
    rest.token_permissions = {"credentials.view"}  # the user has everything; the token only reads
    forbidden = ({"error": "You do not have permission to do this.", "code": "FORBIDDEN"}, 403)
    assert rest.call("credential_reference_action", "post", P1, uuid.UUID(ref),
                     body={"action": "approve", "approval_ref": "A", "policy_revision": "B"},
                     actor=APPROVER, auth_type="token") == forbidden
    assert rest.call("credential_reference_action", "post", P1, uuid.UUID(ref), body={"action": "retire"},
                     auth_type="token") == forbidden
    assert len(rest.events()) == before and rest.gov.reference(P1, uuid.UUID(ref)).state == "validated"
    rest.token_permissions = {"credentials.approve"}
    assert rest.call("credential_reference_action", "post", P1, uuid.UUID(ref),
                     body={"action": "approve", "approval_ref": "A", "policy_revision": "B"},
                     actor=APPROVER, auth_type="token")[1] == 200


def test_grant_rows_are_listed_only_if_an_action_can_find_them(rest):
    ref, binding = str(rest.gov.add_reference(P1, state="active")), rest.seed_binding()
    rest.gov.add_grant(P1, credential_ref=uuid.UUID(ref), agent_binding_ref=uuid.UUID(binding), target_ref="repo:x")
    listed = rest.create_grant(binding, ref)[0]["id"]
    assert {row["id"] for row in rest.list_grants()[0]["rows"]} == {listed}
    assert rest.grant_action(listed, "revoke")[1] == 200


def test_the_subjects_of_a_page_are_named_without_asking_for_a_whole_project(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    rest.create_grant(binding, ref, subject_user_id=MEMBER)
    rest.user_calls.clear()
    rest.member_calls = 0
    # for one user nothing but that user and the operators of the page is asked for
    assert rest.list_grants(subject_user_id=MEMBER)[0]["rows"][0]["subject"]["user"]["id"] == MEMBER
    assert rest.member_calls == 0 and {i for call in rest.user_calls for i in call} <= {MEMBER, CREATOR}
    # an empty page asks for nobody
    rest.user_calls.clear()
    assert rest.list_grants(state="revoked")[0]["rows"] == [] and rest.user_calls == []


def test_users_are_asked_for_in_chunks_of_at_most_a_hundred(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    rest.create_grant(binding, ref, subject_user_id=MEMBER)
    for extra in range(1000, 1230):
        rest.users[extra] = user(extra, f"u{extra}@x.test", oid=f"o{extra}")
    rest.members = list(rest.users)
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")   # made before the column
    rest.users[CREATOR] = user(CREATOR, "creator@x.test", tid=None)   # no issuer on the page: the members are looked at
    rest.user_calls.clear()
    row = rest.list_grants()[0]["rows"][0]
    assert row["subject"]["user"]["id"] == MEMBER
    assert len(rest.user_calls) >= 3 and max(len(call) for call in rest.user_calls) <= 100
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")
    rest.members = list(range(5000, 7000))  # a project beyond the lookup bound: subjects stay unnamed, nobody is fetched
    rest.user_calls.clear()
    assert rest.list_grants()[0]["rows"][0]["subject"]["user"] is None
    assert {i for call in rest.user_calls for i in call} <= {CREATOR}


# --- perf review 2026-10-21: S5 (grant subjects) and S6 (reference titles) --------------------------------------------

def _statements(rest, project=P1):
    import sqlalchemy as sa  # pylint: disable=C0415
    seen = []
    sa.event.listen(rest.gov.db.engine(project), "before_cursor_execute", lambda *a: seen.append(a[2]))
    return seen


def _selects(statements):
    return [s for s in statements if s.lstrip().upper().startswith("SELECT")]


def _count_configuration_calls(rest, monkeypatch):
    calls = []
    service = rest.gov.configurations
    real = service.configuration_credential_facts
    monkeypatch.setattr(service, "configuration_credential_facts", lambda *a, **k: calls.append(a) or real(*a, **k))
    return calls


def test_a_grant_stores_the_user_its_subject_was_resolved_from(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    body, _ = rest.create_grant(binding, ref, subject_user_id=MEMBER)
    assert rest.gov.grant(P1, uuid.UUID(body["id"])).subject_user_id == MEMBER
    task = rest.grants.manage_grant(
        f"project_id={P1};action=create;binding_ref={binding};toolkit_id={TOOLKIT};ref={ref};subject_ref=idp:t1:o20", CREATOR)
    assert rest.gov.grant(P1, uuid.UUID(task["grant"])).subject_user_id is None   # the task knows a subject, not a user


def test_the_grants_page_names_users_in_one_call_and_never_lists_the_members(rest):
    ref = rest.new_ref(P1, until="active")
    for n in range(7):
        toolkit = 100 + n
        binding = rest.seed_binding(application_id=100 + n, version_id=200 + n, tools=(toolkit,))
        for user_id in (MEMBER, APPROVER, CREATOR):
            assert rest.create_grant(binding, ref, subject_user_id=user_id, toolkit_id=toolkit)[1] == 201
    rest.user_calls.clear()
    rest.member_calls = 0
    body, status = rest.list_grants(limit=20)
    assert status == 200 and len(body["rows"]) == 20 and body["total"] == 21
    assert rest.member_calls == 0
    assert len(rest.user_calls) == 1 and set(rest.user_calls[0]) == {MEMBER, APPROVER, CREATOR}
    assert {row["subject"]["user"]["id"] for row in body["rows"]} == {MEMBER, APPROVER, CREATOR}


def _legacy_grant(rest):
    ref, binding = rest.new_ref(P1, until="active"), rest.seed_binding()
    grant = rest.create_grant(binding, ref, subject_user_id=MEMBER)[0]["id"]
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")   # made before the column
    rest.member_calls, rest.subject_calls = 0, []
    return grant


def test_a_grant_without_a_stored_user_is_named_by_its_subject_once_and_remembered(rest):
    grant = _legacy_grant(rest)
    row = rest.list_grants()[0]["rows"][0]
    assert row["subject"]["user"] == {"id": MEMBER, "email": "member@x.test"}
    assert rest.bulk_calls == [("https://issuer.test", [("t1", "o30")])] and rest.subject_calls == []
    assert rest.member_calls == 0
    assert rest.gov.grant(P1, uuid.UUID(grant)).subject_user_id == MEMBER
    rest.bulk_calls.clear()
    assert rest.list_grants()[0]["rows"][0]["subject"]["user"]["id"] == MEMBER
    assert rest.bulk_calls == [] and rest.subject_calls == [] and rest.member_calls == 0


def test_without_an_issuer_on_the_page_the_members_are_looked_at_once_and_remembered(rest):
    grant = _legacy_grant(rest)
    rest.users[CREATOR] = user(CREATOR, "creator@x.test", tid=None)   # the only user of the page has no issuer to offer
    row = rest.list_grants()[0]["rows"][0]
    assert row["subject"]["user"] == {"id": MEMBER, "email": "member@x.test"}
    assert rest.bulk_calls == [] and rest.subject_calls == [] and rest.member_calls == 1
    assert rest.gov.grant(P1, uuid.UUID(grant)).subject_user_id == MEMBER
    rest.list_grants()
    assert rest.member_calls == 1


def test_a_subject_nobody_resolves_stays_unnamed_costs_one_lookup_per_ten_minutes_and_stores_nothing(rest, monkeypatch):
    grant = _legacy_grant(rest)
    del rest.users[MEMBER]   # the subject names a user the identity service no longer has
    queries = rest.gov.module("utils.credential_queries")
    now = [1000.0]
    monkeypatch.setattr(queries, "_clock", lambda: now[0])
    for _ in range(3):   # a page shown again and again
        assert rest.list_grants()[0]["rows"][0]["subject"]["user"] is None
    assert len(rest.bulk_calls) == 1 and rest.member_calls == 1   # one lookup and one look at the members, once
    assert rest.gov.grant(P1, uuid.UUID(grant)).subject_user_id is None
    now[0] += queries.UNRESOLVABLE_TTL_S - 1
    rest.list_grants()
    assert len(rest.bulk_calls) == 1 and rest.member_calls == 1
    now[0] += 2   # ten minutes have passed
    rest.list_grants()
    rest.list_grants()
    assert len(rest.bulk_calls) == 2 and rest.member_calls == 2


def test_a_subject_lookup_that_fails_is_retried_not_remembered(rest):
    _legacy_grant(rest)
    rest.identity_down = True
    assert rest.list_grants()[0]["rows"][0]["subject"]["user"] is None
    rest.identity_down = False
    assert rest.list_grants()[0]["rows"][0]["subject"]["user"]["id"] == MEMBER


def _legacy_grants(rest, count, tenant=lambda n: ("t1", "https://issuer.test"), actor=lambda n: None):
    """``count`` grants made before the column, each for another user of the identity service (by default of tenant t1)."""
    ref = rest.new_ref(P1, until="active")
    for n in range(count):
        user_id = 2000 + n
        tid, issuer = tenant(n)
        rest.users[user_id] = {**user(user_id, f"legacy{n}@x.test", tid=tid, oid=f"legacy{n}"), "idp_issuer": issuer}
        rest.members.append(user_id)
        binding = rest.seed_binding(application_id=300 + n, version_id=400 + n, tools=(500 + n,))
        assert rest.create_grant(binding, ref, subject_user_id=user_id, toolkit_id=500 + n, actor=actor(n))[1] == 201
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")   # made before the column
    rest.member_calls, rest.subject_calls, rest.bulk_calls = 0, [], []


def test_a_page_of_legacy_subjects_is_named_with_one_bulk_call(rest):
    _legacy_grants(rest, 6)
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert {row["subject"]["user"]["email"] for row in rows} == {f"legacy{n}@x.test" for n in range(6)}
    assert len(rest.bulk_calls) == 1 and len(rest.bulk_calls[0][1]) == 6   # one round trip for six subjects
    assert rest.subject_calls == [] and rest.member_calls == 0
    assert rest.bulk_calls[0][0] == "https://issuer.test"


def test_the_subjects_of_a_page_are_stored_on_their_grants_after_the_bulk_lookup(rest):
    _legacy_grants(rest, 4)
    rest.list_grants(limit=20)
    stored = rest.gov.db.execute(P1, "SELECT subject_user_id FROM tenant.credential_use_grant")
    assert sorted(row["subject_user_id"] for row in stored) == [2000, 2001, 2002, 2003]
    rest.bulk_calls.clear()
    rest.list_grants(limit=20)
    assert rest.bulk_calls == [] and rest.subject_calls == []   # named from the stored ids now


def test_more_subjects_than_the_bulk_call_takes_are_split_into_calls_of_at_most_that_many(rest, monkeypatch):
    queries = rest.gov.module("utils.credential_queries")
    monkeypatch.setattr(queries, "BULK_SUBJECTS_PER_CALL", 2)
    _legacy_grants(rest, 5)
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert all(row["subject"]["user"] for row in rows)
    assert [len(call[1]) for call in rest.bulk_calls] == [2, 2, 1]


def test_without_the_bulk_call_the_subjects_are_looked_up_one_by_one_and_the_gap_is_remembered(rest, monkeypatch):
    queries = rest.gov.module("utils.credential_queries")
    now = [1000.0]
    monkeypatch.setattr(queries, "_clock", lambda: now[0])
    _legacy_grants(rest, 3)
    rest.bulk_mode = "missing"   # an older pylon_auth: the request is never answered
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert {row["subject"]["user"]["email"] for row in rows} == {f"legacy{n}@x.test" for n in range(3)}
    assert len(rest.bulk_calls) == 1 and len(rest.subject_calls) == 3
    assert {sub[0] for sub in rest.subject_calls} == {"https://issuer.test"}
    # backfilled all the same
    assert sorted(row["subject_user_id"] for row in rest.gov.db.execute(P1, "SELECT subject_user_id FROM tenant.credential_use_grant")) == [
        2000, 2001, 2002]
    # a page seen again soon does not wait for the missing handler again
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")
    rest.bulk_calls.clear()
    rest.list_grants(limit=20)
    assert rest.bulk_calls == [] and len(rest.subject_calls) == 6
    # and tries again once the memory has expired (the service may have been upgraded)
    now[0] += queries.BULK_UNAVAILABLE_TTL_S + 1
    rest.bulk_mode = "ok"
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")
    rest.list_grants(limit=20)
    assert len(rest.bulk_calls) == 1 and len(rest.subject_calls) == 6


def _single_lookups_time_out(rest):
    def unanswered(issuer, tid, oid):
        rest.subject_calls.append((issuer, tid, oid))
        raise queue.Empty()

    rest.monkeypatch.setattr(StubAuth, "get_user_by_idp_subject", staticmethod(unanswered), raising=False)


def _single_lookups_answer(rest):
    def answer(issuer, tid, oid):
        rest.subject_calls.append((issuer, tid, oid))
        found = [u for u in rest.users.values() if (u["idp_issuer"], u["idp_tid"], u["idp_oid"]) == (issuer, tid, oid)]
        return dict(found[0]) if found else None

    rest.monkeypatch.setattr(StubAuth, "get_user_by_idp_subject", staticmethod(answer), raising=False)


def test_an_unanswering_identity_service_costs_one_single_lookup_not_one_per_subject(rest):
    _legacy_grants(rest, 4)
    rest.bulk_mode = "missing"
    _single_lookups_time_out(rest)
    assert rest.list_grants(limit=20)[1] == 200   # still listed (the members of the project name the subjects)
    assert len(rest.subject_calls) == 1


def test_subjects_that_were_never_answered_are_not_remembered_as_unresolvable_and_are_asked_again(rest):
    queries = rest.gov.module("utils.credential_queries")
    _legacy_grants(rest, 4)
    rest.members = [CREATOR]   # the members answer, and the subjects are not among them
    rest.bulk_mode = "missing"
    _single_lookups_time_out(rest)   # the first single lookup times out; the other three are never asked
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert all(row["subject"]["user"] is None for row in rows) and len(rest.subject_calls) == 1
    assert queries._UNRESOLVABLE == {}   # nothing was answered "nobody"
    # the next page load asks for all of them again
    rest.bulk_mode = "ok"
    queries._BULK["unavailable_until"] = 0.0
    rest.subject_calls.clear()
    _single_lookups_answer(rest)
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert {row["subject"]["user"]["email"] for row in rows} == {f"legacy{n}@x.test" for n in range(4)}


def test_a_subject_answered_nobody_is_remembered_but_one_not_asked_is_not(rest):
    queries = rest.gov.module("utils.credential_queries")
    _legacy_grants(rest, 2)
    rest.members = [CREATOR]
    del rest.users[2000]   # the identity service answers "nobody" for the first subject only
    rest.bulk_mode = "ok"
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert sorted(row["subject"]["user"] is None for row in rows) == [False, True]
    assert {subject for _, subject in queries._UNRESOLVABLE} == {"idp:t1:legacy0"}


def test_a_missing_bulk_handler_is_not_remembered_when_the_single_lookups_do_not_answer_either(rest):
    queries = rest.gov.module("utils.credential_queries")
    _legacy_grants(rest, 3)
    rest.members = [CREATOR]
    rest.bulk_mode = "missing"
    _single_lookups_time_out(rest)   # an outage of pylon_auth, not a missing handler
    rest.list_grants(limit=20)
    assert queries._BULK["unavailable_until"] == 0.0
    rest.list_grants(limit=20)
    assert len(rest.bulk_calls) == 2   # the bulk call is tried again


def test_a_failing_chunk_keeps_the_answers_of_the_chunks_before_it(rest, monkeypatch):
    queries = rest.gov.module("utils.credential_queries")
    monkeypatch.setattr(queries, "BULK_SUBJECTS_PER_CALL", 2)
    _legacy_grants(rest, 5)
    rest.bulk_fail_on = 2   # the second chunk is refused
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert all(row["subject"]["user"] for row in rows)
    assert [len(call[1]) for call in rest.bulk_calls] == [2, 2]   # the third chunk is not tried after a failure
    assert len(rest.subject_calls) == 3   # the first chunk needed no single lookup
    assert queries._BULK["unavailable_until"] == 0.0   # a refusal is not a missing handler


def test_a_bulk_lookup_that_fails_leaves_the_page_listed_and_is_retried(rest):
    _legacy_grants(rest, 2)
    rest.members = [CREATOR]
    rest.bulk_fail_on = 1

    def down(issuer, tid, oid):
        rest.subject_calls.append((issuer, tid, oid))
        raise ConnectionError("down")

    rest.monkeypatch.setattr(StubAuth, "get_user_by_idp_subject", staticmethod(down), raising=False)
    assert all(row["subject"]["user"] is None for row in rest.list_grants(limit=20)[0]["rows"])
    rest.bulk_fail_on = None
    _single_lookups_answer(rest)
    rest.subject_calls.clear()
    assert all(row["subject"]["user"] for row in rest.list_grants(limit=20)[0]["rows"])
    assert len(rest.bulk_calls) == 2 and rest.subject_calls == []   # the bulk call is made again, no single lookup is needed


@pytest.mark.parametrize("mode", ["error", "non_dict"])
def test_a_bulk_handler_that_refuses_or_answers_badly_sends_the_page_to_the_single_lookups_without_a_memory(rest, mode):
    queries = rest.gov.module("utils.credential_queries")
    _legacy_grants(rest, 3)
    rest.bulk_mode = mode
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert all(row["subject"]["user"] for row in rows) and len(rest.subject_calls) == 3
    assert queries._BULK["unavailable_until"] == 0.0
    rest.gov.db.execute(P1, "UPDATE tenant.credential_use_grant SET subject_user_id = NULL")
    rest.list_grants(limit=20)
    assert len(rest.bulk_calls) == 2   # tried again


def test_an_answer_for_somebody_else_is_not_trusted(rest):
    _legacy_grants(rest, 2)
    rest.members = [CREATOR]
    rest.bulk_mode = "wrong_user"   # both keys answered with the record of the creator
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert all(row["subject"]["user"] is None for row in rows)
    assert rest.gov.db.execute(P1, "SELECT subject_user_id FROM tenant.credential_use_grant")[0]["subject_user_id"] is None


def test_two_issuers_on_one_page_are_two_bulk_calls_and_everyone_is_named(rest):
    rest.users[APPROVER] = {**rest.users[APPROVER], "idp_tid": "t2", "idp_issuer": "https://issuer2.test"}   # on the page
    _legacy_grants(rest, 4, tenant=lambda n: ("t1", "https://issuer.test") if n % 2 == 0 else ("t2", "https://issuer2.test"),
                   actor=lambda n: None if n % 2 == 0 else APPROVER)   # the operators of the page show both issuers
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert {row["subject"]["user"]["email"] for row in rows} == {f"legacy{n}@x.test" for n in range(4)}
    assert sorted((issuer, len(pairs)) for issuer, pairs in rest.bulk_calls) == [
        ("https://issuer.test", 2), ("https://issuer2.test", 2)]
    assert rest.subject_calls == [] and rest.member_calls == 0


def test_subjects_of_a_tenant_with_no_known_issuer_go_to_the_member_list_and_are_not_dropped(rest):
    _legacy_grants(rest, 3, tenant=lambda n: ("t1", "https://issuer.test") if n == 0 else ("t9", "https://issuer9.test"))
    rows = rest.list_grants(limit=20)[0]["rows"]
    assert {row["subject"]["user"]["email"] for row in rows} == {f"legacy{n}@x.test" for n in range(3)}
    assert [(issuer, pairs) for issuer, pairs in rest.bulk_calls] == [("https://issuer.test", [("t1", "legacy0")])]
    assert rest.member_calls == 1 and rest.subject_calls == []


def test_the_bulk_call_is_made_with_the_rpc_timeout_of_the_other_auth_proxies(rest):
    _legacy_grants(rest, 2)
    rest.list_grants(limit=20)
    assert rest.bulk_timeouts == [15]


def test_a_mandate_grant_needs_no_user(rest):
    ref, binding = str(rest.gov.add_reference(P1, state="active")), rest.seed_binding()
    rest.gov.add_grant(P1, credential_ref=uuid.UUID(ref), agent_binding_ref=uuid.UUID(binding), state="active",
                       subject_kind="mandate", subject_ref=f"mandate:{uuid.uuid4()}")
    rest.member_calls = 0
    row = rest.list_grants()[0]["rows"][0]
    assert row["subject"]["user"] is None and rest.member_calls == 0


def test_the_reference_search_is_one_statement_pair_and_asks_the_configurations_service_for_nothing(rest, monkeypatch):
    for n in range(25):
        rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, type_="jira", title=f"Config {n}"))
    wanted = rest.gov.configurations.add(P1, type_="github", title="Payments gateway")
    wanted_ref = rest.new_ref(P1, configuration=wanted)
    calls = _count_configuration_calls(rest, monkeypatch)
    statements = _statements(rest)
    body, status = rest.list_refs(P1, search="gateway", limit=5)
    assert status == 200 and [row["id"] for row in body["rows"]] == [wanted_ref] and body["total"] == 1
    assert calls == []
    selects = [s for s in _selects(statements) if "credential_reference" in s]
    assert len(selects) == 2   # the count and the page; the users of the page come from the identity service
    assert not [s for s in statements if "credential_reference" in s and "LIMIT 1000" in s]   # no title scan


def test_a_reference_page_and_a_grants_page_need_no_configuration_call(rest, monkeypatch):
    ref = rest.new_ref(P1, until="active", configuration=rest.gov.configurations.add(P1, title="Jira prod"))
    rest.create_grant(rest.seed_binding(), ref)
    calls = _count_configuration_calls(rest, monkeypatch)
    assert rest.list_refs(P1)[0]["rows"][0]["configuration"]["title"] == "Jira prod"
    assert rest.get_ref(ref)[0]["configuration"]["title"] == "Jira prod"
    assert rest.list_grants()[0]["rows"][0]["credential"]["configuration_title"] == "Jira prod"
    assert calls == []


def test_a_reference_page_is_one_count_and_one_page_statement(rest):
    for n in range(3):
        rest.new_ref(P1, configuration=rest.gov.configurations.add(P1, title=f"T{n}"))
    statements = _statements(rest)
    assert rest.list_refs(P1)[1] == 200
    assert len([s for s in _selects(statements) if "credential_reference" in s]) == 2


def test_a_project_without_a_readable_configuration_table_lists_with_empty_titles(rest):
    ref = rest.new_ref(P1, until="active", configuration=rest.gov.configurations.add(P1, title="Jira prod"))
    rest.create_grant(rest.seed_binding(), ref)
    rest.gov.db.execute(P1, "DROP TABLE tenant.configuration")
    body, status = rest.list_refs(P1)
    assert status == 200 and body["total"] == 1
    assert body["rows"][0]["configuration"]["title"] is None and body["rows"][0]["configuration_changed"] is None
    assert rest.list_refs(P1, search="api_cred")[0]["total"] == 1       # the provider still matches
    assert rest.list_refs(P1, search="Jira prod")[0]["rows"] == []      # a title cannot
    assert rest.get_ref(ref)[0]["configuration"]["title"] is None
    grants = rest.list_grants()[0]["rows"]
    assert len(grants) == 1 and grants[0]["credential"]["configuration_title"] is None
