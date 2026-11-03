"""C-1009 #7269 phase 1: the project-mode credential routes (the project's own admins) and the inbox's escalation.

The handlers and the lifecycles run for real over SQLite with the fakes of ``test_7119_credential_api``. ``check_api``
cannot run here, so ``checked`` applies what it would: the descriptor a handler declares, evaluated for the caller's
role in the project through the auth plugin's ``Permissions`` model. The permission each action asks for itself goes
through ``auth.resolve_permissions`` faked per (mode, project): a project role counts in its own project and in project
mode only, a platform role in administration mode only. elitea_core's project gate (``governance_project_refusal``,
tested there) and its membership read (``governance_project_admins``) are faked on the elitea_core module.
"""
import sys
import types
from pathlib import Path
import uuid

import pytest
from flask import g

from fixtures.permissions import effective_roles
from run_tests import StubAuth
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_7119_credential_api import APPROVER, CREATOR, MEMBER, P1, P2, TOOLKIT, Rest, app

ADMINISTRATION, DEFAULT = "administration", "default"
VIEWER, FOREIGN, PLATFORM = 40, 50, 60
ROLES = {  # user -> {project id or "administration": role}
    # the two project admins are platform operators too, so the setup can use the administration routes of #7119
    CREATOR: {P1: "admin", ADMINISTRATION: "admin"}, APPROVER: {P1: "admin", ADMINISTRATION: "admin"}, MEMBER: {P1: "editor"}, VIEWER: {P1: "viewer"},
    FOREIGN: {P2: "admin"}, PLATFORM: {ADMINISTRATION: "admin"},
}
APPROVAL = {"approval_ref": "CHG-7269", "policy_revision": "rev-1"}
OFF = ({"error": "Project governance applies only while credential governance is enforced; nothing was changed.",
        "code": "PROJECT_GOVERNANCE_OFF"}, 409)


class ProjectRest(Rest):
    """``Rest`` with project-scoped permissions, the project-mode handlers and elitea_core's gate and membership."""

    def __init__(self, gov, monkeypatch):
        super().__init__(gov, monkeypatch)
        self.gate = None                      # what elitea_core's project gate answers (None: let through)
        self.admins = {P1: frozenset({CREATOR, APPROVER}), P2: frozenset({FOREIGN})}
        self.admin_calls, self.project_calls = [], []
        core = gov.core
        monkeypatch.setattr(core, "governance_project_refusal", lambda: self.gate, raising=False)

        def admins(project_id):
            self.admin_calls.append(project_id)
            return self.admins[project_id]

        monkeypatch.setattr(core, "governance_project_admins", admins, raising=False)

        def resolve_permissions(mode="administration", project_id=None, **_kw):
            self.permission_calls.append((mode, project_id))
            return self.granted(StubAuth.user.get("id"), mode, project_id)

        monkeypatch.setattr(StubAuth, "resolve_permissions", staticmethod(resolve_permissions), raising=False)
        for user_id in (VIEWER, FOREIGN, PLATFORM):
            self.users[user_id] = {"id": user_id, "email": f"u{user_id}@x.test", "name": "n", "idp_issuer": None,
                                   "idp_tid": None, "idp_oid": None}

    @staticmethod
    def granted(user_id, mode, project_id):
        """Every credential permission the role recommends, from the descriptors the handlers declared."""
        roles = ROLES.get(user_id, {})
        role = roles.get(ADMINISTRATION) if mode == ADMINISTRATION else roles.get(project_id)
        key = ADMINISTRATION if mode == ADMINISTRATION else DEFAULT
        if not role:
            return set()
        return {permission for descriptor in StubAuth.decorators.requirements.values()
                if isinstance(descriptor, dict) and "recommended_roles" in descriptor
                for permission in descriptor["permissions"]
                if effective_roles(descriptor["recommended_roles"])[key].get(role)}

    def project(self, name, verb, *path, actor=CREATOR, body=None, query=None, mode=DEFAULT):
        """One call as the route makes it, ``check_api`` applied (403 access_denied when the descriptor refuses)."""
        self.set_actor(actor)
        handler_name = "ProjectAPI" if mode == DEFAULT else "AdminAPI"
        descriptor = StubAuth.decorators.requirements[f"{self.mods[name].__name__}:{handler_name}.{verb}"]
        if not set(descriptor["permissions"]) & self.granted(actor, mode, path[0]):
            return {"ok": False, "error": "access_denied"}, 403
        kwargs = {"method": "GET" if verb == "get" else "POST", "query_string": query or {}}
        if body is not None:
            kwargs["json"] = body

        def project_by_id(project_id):
            self.project_calls.append(project_id)
            return {"id": project_id}

        module = types.SimpleNamespace(context=types.SimpleNamespace(rpc_manager=types.SimpleNamespace(
            call=types.SimpleNamespace(project_get_by_id=project_by_id))))
        with app.test_request_context(**kwargs):
            g.auth = types.SimpleNamespace(type="user", id=actor)
            handler = getattr(self.mods[name], handler_name)(api=types.SimpleNamespace(module=module), mode=mode)
            return getattr(handler, verb)(*path)


@pytest.fixture
def rest(gov, monkeypatch):
    return ProjectRest(gov, monkeypatch)


def pending_grant(rest, creator=CREATOR):
    binding, ref = rest.seed_binding(), str(rest.gov.add_reference(P1, state="active"))
    body, status = rest.project("credential_grants", "post", P1, actor=creator, body={
        "agent_binding_ref": binding, "toolkit_id": TOOLKIT, "credential_ref": ref, "subject_user_id": MEMBER})
    assert status == 201, body
    return body["id"]


ROUTES = {
    "reference_list": lambda rest, actor, ids: rest.project("credential_references", "get", P1, actor=actor),
    "reference_detail": lambda rest, actor, ids: rest.project("credential_reference", "get", P1, uuid.UUID(ids["ref"]),
                                                              actor=actor),
    "reference_probe": lambda rest, actor, ids: rest.project(
        "credential_reference_action", "post", P1, uuid.UUID(ids["ref"]), actor=actor, body={"action": "suspend"}),
    "grant_list": lambda rest, actor, ids: rest.project("credential_grants", "get", P1, actor=actor),
    "grant_create": lambda rest, actor, ids: rest.project("credential_grants", "post", P1, actor=actor, body={
        "agent_binding_ref": ids["binding"], "toolkit_id": TOOLKIT, "credential_ref": ids["ref"],
        "subject_user_id": MEMBER}),
    "grant_revoke": lambda rest, actor, ids: rest.project(
        "credential_grant_action", "post", P1, uuid.UUID(ids["grant"]), actor=actor, body={"action": "suspend"}),
}
READS = ("reference_list", "reference_detail", "grant_list")


def _ids(rest):
    binding = rest.seed_binding()
    ref = str(rest.gov.add_reference(P1, state="active"))
    other_binding = rest.seed_binding(application_id=6, version_id=8, tools=(42,))
    grant = rest.grants.manage_grant(
        f"project_id={P1};action=create;binding_ref={other_binding};toolkit_id=42;ref={ref};"
        "subject_ref=idp:t1:o30", APPROVER)["grant"]
    assert "error" not in rest.grants.manage_grant(
        f"project_id={P1};action=approve;binding_ref={other_binding};toolkit_id=42;ref={ref};"
        "subject_ref=idp:t1:o30;approval_ref=A;policy_revision=B", CREATOR)
    return {"binding": binding, "ref": ref, "grant": grant}


@pytest.mark.parametrize("route", sorted(ROUTES))
@pytest.mark.parametrize("actor, may_read, may_write", [
    (CREATOR, True, True), (APPROVER, True, True), (MEMBER, False, False), (VIEWER, False, False),
    (FOREIGN, False, False), (PLATFORM, False, False), (0, False, False),
])
def test_the_project_mode_authorization_matrix(rest, route, actor, may_read, may_write):
    ids = _ids(rest)
    before = len(rest.events())
    payload, status = ROUTES[route](rest, actor, ids)
    if (may_read if route in READS else may_write):
        assert status in (200, 201), (route, actor, payload)
    else:
        # check_api refuses, but the reference list: every member opens it (their own list, mine=true), and the
        # handler refuses the project list without credentials.view
        refusal = ("FORBIDDEN" if route == "reference_list" and actor in (MEMBER, VIEWER, CREATOR, APPROVER)
                   else None)
        if refusal:
            assert (status, payload.get("code")) == (403, refusal), (route, actor, payload)
        else:
            assert (status, payload.get("error")) == (403, "access_denied"), (route, actor, payload)
        assert len(rest.events()) == before


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_the_gates_refusal_is_the_answer_and_nothing_is_read(rest, route):
    """Off and audit only (and an unscoped API token, which the gate refuses with its own code): elitea_core's answer,
    before the project, a permission or a row is read."""
    ids = _ids(rest)
    rest.permission_calls.clear()
    events = len(rest.events())
    for refusal in (OFF, ({"error": "x", "code": "TOKEN_SCOPE_OPERATION"}, 403)):
        rest.gate = refusal
        assert ROUTES[route](rest, CREATOR, ids) == refusal
    assert rest.project_calls == [] and rest.permission_calls == [] and rest.admin_calls == []
    assert len(rest.events()) == events


def test_without_elitea_core_the_project_routes_fail_closed(rest, monkeypatch):
    monkeypatch.setitem(rest.gov.this.modules, "elitea_core", types.SimpleNamespace(module=None))
    payload, status = rest.project("credential_grants", "get", P1)
    assert (status, payload["code"]) == (503, "DEPENDENCY_UNAVAILABLE")


# --- four-eyes with two project admins -------------------------------------------------------------------------

def test_two_project_admins_close_a_grant_and_its_creator_cannot(rest):
    grant = pending_grant(rest, CREATOR)
    approve = {"action": "approve", **APPROVAL}
    payload, status = rest.project("credential_grant_action", "post", P1, uuid.UUID(grant), actor=CREATOR, body=approve)
    assert (status, payload["code"]) == (403, "SELF_APPROVAL")
    payload, status = rest.project("credential_grant_action", "post", P1, uuid.UUID(grant), actor=APPROVER, body=approve)
    assert (status, payload["state"]) == (200, "active")
    assert ("default", P1) in rest.permission_calls and ("administration", P1) not in rest.permission_calls


def test_a_project_admin_approves_a_reference_the_other_admin_made(rest):
    ref = rest.new_ref(P1, until="validated")   # created and probed by CREATOR through administration
    approve = {"action": "approve", **APPROVAL}
    assert rest.project("credential_reference_action", "post", P1, uuid.UUID(ref), actor=CREATOR,
                        body=approve)[0]["code"] == "SELF_APPROVAL"
    payload, status = rest.project("credential_reference_action", "post", P1, uuid.UUID(ref), actor=APPROVER, body=approve)
    assert status == 200 and payload["approved"] is True
    payload, status = rest.project("credential_reference_action", "post", P1, uuid.UUID(ref), actor=CREATOR,
                                   body={"action": "activate"})
    assert (status, payload["state"]) == (200, "active")


def test_a_member_of_another_project_cannot_reach_this_projects_rows_with_their_own_admin_role(rest):
    grant = pending_grant(rest, CREATOR)
    payload, status = rest.project("credential_grant_action", "post", P2, uuid.UUID(grant), actor=FOREIGN,
                                   body={"action": "approve", **APPROVAL})
    assert (status, payload["code"]) == (404, "GRANT_NOT_FOUND")


# --- escalation ------------------------------------------------------------------------------------------------

def test_the_project_lists_say_which_waiting_rows_nobody_in_the_project_can_approve(rest):
    pending_grant(rest, CREATOR)
    page, _ = rest.project("credential_grants", "get", P1)
    assert [row["escalated"] for row in page["rows"]] == [False]   # APPROVER may approve it
    rest.admins[P1] = frozenset({CREATOR})
    page, _ = rest.project("credential_grants", "get", P1)
    assert [row["escalated"] for row in page["rows"]] == [True]
    assert rest.admin_calls == [P1, P1]


def test_a_reference_escalates_when_the_admins_are_its_creator_and_its_writer(rest):
    rest.new_ref(P1, until="validated")   # created and imported by CREATOR
    rest.admins[P1] = frozenset({CREATOR})
    page, _ = rest.project("credential_references", "get", P1)
    assert [(row["state"], row["escalated"]) for row in page["rows"]] == [("validated", True)]
    rest.admins[P1] = frozenset({CREATOR, APPROVER})
    page, _ = rest.project("credential_references", "get", P1)
    assert [row["escalated"] for row in page["rows"]] == [False]


def test_escalated_true_on_the_administration_lists_keeps_exactly_those_rows(rest):
    pending_grant(rest, CREATOR)
    rest.new_ref(P1, until="validated")
    rest.gov.add_reference(P1, state="active")
    rest.admins[P1] = frozenset()   # a private project: no admin
    page, status = rest.project("credential_grants", "get", P1, actor=PLATFORM, mode=ADMINISTRATION,
                                query={"escalated": "true"})
    assert status == 200 and page["total"] == 1 and page["rows"][0]["escalated"] is True
    page, _ = rest.project("credential_references", "get", P1, actor=PLATFORM, mode=ADMINISTRATION,
                           query={"escalated": "true"})
    assert page["total"] == 1 and page["rows"][0]["state"] == "validated"


def test_without_escalated_the_administration_lists_are_as_before(rest):
    pending_grant(rest, CREATOR)
    rest.admin_calls.clear()
    for name in ("credential_grants", "credential_references"):
        page, status = rest.project(name, "get", P1, actor=PLATFORM, mode=ADMINISTRATION)
        assert status == 200 and all("escalated" not in row for row in page["rows"])
    assert rest.admin_calls == []


def test_the_owners_own_list_is_unchanged_in_project_mode(rest):
    payload, status = rest.project("credential_references", "get", P1, actor=MEMBER, query={"mine": "true"})
    assert status == 200 and payload == {"total": 0, "rows": []} and rest.admin_calls == []


def test_the_escalation_rule():
    from fixtures.governance import GOV  # pylint: disable=C0415
    inbox = GOV.module("utils.credential_inbox")
    assert inbox.escalated(frozenset(), 3) and inbox.escalated({3}, 3, None) and not inbox.escalated({3, 4}, 3)
    assert inbox.reference_waiting("validated", None) and not inbox.reference_waiting("validated", 7)
    assert not inbox.reference_waiting("active", None)
