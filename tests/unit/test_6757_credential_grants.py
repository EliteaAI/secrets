"""C-1009 (#6757): credential use grants - an agent binding may use a reference for one user, once a second operator approves."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from fixtures.governance import BINDING, TOOL_MAPPING

PROJECT = 3
CREATOR, APPROVER, OTHER = 10, 20, 30
SUBJECT = "idp:tenant-1:oid-1"
TOOLKIT = 41


@pytest.fixture
def grants(gov):
    return gov.module("utils.credential_grants")


def add_binding(gov, project_id=PROJECT, application_id=5, version_id=9, tools=(TOOLKIT,), entity_type="agent"):
    binding_ref = uuid.uuid4()
    with gov.db.get_session(project_id) as session:
        session.execute(BINDING.insert().values(
            id=binding_ref, project_id=project_id, application_id=application_id, version_id=version_id))
        for tool_id in tools:
            session.execute(TOOL_MAPPING.insert().values(
                tool_id=tool_id, entity_version_id=version_id, entity_type=entity_type))
        session.commit()
    return str(binding_ref)


class Setup:
    def __init__(self, gov, grants):
        self.gov, self.grants = gov, grants
        self.binding = add_binding(gov)
        self.ref = str(gov.add_reference(PROJECT, state="active"))
        self.results = []

    def run(self, actor=CREATOR, project_id=PROJECT, dry_run=False, **overrides):
        values = dict(project_id=project_id, binding_ref=self.binding, toolkit_id=TOOLKIT, ref=self.ref,
                      subject_ref=SUBJECT)
        values.update(overrides)
        param = ";".join(f"{key}={value}" for key, value in values.items() if value is not None)
        result = self.grants.manage_grant(param + (";dry_run" if dry_run else ""), actor)
        self.results.append(result)
        return result

    def create(self, **kw):
        result = self.run(action="create", **kw)
        assert "error" not in result, result
        self.grant_id = result["grant"]
        return result

    def active(self):
        self.create()
        result = self.run(APPROVER, action="approve", approval_ref="CHG-7", policy_revision="rev-7")
        assert "error" not in result, result

    @property
    def row(self):
        return self.gov.grant(PROJECT, uuid.UUID(self.grant_id))

    @property
    def events(self):
        return self.gov.db.events(PROJECT)


@pytest.fixture
def setup(gov, grants):
    return Setup(gov, grants)


# --- parameters ---------------------------------------------------------------------------------------------------

def base(**kw):
    values = dict(project_id=3, action="create", binding_ref=str(uuid.uuid4()), toolkit_id=41, ref=str(uuid.uuid4()),
                  subject_ref=SUBJECT)
    values.update(kw)
    return ";".join(f"{key}={value}" for key, value in values.items() if value is not None)


@pytest.mark.parametrize("param, fragment", [
    ("", "project_id, action, binding_ref, toolkit_id, ref, subject_ref required"),
    (base(project_id=None), "project_id"), (base(binding_ref=None), "binding_ref"), (base(toolkit_id=None), "toolkit_id"),
    (base(ref=None), "ref required"), (base(subject_ref=None), "subject_ref"),
    (base(action="erase"), "invalid action"), (base(project_id="x"), "invalid project_id"),
    (base(toolkit_id="0"), "invalid toolkit_id"), (base(toolkit_id="abc"), "invalid toolkit_id"),
    (base(binding_ref="nope"), "invalid binding_ref"), (base(ref="nope"), "invalid ref"),
    (base(subject_ref="oid-1"), "invalid subject_ref"), (base(subject_ref="idp:t1"), "invalid subject_ref"),
    (base(subject_ref="idp:t1:u1:x"), "invalid subject_ref"), (base(subject_ref="idp:t 1:u1"), "invalid subject_ref"),
    (base(action="approve"), "approval_ref, policy_revision required"),
    (base() + ";surprise=1", "unknown parameter"),
    (base(valid_until="tomorrow"), "invalid valid_until"),
    (base(valid_until="2099-01-01T00:00:00"), "needs an offset"),  # no offset: ambiguous
    (base(valid_until="2001-01-01T00:00:00+00:00"), "must be in the future"),
    (base(action="suspend", valid_until="2099-01-01T00:00:00+00:00"), "applies to create only"),
])
def test_bad_parameters_are_refused_before_anything_runs(gov, grants, param, fragment):
    assert fragment in grants.manage_grant(param, CREATOR)["error"]
    assert gov.db.engines == {}


def test_a_valid_until_with_an_offset_in_the_future_is_parsed(grants):
    values, error = grants.parse_grant_param(base(valid_until="2099-06-01T12:00:00+02:00"))
    assert error is None and values["valid_until"] == datetime(2099, 6, 1, 10, 0, tzinfo=timezone.utc)


# --- create -------------------------------------------------------------------------------------------------------

def test_create_records_a_pending_grant_for_the_exact_key_and_audits_it(gov, setup):
    result = setup.create()
    assert result["state"] == "pending_approval"
    row = setup.row
    assert (row.project_id, row.application_id, row.subject_kind, row.subject_ref, row.toolkit_instance_id,
            row.target_ref, row.state, row.created_by, row.revocation_epoch) == (
        PROJECT, 5, "user_delegation", SUBJECT, str(TOOLKIT), "*", "pending_approval", CREATOR, 0)
    assert (str(row.agent_binding_ref), str(row.credential_ref)) == (setup.binding, setup.ref)
    assert (row.operations, row.resource_constraints, row.obligations, row.valid_until) == (["*"], {}, {}, None)
    (event,) = setup.events
    assert (event["event_type"], event["reason_code"], event["outcome"]) == ("lifecycle", "GRANT_PENDING_APPROVAL", "success")
    assert (event["credential_ref"], event["agent_binding_ref"], event["toolkit_instance_id"], event["user_ref"],
            event["target_ref"], event["application_id"], event["caller_ref"]) == (
        setup.ref, setup.binding, str(TOOLKIT), SUBJECT, "*", 5, f"operator:{CREATOR}")


def test_create_can_set_an_expiry(gov, setup):
    until = (datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0)
    setup.create(valid_until=until.isoformat())
    assert setup.row.valid_until.replace(tzinfo=timezone.utc) == until


def test_create_refuses_what_does_not_exist_or_does_not_fit(gov, setup):
    cases = [
        (dict(ref=str(uuid.uuid4())), "REFERENCE_NOT_FOUND"),
        (dict(binding_ref=str(uuid.uuid4())), "BINDING_NOT_FOUND"),
        (dict(toolkit_id=99), "TOOLKIT_NOT_IN_BINDING"),
        (dict(binding_ref=add_binding(gov, version_id=10, tools=(77,))), "TOOLKIT_NOT_IN_BINDING"),
        (dict(binding_ref=add_binding(gov, version_id=11, tools=(TOOLKIT,), entity_type="pipeline")),
         "TOOLKIT_NOT_IN_BINDING"),
    ]
    for overrides, code in cases:
        assert setup.run(action="create", **overrides)["code"] == code, overrides
    assert setup.events == []


def test_a_binding_of_another_project_is_not_found(gov, setup):
    foreign = add_binding(gov, project_id=PROJECT + 1)
    assert setup.run(action="create", binding_ref=foreign)["code"] == "BINDING_NOT_FOUND"
    gov.db.engine(PROJECT + 1)
    assert setup.run(project_id=PROJECT + 1, action="create", binding_ref=foreign)["code"] == "REFERENCE_NOT_FOUND"


def test_a_retired_reference_cannot_be_granted(gov, setup):
    retired = str(gov.add_reference(PROJECT, state="retired"))
    assert setup.run(action="create", ref=retired)["code"] == "INVALID_STATE"


def test_the_same_grant_cannot_be_created_twice_but_another_subject_can(gov, setup):
    setup.create()
    assert setup.run(action="create")["code"] == "GRANT_EXISTS"
    assert "error" not in setup.run(action="create", subject_ref="idp:tenant-1:oid-2")


def test_dry_run_and_the_operator_requirement(gov, setup):
    assert setup.run(0, dry_run=True, action="create") == {"dry_run": True, "action": "create", "state": "pending_approval"}
    assert setup.events == []
    for actor in (0, None, True, -2):
        assert setup.run(actor, action="create")["code"] == "ACTOR_REQUIRED"
    assert setup.events == []


def test_a_failed_audit_leaves_no_grant(gov, setup):
    gov.tracing.fail = True
    assert setup.run(action="create")["code"] == "FAILED"
    gov.tracing.fail = False
    setup.create()  # nothing was left behind to collide with


# --- approve ------------------------------------------------------------------------------------------------------------

def test_a_second_operator_approves_and_the_grant_becomes_active(gov, setup):
    setup.create()
    result = setup.run(APPROVER, action="approve", approval_ref="CHG-7", policy_revision="rev-7")
    assert result == {"action": "approve", "grant": setup.grant_id, "state": "active", "dry_run": False}
    row = setup.row
    assert (row.state, row.approved_by, row.approval_ref, row.policy_revision) == ("active", APPROVER, "CHG-7", "rev-7")
    event = setup.events[-1]
    assert (event["event_type"], event["reason_code"], event["approver_ref"], event["policy_revision"]) == (
        "approval", "GRANT_ACTIVE", "CHG-7", "rev-7")


def test_the_creator_cannot_approve_their_own_grant(gov, setup):
    setup.create()
    assert setup.run(CREATOR, action="approve", approval_ref="CHG-7", policy_revision="rev-7")["code"] == "SELF_APPROVAL"
    assert setup.row.state == "pending_approval" and len(setup.events) == 1


def test_approval_happens_once_and_only_for_a_pending_grant(gov, setup):
    setup.active()
    assert setup.run(OTHER, action="approve", approval_ref="CHG-8", policy_revision="rev-8")["code"] == "INVALID_STATE"
    assert setup.row.approved_by == APPROVER


def test_approving_a_grant_that_does_not_exist(gov, setup):
    assert setup.run(APPROVER, action="approve", approval_ref="a", policy_revision="p")["code"] == "GRANT_NOT_FOUND"


# --- suspend, resume, revoke ---------------------------------------------------------------------------------------------------

def test_suspend_resume_revoke_raise_the_epoch_where_they_take_the_grant_out_of_use(gov, setup):
    setup.active()
    assert setup.run(APPROVER, action="suspend")["state"] == "suspended"
    assert setup.row.revocation_epoch == 1 and setup.events[-1]["revocation_epoch"] == 1
    assert setup.run(APPROVER, action="resume")["state"] == "active"
    assert setup.row.revocation_epoch == 1
    assert setup.run(APPROVER, action="revoke")["state"] == "revoked"
    assert setup.row.revocation_epoch == 2
    assert [event["reason_code"] for event in setup.events] == [
        "GRANT_PENDING_APPROVAL", "GRANT_ACTIVE", "GRANT_SUSPENDED", "GRANT_ACTIVE", "GRANT_REVOKED"]


def test_a_pending_grant_can_be_revoked_and_a_revoked_one_stays_revoked(gov, setup):
    setup.create()
    assert setup.run(APPROVER, action="revoke")["state"] == "revoked"
    for action in ("resume", "suspend", "revoke"):
        assert setup.run(APPROVER, action=action)["code"] == "INVALID_STATE"
    assert setup.run(APPROVER, action="approve", approval_ref="a", policy_revision="p")["code"] == "INVALID_STATE"


@pytest.mark.parametrize("action", ["resume", "suspend"])
def test_moves_from_the_wrong_state_are_refused(gov, setup, action):
    setup.create()  # pending approval: neither resumable nor suspendable
    assert setup.run(APPROVER, action=action)["code"] == "INVALID_STATE"
    assert setup.row.state == "pending_approval"


def test_moves_of_an_unknown_grant(gov, setup):
    assert setup.run(APPROVER, action="suspend")["code"] == "GRANT_NOT_FOUND"


def test_dry_runs_report_without_changing(gov, setup):
    setup.active()
    before = len(setup.events)
    assert setup.run(0, dry_run=True, action="suspend") == {
        "dry_run": True, "action": "suspend", "grant": setup.grant_id, "from": "active", "to": "suspended"}
    assert setup.row.state == "active" and len(setup.events) == before


def test_a_failed_audit_rolls_a_change_back(gov, setup):
    setup.active()
    gov.tracing.fail = True
    assert setup.run(APPROVER, action="suspend")["code"] == "FAILED"
    assert setup.row.state == "active" and setup.row.revocation_epoch == 0


def test_another_project_cannot_reach_the_grant(gov, setup):
    setup.active()
    gov.db.engine(PROJECT + 1)
    assert setup.run(APPROVER, project_id=PROJECT + 1, action="suspend")["code"] == "GRANT_NOT_FOUND"
    assert setup.row.state == "active"
