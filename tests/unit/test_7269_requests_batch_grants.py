"""C-1009 #7269 phase 2 in the secrets plugin: a member's references and grants filed inside elitea_core's batch (one
transaction), batch granting on approval, and the owner's consent notice.

The lifecycles run for real over SQLite with the fakes of ``test_7119_credential_api``. The batch's session is a real
session wrapped as elitea_core wraps it (its commit is a flush); the test commits or rolls it back as the batch does.
"""
import sys
import types
import uuid
from pathlib import Path

import pytest

from run_tests import StubAuth

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_7119_credential_api import APPROVER, CREATOR, MEMBER, P1, TOOLKIT, UNLINKED, Rest  # noqa: E402

APPROVAL = {"approval_ref": "CHG-7269", "policy_revision": "rev-1"}


class OneTransaction:
    def __init__(self, session):
        self._session = session

    def commit(self):
        self._session.flush()

    def __getattr__(self, name):
        return getattr(self._session, name)


@pytest.fixture
def rest(gov, monkeypatch):
    rest = Rest(gov, monkeypatch)
    rest.requests = gov.module("utils.credential_requests")
    rest.batch = gov.module("utils.credential_grant_batch")
    monkeypatch.setattr(StubAuth, "list_project_roles", staticmethod(
        lambda project_id: [{"id": 1, "name": "editor"}, {"id": 2, "name": "admin"}]), raising=False)
    rest.fired = []
    fake_this = types.SimpleNamespace(
        module=types.SimpleNamespace(context=types.SimpleNamespace(event_manager=types.SimpleNamespace(
            fire_event=lambda name, payload: rest.fired.append((name, payload))))),
        for_module=lambda name: types.SimpleNamespace(descriptor=types.SimpleNamespace(config={
            "mandate_identity_sources": list(rest.sources)})))
    rest.sources = []
    monkeypatch.setattr(rest.batch, "this", fake_this)
    return rest


def in_batch(rest, items, actor=MEMBER, commit=True):
    with rest.gov.db.get_session(P1) as raw:
        try:
            filed = rest.requests.file_requests(OneTransaction(raw), P1, items, actor)
        except Exception:
            raw.rollback()
            raise
        if commit:
            raw.commit()
        else:
            raw.rollback()
    return filed


# --- inside the batch ---------------------------------------------------------------------------------------------

def test_a_members_reference_is_their_own_personal_one_and_lands_in_the_batchs_transaction(rest):
    config = rest.gov.configurations.add(P1)
    [made] = in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": config.uuid}])
    row = rest.gov.reference(P1, uuid.UUID(made["id"]))
    assert (row.state, row.ownership_class, row.created_by, row.custodian_ref["user_id"]) == (
        "pending", "personal", MEMBER, MEMBER)
    assert [event["reason_code"] for event in rest.events()] == ["CREDENTIAL_REF_PENDING"]


def test_nothing_of_the_batch_stays_when_it_is_rolled_back(rest):
    config = rest.gov.configurations.add(P1)
    in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": config.uuid}], commit=False)
    assert rest.list_refs()[0]["total"] == 0 and rest.events() == []


def test_a_grant_in_the_batch_sees_the_reference_made_before_it_and_is_the_members(rest):
    binding = rest.seed_binding()
    config = rest.gov.configurations.add(P1)
    subject = "idp:t1:o30"
    filed = in_batch(rest, [
        {"kind": "reference", "key": "r", "configuration_uuid": config.uuid},
    ])
    [grant] = in_batch(rest, [{"kind": "grant", "key": "g", "binding_ref": binding, "toolkit_id": TOOLKIT,
                               "ref": filed[0]["id"], "subject_ref": subject, "subject_user_id": MEMBER}])
    page = rest.list_grants()[0]
    assert [(row["id"], row["state"], row["created_by"]["id"]) for row in page["rows"]] == [
        (grant["id"], "pending_approval", MEMBER)]


def test_a_member_asks_for_their_own_grants_only(rest):
    binding = rest.seed_binding()
    ref = str(rest.gov.add_reference(P1, state="active"))
    with pytest.raises(Exception) as refused:
        in_batch(rest, [{"kind": "grant", "key": "g", "binding_ref": binding, "toolkit_id": TOOLKIT, "ref": ref,
                         "subject_ref": "idp:t1:o10", "subject_user_id": CREATOR}])
    assert refused.value.code == "FORBIDDEN" and rest.list_grants()[0]["total"] == 0


def test_a_refused_item_names_itself_and_rolls_the_batch_back(rest):
    binding = rest.seed_binding()
    ref = str(rest.gov.add_reference(P1, state="active"))
    item = {"kind": "grant", "key": "g", "binding_ref": binding, "toolkit_id": TOOLKIT, "ref": ref,
            "subject_ref": "idp:t1:o30", "subject_user_id": MEMBER}
    in_batch(rest, [item])
    with pytest.raises(Exception) as refused:
        in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": rest.gov.configurations.add(P1).uuid},
                        {**item, "key": "g2"}])
    assert (refused.value.code, refused.value.key) == ("GRANT_EXISTS", "g2")
    assert rest.list_refs()[0]["total"] == 1   # the first batch's reference only (its own reference in the second: gone)


# --- batch granting on approval ----------------------------------------------------------------------------------

def requested_grant(rest):
    binding = rest.seed_binding()
    ref = str(rest.gov.add_reference(P1, state="active"))
    body, status = rest.create_grant(binding, ref, subject_user_id=MEMBER, actor=MEMBER)
    assert status == 201, body
    return body["id"], binding, ref


def test_the_approver_grants_the_same_use_to_other_members_in_one_transaction(rest):
    grant, binding, ref = requested_grant(rest)
    body, status = rest.grant_action(grant, "approve", actor=APPROVER, also_grant_to=[CREATOR], **APPROVAL)
    assert status == 200 and body["state"] == "active" and len(body["siblings"]) == 1, body
    rows = {row["subject"]["user"]["id"]: row for row in rest.list_grants()[0]["rows"]}
    assert set(rows) == {MEMBER, CREATOR}
    sibling = rows[CREATOR]
    # four-eyes holds for the sibling: filed under the member's request, approved by the same approver
    assert (sibling["state"], sibling["created_by"]["id"], sibling["approved_by"]["id"], sibling["approval_ref"]) == (
        "active", MEMBER, APPROVER, "CHG-7269")
    codes = [event["reason_code"] for event in rest.events()]
    assert codes.count("GRANT_ACTIVE") == 2 and codes.count("GRANT_BATCH_SIBLING") == 1


def test_a_role_grants_to_its_members_and_skips_who_cannot_hold_a_grant(rest):
    grant, *_ = requested_grant(rest)
    body, status = rest.grant_action(grant, "approve", actor=APPROVER, also_grant_role="editor", **APPROVAL)
    assert status == 200, body
    assert MEMBER in body["skipped"] and UNLINKED in body["skipped"]   # already holds it; no linked sign-in
    assert len(body["siblings"]) == 2   # the creator and the approver (any member may be granted to)


def test_a_sibling_that_fails_rolls_the_approval_back(rest):
    grant, *_ = requested_grant(rest)
    body, status = rest.grant_action(grant, "approve", actor=APPROVER, also_grant_to=[UNLINKED], **APPROVAL)
    assert (status, body["code"]) == (409, "SUBJECT_UNLINKED")
    assert {row["state"] for row in rest.list_grants()[0]["rows"]} == {"pending_approval"}


def test_the_requester_cannot_approve_with_siblings_either(rest):
    grant, *_ = requested_grant(rest)
    body, status = rest.grant_action(grant, "approve", actor=MEMBER, also_grant_to=[CREATOR], **APPROVAL)
    assert (status, body["code"]) == (403, "SELF_APPROVAL")
    assert rest.list_grants()[0]["total"] == 1


def test_a_personal_credential_has_no_siblings_and_others_than_approve_take_none(rest):
    binding = rest.seed_binding()
    ref = str(rest.gov.add_reference(P1, state="active", ownership_class="personal",
                                     custodian_ref={"user_id": MEMBER, "subject_ref": "idp:t1:o30"}))
    body, status = rest.create_grant(binding, ref, subject_user_id=MEMBER, actor=MEMBER)
    assert status == 201, body
    reply = rest.grant_action(body["id"], "approve", actor=APPROVER, also_grant_to=[CREATOR], **APPROVAL)
    assert reply[1] == 409 and reply[0]["code"] == "NO_SIBLINGS"
    assert rest.grant_action(body["id"], "suspend", also_grant_to=[CREATOR])[1] == 400


def test_members_outside_the_project_are_refused(rest):
    grant, *_ = requested_grant(rest)
    body, status = rest.grant_action(grant, "approve", actor=APPROVER, also_grant_to=[999], **APPROVAL)
    assert (status, body["code"]) == (400, "OWNER_NOT_MEMBER")


# --- the owner's consent notice ----------------------------------------------------------------------------------

def test_an_approved_grant_on_a_sign_in_credential_asks_its_mandate_owner_for_consent(rest):
    from fixtures.governance import MANDATE  # pylint: disable=C0415
    binding = rest.seed_binding()
    mandate = uuid.uuid4()
    with rest.gov.db.get_session(P1) as session:
        session.execute(MANDATE.insert().values(id=mandate, project_id=P1, agent_binding_ref=uuid.UUID(binding),
                                                owner_user_id=MEMBER, state="pending_approval"))
        session.commit()
    ref = str(rest.gov.add_reference(P1, state="active", auth_mode="entra_delegated"))
    grant = rest.gov.add_grant(P1, credential_ref=uuid.UUID(ref), agent_binding_ref=uuid.UUID(binding),
                               toolkit_instance_id=str(TOOLKIT), subject_kind="mandate", subject_ref=f"mandate:{mandate}")
    assert rest.grant_action(grant, "approve", actor=APPROVER, **APPROVAL)[1] == 200
    [(name, payload)] = rest.fired
    assert (name, payload["user_id"], payload["event_type"], payload["meta"]["target"]) == (
        "notifications_stream", MEMBER, "governance_consent_needed", "schedules")


def test_a_persons_grant_asks_for_consent_only_where_tokens_may_act_with_the_sign_in(rest):
    binding = rest.seed_binding()
    ref = str(rest.gov.add_reference(P1, state="active", auth_mode="entra_delegated"))
    body, _ = rest.create_grant(binding, ref, subject_user_id=MEMBER, actor=MEMBER)
    rest.grant_action(body["id"], "approve", actor=APPROVER, **APPROVAL)
    assert rest.fired == []
    rest.sources = ["token_owner_delegated"]
    assert rest.batch.notify_consent(P1, body["id"]) is True
    assert rest.fired[-1][1]["meta"]["target"] == "tokens" and rest.fired[-1][1]["user_id"] == MEMBER


def test_a_stored_secret_asks_nobody(rest):
    grant, *_ = requested_grant(rest)
    rest.sources = ["token_owner_delegated"]
    rest.grant_action(grant, "approve", actor=APPROVER, **APPROVAL)
    assert rest.fired == []
