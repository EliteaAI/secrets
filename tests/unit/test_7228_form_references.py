"""C-1009 #7228: the references the chat's credential form files inside elitea_core's transaction (``file_requests``):
the member's own personal one (as #7269), a team one in ``pending`` created by the member (a project admin approves it
later, four-eyes unchanged), and an Entra-delegated personal one that stores nothing. Real lifecycle over SQLite with the
fakes of ``test_7119_credential_api``; every value here is made up."""
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_7119_credential_api import MEMBER, P1  # noqa: E402
from test_7269_requests_batch_grants import in_batch, rest  # noqa: E402,F401  pylint: disable=W0611

TENANT = "11111111-2222-3333-4444-555555555555"
DESCRIPTOR = {"oauth_app_id": "platform", "tenant_id": TENANT, "resource": "https://graph.microsoft.com",
              "scopes": ["https://graph.microsoft.com/.default"], "assertion_source": "login"}


def test_a_team_reference_from_the_form_is_pending_created_by_the_member_and_has_no_custodian(rest):
    config = rest.gov.configurations.add(P1)
    [made] = in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": config.uuid,
                              "ownership_class": "project_shared"}])
    row = rest.gov.reference(P1, uuid.UUID(made["id"]))
    assert (row.state, row.ownership_class, row.created_by, row.custodian_ref) == (
        "pending", "project_shared", MEMBER, None)
    assert row.approved_by is None   # a request, never an approval
    assert [event["reason_code"] for event in rest.events()] == ["CREDENTIAL_REF_PENDING"]


def test_the_default_stays_the_members_personal_reference(rest):
    config = rest.gov.configurations.add(P1)
    [made] = in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": config.uuid}])
    row = rest.gov.reference(P1, uuid.UUID(made["id"]))
    assert (row.ownership_class, row.custodian_ref["user_id"]) == ("personal", MEMBER)


def test_a_delegated_reference_from_the_form_is_the_members_own_and_stores_nothing(rest, monkeypatch):
    monkeypatch.setattr(rest.gov.core, "entra_delegated_app_available", lambda project_id, delegation: True,
                        raising=False)
    config = rest.gov.configurations.add(P1, type_="sharepoint", secrets={})
    [made] = in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": config.uuid,
                              "auth_mode": "entra_delegated", "delegation": DESCRIPTOR}])
    row = rest.gov.reference(P1, uuid.UUID(made["id"]))
    assert (row.auth_mode, row.ownership_class, row.custodian_ref["user_id"], row.state) == (
        "entra_delegated", "personal", MEMBER, "pending")


@pytest.mark.parametrize("item", [
    {"ownership_class": "project_shared", "auth_mode": "entra_delegated", "delegation": DESCRIPTOR},   # always personal
    {"ownership_class": "platform"},
    {"auth_mode": "static_plus"},
])
def test_an_ownership_the_form_does_not_offer_is_refused_with_nothing_written(rest, item):
    config = rest.gov.configurations.add(P1)
    with pytest.raises(Exception) as refused:
        in_batch(rest, [{"kind": "reference", "key": "r", "configuration_uuid": config.uuid, **item}])
    assert refused.value.code == "INVALID_REQUEST"
    assert rest.list_refs()[0]["total"] == 0 and rest.events() == []
