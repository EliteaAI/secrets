"""C-1009 #7337: the delegated references a scoped token's owner may name in their consent."""
from datetime import datetime, timedelta, timezone

import pytest

PROJECT = 3
SUBJECT = "idp:t1:u9"
OWNER = 9


@pytest.fixture
def listed(gov):
    method = gov.module("methods.credential_facts")
    return lambda *args, **kw: method.Method.delegated_references_of(object(), *args, **kw)


def delegated(gov, **over):
    return gov.add_reference(PROJECT, **{"state": "active", "auth_mode": "entra_delegated", **over})


def test_only_the_owners_own_and_granted_delegated_references_are_listed(gov, listed):
    mine = delegated(gov, ownership_class="personal", custodian_ref={"user_id": OWNER, "subject_ref": SUBJECT})
    theirs = delegated(gov, ownership_class="personal", custodian_ref={"user_id": 10, "subject_ref": "idp:t1:u10"})
    shared = delegated(gov)
    gov.add_grant(PROJECT, state="active", credential_ref=shared, subject_ref=SUBJECT)
    ungranted = delegated(gov)
    static = gov.add_reference(PROJECT, state="active", ownership_class="personal",
                               custodian_ref={"user_id": OWNER, "subject_ref": SUBJECT})   # a stored secret
    pending = delegated(gov, state="pending", ownership_class="personal",
                        custodian_ref={"user_id": OWNER, "subject_ref": SUBJECT})
    found = listed(PROJECT, SUBJECT, OWNER)
    assert {item["ref_id"] for item in found} == {str(mine), str(shared)}
    for absent in (theirs, ungranted, static, pending):
        assert str(absent) not in {item["ref_id"] for item in found}
    assert set(found[0]) == {"ref_id", "configuration_id", "configuration_uuid", "generation",
                             "configuration_generation", "ownership_class"}


@pytest.mark.parametrize("grant", [
    {"state": "pending_approval"}, {"state": "revoked"},
    {"state": "active", "valid_until": datetime.now(timezone.utc) - timedelta(hours=1)},
    {"state": "active", "valid_from": datetime.now(timezone.utc) + timedelta(hours=1)},
    {"state": "active", "subject_ref": "idp:t1:u10"},
])
def test_a_shared_reference_needs_an_active_grant_in_force_to_the_owner(gov, listed, grant):
    shared = delegated(gov)
    gov.add_grant(PROJECT, credential_ref=shared, **{"subject_ref": SUBJECT, **grant})
    assert listed(PROJECT, SUBJECT, OWNER) == []


def test_another_projects_references_are_not_listed_and_the_caller_is_checked(gov, listed):
    delegated(gov, ownership_class="personal", custodian_ref={"user_id": OWNER, "subject_ref": SUBJECT})
    assert listed(PROJECT + 1, SUBJECT, OWNER) == []
    for subject, user in ((None, OWNER), (SUBJECT, None), ("", OWNER), (SUBJECT, True)):
        with pytest.raises(ValueError):
            listed(PROJECT, subject, user)
