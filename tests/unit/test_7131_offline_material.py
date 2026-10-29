"""C-1009 #7131: the store adapter of a mandate owner's offline delegated consent (their refresh token).

The real service runs on real tables; the store and the audit trail are fakes. Every value here is a made-up test value.
"""
import json
import uuid

import pytest
from pydantic import SecretStr

from run_tests import StubLog

PROJECT = 3
OWNER = 9
SUBJECT = "idp:tid-1:oid-9"
HOLDER = f"mandate:{uuid.uuid4()}"
TOKEN = "offline-refresh-token-made-up-0001"
ROTATED = "offline-refresh-token-made-up-0002"


@pytest.fixture(name="om")
def _om(gov):
    StubLog.records.clear()
    return gov.module("utils.credential_offline_material")


def keep(om, **over):
    values = dict(holder_ref=HOLDER, custodian_user_id=OWNER, custodian_subject_ref=SUBJECT, source="login",
                  refresh_token=SecretStr(TOKEN), actor_user_id=OWNER)
    values.update(over)
    return om.keep(PROJECT, **values)


def release(om, ref, **over):
    values = dict(holder_ref=HOLDER, custodian_subject_ref=SUBJECT, release_id=str(uuid.uuid4()),
                  actor_ref="elitea_core:release")
    values.update(over)
    return om.release(PROJECT, ref, **values)


def row(gov, ref):
    [found] = gov.db.execute(PROJECT, "SELECT * FROM tenant.credential_offline_material WHERE id = :id",
                             id=uuid.UUID(ref).hex if gov.db.engine(PROJECT).dialect.name == "sqlite" else ref)
    return found


def everything_said(gov):
    return json.dumps(gov.db.events(PROJECT)) + "\n".join(str(record) for record in StubLog.records)


def test_a_consent_is_kept_in_the_governed_store_and_the_row_holds_no_value(gov, om):
    answer = keep(om)
    assert answer["ok"] is True and answer["generation"] == 1
    ref = answer["material_ref"]
    store = gov.stores.stores["database"]
    assert store.versions[uuid.UUID(ref)] == {1: {"refresh_token": TOKEN}}
    assert [call[:2] for call in store.calls] == [("write", "onboard")]
    found = row(gov, ref)
    assert (found["state"], found["generation"], found["holder_ref"], found["custodian_subject_ref"],
            found["custodian_user_id"], found["source"]) == ("active", 1, HOLDER, SUBJECT, OWNER, "login")
    assert TOKEN not in json.dumps(found, default=str)
    [event] = gov.db.events(PROJECT)
    assert (event["event_type"], event["reason_code"], event["credential_ref"], event["user_ref"],
            event["mandate_ref"]) == ("lifecycle", "CREDENTIAL_OFFLINE_MATERIAL_KEPT", ref, SUBJECT, HOLDER[8:])
    assert TOKEN not in everything_said(gov)


@pytest.mark.parametrize("over", [
    {"actor_user_id": 10},                  # someone else cannot consent for the owner
    {"source": "keycloak"},
    {"holder_ref": ""},
    {"refresh_token": SecretStr("")},
    {"refresh_token": SecretStr("x" * 16_385)},
    {"custodian_user_id": True},
])
def test_a_consent_that_is_not_the_custodians_own_well_formed_one_is_refused_with_nothing_written(gov, om, over):
    assert keep(om, **over) == {"ok": False, "reason_code": "INVALID_REQUEST"}
    assert gov.stores.stores["database"].versions == {} and gov.db.events(PROJECT) == []


def test_the_token_is_released_only_to_its_own_holder_and_custodian(gov, om):
    ref = keep(om)["material_ref"]
    answer = release(om, ref)
    assert answer["ok"] is True and answer["refresh_token"].get_secret_value() == TOKEN
    assert (answer["source"], answer["generation"]) == ("login", 1)
    assert gov.stores.stores["database"].calls[-1][:2] == ("read", "release")
    for over in ({"holder_ref": f"mandate:{uuid.uuid4()}"}, {"custodian_subject_ref": "idp:tid-1:oid-10"}):
        before = len(gov.stores.stores["database"].calls)
        assert release(om, ref, **over) == {"ok": False, "reason_code": "OFFLINE_MATERIAL_MISMATCH"}
        assert len(gov.stores.stores["database"].calls) == before   # refused before the store is read
    assert release(om, str(uuid.uuid4())) == {"ok": False, "reason_code": "OFFLINE_MATERIAL_INACTIVE"}


def test_another_projects_material_is_not_found(gov, om):
    ref = keep(om)["material_ref"]
    assert om.release(PROJECT + 1, ref, holder_ref=HOLDER, custodian_subject_ref=SUBJECT, release_id="r",
                      actor_ref="a") == {"ok": False, "reason_code": "OFFLINE_MATERIAL_INACTIVE"}


def test_a_retired_material_is_never_released_again_and_its_store_copy_is_deleted(gov, om):
    ref = keep(om)["material_ref"]
    assert om.retire(PROJECT, ref, reason="CONSENT_WITHDRAWN", caller_ref="operator:9", actor_user_id=OWNER) == {
        "ok": True, "retired": True}
    assert release(om, ref) == {"ok": False, "reason_code": "OFFLINE_MATERIAL_INACTIVE"}
    assert uuid.UUID(ref) not in gov.stores.stores["database"].versions
    assert (row(gov, ref)["state"], row(gov, ref)["retired_reason"]) == ("retired", "CONSENT_WITHDRAWN")
    assert gov.db.events(PROJECT)[-1]["reason_code"] == "CREDENTIAL_OFFLINE_MATERIAL_RETIRED"
    again = om.retire(PROJECT, ref, reason="CONSENT_WITHDRAWN", caller_ref="operator:9")
    assert again == {"ok": True, "retired": False} and len(gov.db.events(PROJECT)) == 2   # idempotent, one event
    assert om.retire(PROJECT, ref, reason="ANYTHING", caller_ref="x") == {"ok": False, "reason_code": "INVALID_REQUEST"}


def test_a_retirement_holds_even_when_the_store_copy_cannot_be_deleted(gov, om):
    ref = keep(om)["material_ref"]
    gov.stores.stores["database"].fail["delete_all"] = "UNAVAILABLE"
    assert om.retire(PROJECT, ref, reason="HOLDER_REVOKED", caller_ref="operator:1")["ok"] is True
    assert release(om, ref) == {"ok": False, "reason_code": "OFFLINE_MATERIAL_INACTIVE"}


def test_a_rotated_token_becomes_the_next_generation_and_older_ones_are_pruned(gov, om):
    ref = keep(om)["material_ref"]
    assert om.rotate(PROJECT, ref, expected_generation=1, refresh_token=SecretStr(ROTATED),
                     caller_ref="elitea_core:release", min_interval_s=0) == {"ok": True, "generation": 2, "kept": True}
    answer = release(om, ref)
    assert answer["refresh_token"].get_secret_value() == ROTATED and answer["generation"] == 2
    om.rotate(PROJECT, ref, expected_generation=2, refresh_token=SecretStr(TOKEN + "-3"), caller_ref="x",
              min_interval_s=0)
    assert sorted(gov.stores.stores["database"].versions[uuid.UUID(ref)]) == [2, 3]
    assert [e["reason_code"] for e in gov.db.events(PROJECT)].count("CREDENTIAL_OFFLINE_MATERIAL_ROTATED") == 2
    assert ROTATED not in everything_said(gov)


def test_a_stale_or_retired_rotation_writes_nothing(gov, om):
    ref = keep(om)["material_ref"]
    assert om.rotate(PROJECT, ref, expected_generation=5, refresh_token=SecretStr(ROTATED), caller_ref="x",
                     min_interval_s=0) == {"ok": False, "reason_code": "CONCURRENT_CHANGE"}
    om.retire(PROJECT, ref, reason="CONSENT_WITHDRAWN", caller_ref="x")
    assert om.rotate(PROJECT, ref, expected_generation=1, refresh_token=SecretStr(ROTATED), caller_ref="x",
                     min_interval_s=0) == {"ok": False, "reason_code": "CONCURRENT_CHANGE"}
    assert uuid.UUID(ref) not in gov.stores.stores["database"].versions


def test_a_store_that_refuses_the_write_leaves_a_pending_row_that_is_never_released(gov, om):
    gov.stores.stores["database"].fail["write"] = "UNAVAILABLE"
    assert keep(om) == {"ok": False, "reason_code": "STORE_UNAVAILABLE"}
    [found] = gov.db.execute(PROJECT, "SELECT * FROM tenant.credential_offline_material")
    assert (found["state"], found["generation"]) == ("pending", 0)


def test_a_value_written_whose_row_cannot_be_activated_is_deleted_from_the_store(gov, om):
    gov.tracing.fail = True   # the activation's audit event cannot be recorded
    assert keep(om) == {"ok": False, "reason_code": "AUDIT_UNAVAILABLE"}
    [found] = gov.db.execute(PROJECT, "SELECT * FROM tenant.credential_offline_material")
    assert found["state"] == "retired" and found["generation"] == 0
    assert gov.stores.stores["database"].versions == {}   # nothing left at rest
    assert [call[:2] for call in gov.stores.stores["database"].calls] == [("write", "onboard"), ("delete_all", "retire")]


def test_a_rotation_is_kept_at_most_once_a_day(gov, om):
    ref = keep(om)["material_ref"]
    assert om.rotate(PROJECT, ref, expected_generation=1, refresh_token=SecretStr(ROTATED), caller_ref="x") == {
        "ok": True, "generation": 1, "kept": False}   # just kept: the token in the store stays valid
    assert gov.stores.stores["database"].calls[-1][0] == "write" and len(gov.stores.stores["database"].calls) == 1
    later = __import__("datetime").datetime.now(__import__("datetime").timezone.utc) + \
        __import__("datetime").timedelta(days=1, minutes=1)
    assert om.rotate(PROJECT, ref, expected_generation=1, refresh_token=SecretStr(ROTATED), caller_ref="x",
                     now=later)["kept"] is True
