"""C-1009 (#6757): credential_use_facts - what admission reads about references and grants."""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

PROJECT = 3
SUBJECT = "idp:t1:u1"


@pytest.fixture
def facts(gov):
    method = gov.module("methods.credential_facts")
    return lambda *args, **kw: method.Method.credential_use_facts(object(), *args, **kw), method


def grant_key(grant):
    return (grant.agent_binding_ref, grant.toolkit_instance_id, grant.credential_ref, grant.target_ref, grant.subject_ref)


def test_references_are_keyed_by_configuration_id_with_the_documented_shape(gov, facts):
    call, _ = facts
    ref_id = gov.add_reference(PROJECT, state="active", ownership_class="service", store_kind="corporate_vault",
                               configuration_generation=4, revocation_epoch=2)
    row = gov.reference(PROJECT, ref_id)
    result = call(PROJECT, [row.configuration_id], [])
    assert result == {"references": {row.configuration_id: {
        "ref_id": str(ref_id), "state": "active", "generation": 1, "configuration_generation": 4,
        "store_kind": "corporate_vault", "ownership_class": "service", "revocation_epoch": 2}}, "grants": {}}


def test_ref_ids_find_the_same_rows_and_the_selectors_combine(gov, facts):
    call, _ = facts
    first, second = gov.add_reference(PROJECT), gov.add_reference(PROJECT)
    one, two = gov.reference(PROJECT, first), gov.reference(PROJECT, second)
    by_ref = call(PROJECT, [], [], ref_ids=[str(second)])
    assert list(by_ref["references"]) == [two.configuration_id]
    both = call(PROJECT, [one.configuration_id], [], ref_ids=[second])
    assert set(both["references"]) == {one.configuration_id, two.configuration_id}
    overlap = call(PROJECT, [two.configuration_id], [], ref_ids=[second])
    assert list(overlap["references"]) == [two.configuration_id]


def test_retired_references_and_other_projects_are_not_returned(gov, facts):
    call, _ = facts
    retired = gov.reference(PROJECT, gov.add_reference(PROJECT, state="retired"))
    live = gov.reference(PROJECT, gov.add_reference(PROJECT))
    foreign = gov.reference(PROJECT + 1, gov.add_reference(PROJECT + 1))
    result = call(PROJECT, [retired.configuration_id, live.configuration_id, foreign.configuration_id], [])
    assert list(result["references"]) == [live.configuration_id]
    assert call(PROJECT + 1, [live.configuration_id], []) == {"references": {}, "grants": {}}


def test_a_retired_reference_does_not_hide_its_live_replacement(gov, facts):
    call, _ = facts
    old = gov.reference(PROJECT, gov.add_reference(PROJECT, state="retired", configuration_id=77))
    new = gov.add_reference(PROJECT, configuration_id=77)
    assert call(PROJECT, [old.configuration_id], [])["references"][77]["ref_id"] == str(new)


def test_grants_are_keyed_by_the_pipe_joined_key_in_tuple_or_dict_form(gov, facts):
    call, method = facts
    until = datetime.now(timezone.utc) + timedelta(days=1)
    grant_id = gov.add_grant(PROJECT, state="active", valid_until=until, revocation_epoch=3, operations=["read"])
    row = gov.grant(PROJECT, grant_id)
    key = grant_key(row)
    text_key = "|".join(str(part) for part in key)
    as_dict = dict(zip(method.KEY_FIELDS, key))
    for form in (key, list(key), as_dict):
        result = call(PROJECT, [], [form])
        assert list(result["grants"]) == [text_key]
        found = result["grants"][text_key]
        assert (found["grant_id"], found["state"], found["revocation_epoch"], found["operations"]) == (
            str(grant_id), "active", 3, ["read"])
        assert found["valid_from"] and datetime.fromisoformat(found["valid_until"]).replace(tzinfo=timezone.utc) == \
            until.replace(tzinfo=timezone.utc, microsecond=until.microsecond)


def test_only_the_exact_key_matches_and_revoked_grants_are_not_returned(gov, facts):
    call, _ = facts
    binding, ref = uuid.uuid4(), uuid.uuid4()
    base = dict(agent_binding_ref=binding, credential_ref=ref, toolkit_instance_id="41", subject_ref=SUBJECT)
    live = gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", **base))
    other_subject = gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", **{**base, "subject_ref": "idp:t1:u2"}))
    other_toolkit = gov.grant(PROJECT, gov.add_grant(PROJECT, state="suspended", **{**base, "toolkit_instance_id": "42"}))
    revoked = gov.grant(PROJECT, gov.add_grant(PROJECT, state="revoked", **{**base, "subject_ref": "idp:t1:u3"}))
    result = call(PROJECT, [], [grant_key(live), grant_key(revoked), (binding, "42", uuid.uuid4(), "*", SUBJECT)])
    assert list(result["grants"]) == ["|".join(str(p) for p in grant_key(live))]
    # an IN list built from separate columns must not return the cross product of the asked keys
    asked = call(PROJECT, [], [grant_key(live), grant_key(other_toolkit)])
    assert len(asked["grants"]) == 2 and asked["grants"][
        "|".join(str(p) for p in grant_key(other_toolkit))]["state"] == "suspended"
    assert other_subject.subject_ref not in json.dumps(asked)


def test_the_cross_product_of_asked_keys_is_not_returned(gov, facts):
    call, _ = facts
    b1, b2, r1, r2 = (uuid.uuid4() for _ in range(4))
    wanted = [gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", agent_binding_ref=b1, credential_ref=r1)),
              gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", agent_binding_ref=b2, credential_ref=r2))]
    gov.add_grant(PROJECT, state="active", agent_binding_ref=b1, credential_ref=r2)  # a pairing nobody asked for
    result = call(PROJECT, [], [grant_key(row) for row in wanted])
    assert len(result["grants"]) == 2


def test_grants_of_another_project_are_not_returned(gov, facts):
    call, _ = facts
    row = gov.grant(PROJECT + 1, gov.add_grant(PROJECT + 1, state="active"))
    assert call(PROJECT, [], [grant_key(row)]) == {"references": {}, "grants": {}}
    assert len(call(PROJECT + 1, [], [grant_key(row)])["grants"]) == 1


def test_nothing_asked_means_an_empty_answer(gov, facts):
    call, _ = facts
    assert call(PROJECT, [], []) == {"references": {}, "grants": {}}
    assert call(PROJECT, None, None) == {"references": {}, "grants": {}}


def test_two_queries_at_most(gov, facts):
    import sqlalchemy as sa  # pylint: disable=C0415
    call, _ = facts
    ref = gov.reference(PROJECT, gov.add_reference(PROJECT, state="active"))
    grant = gov.grant(PROJECT, gov.add_grant(PROJECT, state="active"))
    statements = []
    engine = gov.db.engine(PROJECT)
    sa.event.listen(engine, "before_cursor_execute", lambda *a: statements.append(a[2]))
    call(PROJECT, [ref.configuration_id], [grant_key(grant)], ref_ids=[ref.id])
    assert len([s for s in statements if s.lstrip().upper().startswith("SELECT")]) == 2


def test_limits_and_malformed_selectors(gov, facts):
    call, _ = facts
    ids = list(range(1, 65))
    assert call(PROJECT, ids, []) == {"references": {}, "grants": {}}
    key = (uuid.uuid4(), "1", uuid.uuid4(), "*", SUBJECT)
    for args, kwargs in (
            ((ids + [65], []), {}), (([], [key] * 65), {}), (([], []), {"ref_ids": [uuid.uuid4()] * 65}),
            (("x", []), {}), (([], "x"), {}), ((["a"], []), {}), (([], [("only", "three", "parts")]), {}),
            (([], [("not-a-uuid", "1", str(uuid.uuid4()), "*", SUBJECT)]), {}),
            (([], [{"agent_binding_ref": str(uuid.uuid4())}]), {}), (([], []), {"ref_ids": ["nope"]}),
    ):
        with pytest.raises(ValueError):
            call(PROJECT, *args, **kwargs)
    assert call(PROJECT, [], [key] * 64) == {"references": {}, "grants": {}}  # duplicates collapse, 64 is allowed


def test_the_answer_has_no_locator_secret_or_store_path(gov, facts):
    call, _ = facts
    ref = gov.reference(PROJECT, gov.add_reference(PROJECT, state="active", store_locator={"section": "credential_store"}))
    grant = gov.grant(PROJECT, gov.add_grant(PROJECT, state="active"))
    blob = json.dumps(call(PROJECT, [ref.configuration_id], [grant_key(grant)]))
    for forbidden in ("locator", "credential_store", "section", "approval", "approved_by", "created_by"):
        assert forbidden not in blob
