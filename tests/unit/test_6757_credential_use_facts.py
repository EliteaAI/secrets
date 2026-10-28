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
        "store_kind": "corporate_vault", "ownership_class": "service", "revocation_epoch": 2,
        "custodian_user_id": None, "custodian_subject_ref": None, "auth_mode": "static_secret"}}, "grants": {}}


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
        assert found["subject_kind"] == "user_delegation"
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


# --- WP-1C slice 1 (#6947): subject kind and custodian ------------------------------------------------------------------

def test_the_facts_version_is_exported_where_a_startup_check_can_read_it(gov, facts):
    _, method = facts
    assert method.CREDENTIAL_FACTS_VERSION == 5 == method.Method.CREDENTIAL_FACTS_VERSION
    assert method.Method.credential_facts_version(object()) == 5


def test_grant_facts_carry_the_subject_kind_for_both_kinds(gov, facts):
    call, _ = facts
    mandate = f"mandate:{uuid.uuid4()}"
    rows = [gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", subject_ref=ref, subject_kind=kind))
            for ref, kind in ((SUBJECT, "user_delegation"), (mandate, "mandate"))]
    result = call(PROJECT, [], [grant_key(row) for row in rows])
    kinds = {key.rpartition("|")[2]: fact["subject_kind"] for key, fact in result["grants"].items()}
    assert kinds == {SUBJECT: "user_delegation", mandate: "mandate"}


@pytest.mark.parametrize("custodian, expected", [
    ({"user_id": 17}, 17), ({"user_id": 17, "other": 1}, 17), (None, None), ({}, None), ({"user_id": "17"}, None),
    ({"user_id": True}, None), ({"user_id": None}, None), ({"team": 4}, None), (["user_id"], None),
])
def test_reference_facts_carry_the_custodian_user_id_or_none(gov, facts, custodian, expected):
    call, _ = facts
    ref = gov.reference(PROJECT, gov.add_reference(PROJECT, state="active", custodian_ref=custodian))
    assert call(PROJECT, [ref.configuration_id], [])["references"][ref.configuration_id]["custodian_user_id"] == expected


def test_the_new_facts_still_leave_out_the_locator_and_the_custodian_record(gov, facts):
    call, _ = facts
    ref = gov.reference(PROJECT, gov.add_reference(
        PROJECT, state="active", custodian_ref={"user_id": 17, "note": "x"}, store_locator={"path": "secret/x"}))
    blob = json.dumps(call(PROJECT, [ref.configuration_id], []))
    assert "custodian_user_id" in blob
    for forbidden in ("locator", "secret/x", "note", "custodian_ref"):
        assert forbidden not in blob


# --- grants_for: references and the grants on them in one session (perf review 2026-10-21, M4/M5) ----------------------

def _count_sessions(gov, monkeypatch):
    opened = []
    real = gov.tools.db.get_session

    def counting(project_id=None):
        opened.append(project_id)
        return real(project_id)

    monkeypatch.setattr(gov.tools.db, "get_session", counting)
    return opened


def _active_with_grant(gov, toolkit="41", subject=SUBJECT, **ref_kwargs):
    ref_id = gov.add_reference(PROJECT, state="active", **ref_kwargs)
    binding = uuid.uuid4()
    grant = gov.grant(PROJECT, gov.add_grant(
        PROJECT, state="active", agent_binding_ref=binding, credential_ref=ref_id, toolkit_instance_id=toolkit,
        subject_ref=subject))
    return gov.reference(PROJECT, ref_id), grant


def test_grants_for_a_configuration_id_answers_references_and_grants_from_one_session(gov, facts, monkeypatch):
    call, method = facts
    ref, grant = _active_with_grant(gov)
    opened = _count_sessions(gov, monkeypatch)
    result = call(PROJECT, [ref.configuration_id], [], grants_for=[
        (grant.agent_binding_ref, grant.toolkit_instance_id, ref.configuration_id, "*", SUBJECT)])
    assert opened == [PROJECT]
    assert list(result["references"]) == [ref.configuration_id]
    key = method.grant_key_string((str(grant.agent_binding_ref), "41", str(ref.id), "*", SUBJECT))
    assert list(result["grants"]) == [key] and result["grants"][key]["grant_id"] == str(grant.id)


def test_grants_for_a_reference_id_is_the_same_as_grant_keys(gov, facts):
    call, _ = facts
    ref, grant = _active_with_grant(gov)
    via_keys = call(PROJECT, [], [grant_key(grant)])
    assert call(PROJECT, [], [], grants_for=[grant_key(grant)]) == via_keys
    assert call(PROJECT, [], [], grants_for=[dict(zip(
        ("agent_binding_ref", "toolkit_instance_id", "credential_ref", "target_ref", "subject_ref"), grant_key(grant)))]
    ) == via_keys


def test_grants_for_follows_the_reference_the_call_chose_for_the_caller(gov, facts):
    call, _ = facts
    owner = "idp:t1:owner"
    shared = gov.add_reference(PROJECT, state="active", configuration_id=51)
    personal = gov.add_reference(
        PROJECT, state="active", configuration_id=51, ownership_class="personal",
        custodian_ref={"user_id": 7, "subject_ref": owner})
    binding = uuid.uuid4()
    for ref in (shared, personal):
        gov.add_grant(PROJECT, state="active", agent_binding_ref=binding, credential_ref=ref, subject_ref=owner)
    wanted = [(binding, "41", 51, "*", owner)]
    mine = call(PROJECT, [51], [], personal_subject_ref=owner, grants_for=wanted)
    assert mine["references"][51]["ref_id"] == str(personal)
    assert [key.split("|")[2] for key in mine["grants"]] == [str(personal)]
    others = call(PROJECT, [51], [], personal_subject_ref="idp:t1:other", grants_for=wanted)
    assert others["references"][51]["ref_id"] == str(shared)
    assert [key.split("|")[2] for key in others["grants"]] == [str(shared)]


def test_grants_for_a_configuration_without_a_reference_has_no_grant(gov, facts):
    call, _ = facts
    result = call(PROJECT, [999], [], grants_for=[(uuid.uuid4(), "41", 999, "*", SUBJECT)])
    assert result == {"references": {}, "grants": {}}


def test_grants_for_combines_with_grant_keys_and_other_projects_stay_out(gov, facts):
    call, _ = facts
    ref, grant = _active_with_grant(gov)
    other_ref, other_grant = _active_with_grant(gov, toolkit="42")
    foreign = gov.grant(PROJECT + 1, gov.add_grant(PROJECT + 1, state="active"))
    result = call(PROJECT, [ref.configuration_id], [grant_key(other_grant)], grants_for=[
        (grant.agent_binding_ref, "41", ref.configuration_id, "*", SUBJECT), grant_key(foreign)])
    assert {key.split("|")[1] for key in result["grants"]} == {"41", "42"} and len(result["grants"]) == 2


@pytest.mark.parametrize("selectors", [1, 8, 64])
def test_one_session_whatever_the_number_of_selectors(gov, facts, monkeypatch, selectors):
    call, _ = facts
    refs = [gov.reference(PROJECT, gov.add_reference(PROJECT, state="active")) for _ in range(selectors)]
    binding = uuid.uuid4()
    keys = [(binding, "41", ref.configuration_id, "*", SUBJECT) for ref in refs]
    explicit = [(binding, "42", ref.id, "*", SUBJECT) for ref in refs]
    opened = _count_sessions(gov, monkeypatch)
    call(PROJECT, [ref.configuration_id for ref in refs], explicit, ref_ids=[ref.id for ref in refs], grants_for=keys)
    assert opened == [PROJECT]


def test_grants_for_runs_two_selects_for_references_and_grants(gov, facts):
    import sqlalchemy as sa  # pylint: disable=C0415
    call, _ = facts
    refs = [gov.reference(PROJECT, gov.add_reference(PROJECT, state="active")) for _ in range(6)]
    binding = uuid.uuid4()
    statements = []
    sa.event.listen(gov.db.engine(PROJECT), "before_cursor_execute", lambda *a: statements.append(a[2]))
    call(PROJECT, [ref.configuration_id for ref in refs], [], grants_for=[
        (binding, "41", ref.configuration_id, "*", SUBJECT) for ref in refs])
    assert len([s for s in statements if s.lstrip().upper().startswith("SELECT")]) == 2  # references, grants


def test_grants_for_limits_and_malformed_keys(gov, facts):
    call, _ = facts
    key = (uuid.uuid4(), "1", 5, "*", SUBJECT)
    assert call(PROJECT, [], [], grants_for=[key] * 64) == {"references": {}, "grants": {}}
    for bad in ([key] * 65, "x", [("only", "three", "parts")], [(uuid.uuid4(), "1", True, "*", SUBJECT)],
                [(uuid.uuid4(), "1", "not-a-uuid", "*", SUBJECT)], [(uuid.uuid4(), "1", None, "*", SUBJECT)],
                [{"agent_binding_ref": str(uuid.uuid4())}]):
        with pytest.raises(ValueError):
            call(PROJECT, [], [], grants_for=bad)


def test_a_pending_personal_reference_hides_the_grant_of_the_shared_one_it_shadows(gov, facts):
    """The owner registered a value that is still pending: the shared credential is not a silent fallback, so the grant
    on the shared reference is not offered for the owner's run (the personal reference is the chosen one)."""
    call, _ = facts
    owner = "idp:t1:owner"
    shared = gov.add_reference(PROJECT, state="active", configuration_id=61)
    personal = gov.add_reference(
        PROJECT, state="pending", configuration_id=61, ownership_class="personal",
        custodian_ref={"user_id": 7, "subject_ref": owner})
    binding = uuid.uuid4()
    gov.add_grant(PROJECT, state="active", agent_binding_ref=binding, credential_ref=shared, subject_ref=owner)
    wanted = [(binding, "41", 61, "*", owner)]
    mine = call(PROJECT, [61], [], personal_subject_ref=owner, grants_for=wanted)
    assert mine["references"][61]["ref_id"] == str(personal) and mine["references"][61]["state"] == "pending"
    assert "note" in mine["references"][61] and mine["grants"] == {}
    others = call(PROJECT, [61], [], personal_subject_ref="idp:t1:other", grants_for=wanted)   # anyone else gets the shared one
    assert others["references"][61]["ref_id"] == str(shared) and len(others["grants"]) == 1


# --- subject_grants: the active grants a subject holds on a credential, whatever the binding (#7213) ----------------

def test_subject_grants_answer_every_active_grant_of_the_subject_on_the_credential(gov, facts):
    call, _ = facts
    ref_id = gov.add_reference(PROJECT, state="active")
    first = gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", credential_ref=ref_id, toolkit_instance_id="41"))
    second = gov.grant(PROJECT, gov.add_grant(PROJECT, state="active", credential_ref=ref_id, toolkit_instance_id="42",
                                              revocation_epoch=2))
    gov.add_grant(PROJECT, state="suspended", credential_ref=ref_id, toolkit_instance_id="43")   # not active
    gov.add_grant(PROJECT, state="active", credential_ref=ref_id, subject_ref="idp:t1:u2")        # another subject
    gov.add_grant(PROJECT, state="active", subject_ref=SUBJECT)                                   # another credential
    result = call(PROJECT, [], [], subject_grants=[(ref_id, SUBJECT)])
    assert set(result) == {"references", "grants", "subject_grants"} and result["grants"] == {}
    key = f"{ref_id}|{SUBJECT}"
    assert list(result["subject_grants"]) == [key]
    found = result["subject_grants"][key]
    assert sorted((g["grant_id"], g["toolkit_instance_id"], g["agent_binding_ref"], g["revocation_epoch"]) for g in found) == sorted([
        (str(first.id), "41", str(first.agent_binding_ref), 0), (str(second.id), "42", str(second.agent_binding_ref), 2)])
    assert all(g["state"] == "active" and g["subject_kind"] == "user_delegation" and g["valid_from"] for g in found)


def test_subject_grants_by_configuration_id_follow_the_reference_the_call_resolved(gov, facts):
    call, _ = facts
    ref, grant = _active_with_grant(gov)
    result = call(PROJECT, [ref.configuration_id], [], subject_grants=[(ref.configuration_id, SUBJECT)])
    assert list(result["references"]) == [ref.configuration_id]
    assert [g["grant_id"] for g in result["subject_grants"][f"{ref.id}|{SUBJECT}"]] == [str(grant.id)]
    # a configuration with no reference, or a pair with no grant, is absent (not an empty list)
    missing = call(PROJECT, [999], [], subject_grants=[(999, SUBJECT), (uuid.uuid4(), SUBJECT)])
    assert missing == {"references": {}, "grants": {}, "subject_grants": {}}


def test_subject_grants_are_absent_from_the_answer_unless_asked_and_stay_in_the_project(gov, facts):
    call, _ = facts
    ref_id = gov.add_reference(PROJECT, state="active")
    gov.add_grant(PROJECT, state="active", credential_ref=ref_id)
    assert set(call(PROJECT, [], [])) == {"references", "grants"}
    assert call(PROJECT + 1, [], [], subject_grants=[(ref_id, SUBJECT)])["subject_grants"] == {}
    # the IN lists are a superset of the pairs: a grant pairing another asked credential with another asked subject
    other_ref = gov.add_reference(PROJECT, state="active")
    gov.add_grant(PROJECT, state="active", credential_ref=other_ref, subject_ref="idp:t1:u2")
    gov.add_grant(PROJECT, state="active", credential_ref=ref_id, subject_ref="idp:t1:u2")   # asked for by nobody
    result = call(PROJECT, [], [], subject_grants=[(ref_id, SUBJECT), (other_ref, "idp:t1:u2")])
    assert set(result["subject_grants"]) == {f"{ref_id}|{SUBJECT}", f"{other_ref}|idp:t1:u2"}
    assert all(len(found) == 1 for found in result["subject_grants"].values())


def test_subject_grants_are_bounded_and_malformed_pairs_are_refused(gov, facts):
    call, method = facts
    assert method.MAX_SUBJECT_GRANT_ROWS == 64
    with pytest.raises(ValueError):
        call(PROJECT, [], [], subject_grants=[(uuid.uuid4(), SUBJECT)] * 65)
    for bad in ([("not-a-uuid", SUBJECT)], [(uuid.uuid4(),)], [(uuid.uuid4(), "")], [(True, SUBJECT)], [(uuid.uuid4(), 5)]):
        with pytest.raises(ValueError):
            call(PROJECT, [], [], subject_grants=bad)
