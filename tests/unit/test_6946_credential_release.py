"""C-1009 (#6946, WP-1D slice 1): release_credential_material - the trusted release of one reference's material
at one generation. The real service runs on real tables; the stores, audit trail and configurations are fakes.
The tests that need the real port types (``release`` purpose rules) run when ``C1009_REAL_PORT_DIR`` is set.
"""
import os
import pickle
import uuid

import pytest

from fixtures.governance import FIXTURE_VALUE, FIXTURE_VALUE_2
from run_tests import StubLog

PROJECT = 3
RELEASE_ID = str(uuid.uuid4())
ACTOR = "elitea_core:release"
STORE_KINDS = ("database", "corporate_vault")


@pytest.fixture(name="rel")
def _rel(gov):
    StubLog.records.clear()
    service = gov.module("utils.credential_release")

    def release(ref_id, generation=2, project_id=PROJECT, release_id=RELEASE_ID, actor=ACTOR, **kw):
        return service.release_material(project_id, ref_id, generation, release_id, actor, **kw)

    return release


def stored(gov, store_kind, ref_id, **generations):
    """Put material in the store: ``g1=...`` is generation 1."""
    gov.stores.stores[store_kind].versions[ref_id] = {
        int(name[1:]): {"api_key": value} for name, value in generations.items()}


def active(gov, store_kind="database", generation=2, project_id=PROJECT, **kw):
    ref_id = gov.add_reference(project_id, state="active", generation=generation, store_kind=store_kind, **kw)
    stored(gov, store_kind, ref_id, g1=FIXTURE_VALUE, g2=FIXTURE_VALUE_2, g3="fixture-api-key-0003")
    return ref_id


def secret_of(answer):
    return answer["value"].fields["api_key"].get_secret_value()


@pytest.mark.parametrize("store_kind", STORE_KINDS)
def test_the_requested_generation_is_read_from_the_references_own_store(gov, rel, store_kind):
    ref_id = active(gov, store_kind)
    answer = rel(ref_id, 2)
    assert answer["ok"] is True and secret_of(answer) == FIXTURE_VALUE_2 and answer["value"].generation == 2
    store = gov.stores.stores[store_kind]
    assert store.calls == [("read", "release", RELEASE_ID)]  # the release purpose, the release id as decision id
    assert gov.stores.get_store_calls == [(store_kind, True)]  # governed, no other store asked
    other = next(kind for kind in STORE_KINDS if kind != store_kind)
    assert gov.stores.stores[other].calls == []


def test_a_newer_stored_generation_is_not_returned_for_an_older_reference(gov, rel):
    ref_id = active(gov, generation=2)  # the store holds a staged generation 3
    assert secret_of(rel(ref_id, 2)) == FIXTURE_VALUE_2


@pytest.mark.parametrize("requested", [1, 3, 99])
def test_a_generation_that_is_not_the_committed_one_is_refused_without_a_store_read(gov, rel, requested):
    ref_id = active(gov, generation=2)
    assert rel(ref_id, requested) == {"ok": False, "reason_code": "CREDENTIAL_GENERATION_MISMATCH"}
    assert gov.stores.stores["database"].calls == []


def test_a_generation_that_moved_after_the_decision_is_refused(gov, rel):
    ref_id = active(gov, generation=1)
    assert secret_of(rel(ref_id, 1)) == FIXTURE_VALUE
    gov.db.execute(PROJECT, "UPDATE tenant.credential_reference SET generation = 2, validated_generation = 2 "
                   "WHERE id = :id", id=ref_id.hex)
    assert rel(ref_id, 1)["reason_code"] == "CREDENTIAL_GENERATION_MISMATCH"


@pytest.mark.parametrize("state", ["pending", "validated", "suspended", "retired"])
def test_only_an_active_reference_is_released_to_a_run(gov, rel, state):
    ref_id = gov.add_reference(PROJECT, state=state, generation=2)
    stored(gov, "database", ref_id, g2=FIXTURE_VALUE_2)
    assert rel(ref_id, 2) == {"ok": False, "reason_code": "CREDENTIAL_REFERENCE_INACTIVE"}
    assert gov.stores.stores["database"].calls == []


@pytest.mark.parametrize("state,released", [
    ("validated", True), ("active", True), ("pending", False), ("suspended", False), ("retired", False)])
def test_a_probe_may_also_read_a_validated_reference(gov, rel, state, released):
    ref_id = gov.add_reference(PROJECT, state=state, generation=2)
    stored(gov, "database", ref_id, g2=FIXTURE_VALUE_2)
    answer = rel(ref_id, 2, allow_validated=True)
    assert answer["ok"] is released
    if released:
        assert secret_of(answer) == FIXTURE_VALUE_2
    else:
        assert answer["reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"


def test_a_reference_of_another_project_or_an_unknown_one_looks_the_same(gov, rel):
    ref_id = active(gov)
    foreign = rel(ref_id, 2, project_id=PROJECT + 1)
    unknown = rel(uuid.uuid4(), 2)
    assert foreign == unknown == {"ok": False, "reason_code": "CREDENTIAL_REFERENCE_INACTIVE"}
    assert gov.stores.stores["database"].calls == []


def test_the_reference_of_the_other_project_is_not_reachable_with_its_own_project_id(gov, rel):
    mine, theirs = active(gov), active(gov, project_id=PROJECT + 1)
    assert rel(mine, 2)["ok"] is True and rel(theirs, 2, project_id=PROJECT + 1)["ok"] is True
    assert rel(theirs, 2)["reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"
    assert rel(mine, 2, project_id=PROJECT + 1)["reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"


@pytest.mark.parametrize("code", ["DENIED", "SEALED", "UNAVAILABLE", "TLS_INVALID", "NOT_FOUND"])
def test_a_store_failure_is_returned_as_its_own_code(gov, rel, code):
    ref_id = active(gov)
    gov.stores.stores["database"].fail["read"] = code
    assert rel(ref_id, 2) == {"ok": False, "reason_code": f"STORE_{code}"}


def test_material_missing_at_the_generation_is_not_found(gov, rel):
    ref_id = gov.add_reference(PROJECT, state="active", generation=2)  # nothing in the store
    assert rel(ref_id, 2)["reason_code"] == "STORE_NOT_FOUND"


def test_a_store_that_cannot_be_used_is_unavailable_and_no_other_store_is_tried(gov, rel):
    ref_id = active(gov, "corporate_vault")
    gov.stores.unavailable.add("corporate_vault")
    assert rel(ref_id, 2)["reason_code"] == "STORE_UNAVAILABLE"
    assert gov.stores.get_store_calls == [("corporate_vault", True)]
    assert gov.stores.stores["database"].calls == []


def test_an_unexpected_failure_is_a_dependency_error_that_leaks_nothing(gov, rel):
    ref_id = active(gov)

    def boom(*args, **kwargs):
        raise RuntimeError(f"adapter blew up on {FIXTURE_VALUE_2}")

    gov.stores.stores["database"].read = boom
    answer = rel(ref_id, 2)
    assert answer == {"ok": False, "reason_code": "DEPENDENCY_UNAVAILABLE"}
    assert FIXTURE_VALUE_2 not in " ".join(StubLog.records) and "RuntimeError" in " ".join(StubLog.records)


def test_a_reference_read_failure_is_a_dependency_error(gov, rel, monkeypatch):
    ref_id = active(gov)

    def down(project_id=None):
        raise RuntimeError("database down")

    monkeypatch.setattr(gov.tools.db, "get_session", down)
    assert rel(ref_id, 2) == {"ok": False, "reason_code": "DEPENDENCY_UNAVAILABLE"}
    assert gov.stores.stores["database"].calls == []


@pytest.mark.parametrize("kwargs", [
    dict(ref_id="not-a-uuid"), dict(generation=0), dict(generation=True), dict(generation="2"), dict(generation=None),
    dict(actor=""), dict(actor=None), dict(project_id=True), dict(project_id="3"),
])
def test_a_malformed_request_is_a_value_error_before_anything_is_read(gov, rel, kwargs):
    ref_id = active(gov)
    kwargs = {"ref_id": ref_id, **kwargs}
    with pytest.raises(ValueError) as raised:
        rel(**kwargs)
    assert FIXTURE_VALUE_2 not in str(raised.value)
    assert gov.stores.stores["database"].calls == [] and gov.stores.get_store_calls == []


def test_the_released_value_is_never_logged_audited_or_written_back(gov, rel):
    ref_id = active(gov)
    before = gov.reference(PROJECT, ref_id)
    answers = [rel(ref_id, 2), rel(ref_id, 1), rel(uuid.uuid4(), 2)]
    gov.stores.stores["database"].fail["read"] = "UNAVAILABLE"
    answers.append(rel(ref_id, 2))
    for needle in (FIXTURE_VALUE, FIXTURE_VALUE_2):
        assert needle not in " ".join(StubLog.records)
        assert needle not in repr(answers) and needle not in str(answers)
    assert gov.reference(PROJECT, ref_id) == before  # the release changes no row
    assert gov.db.events(PROJECT) == [] and gov.tracing.autocommit_events == []  # the audit event is the caller's
    assert gov.stores.stores["database"].versions[ref_id][2] == {"api_key": FIXTURE_VALUE_2}
    assert gov.reference(PROJECT, ref_id).generation == 2


def _has_real_port():
    return bool(os.environ.get("C1009_REAL_PORT_DIR"))


@pytest.mark.skipif(not _has_real_port(), reason="needs the real port types (C1009_REAL_PORT_DIR)")
@pytest.mark.parametrize("release_id", ["has space", "", "x" * 129, "a\r\nb"])
def test_with_the_real_port_a_release_id_that_is_not_a_header_safe_token_is_refused(gov, rel, release_id):
    ref_id = active(gov)
    with pytest.raises(ValueError):
        rel(ref_id, 2, release_id=release_id)
    assert gov.stores.stores["database"].calls == []


def test_the_method_is_a_thin_binding_of_the_service(gov):
    method = gov.module("methods.credential_release")
    ref_id = active(gov)
    answer = method.Method.release_credential_material(object(), PROJECT, str(ref_id), 2, RELEASE_ID, ACTOR)
    assert answer["ok"] is True and secret_of(answer) == FIXTURE_VALUE_2
    probe = gov.add_reference(PROJECT, state="validated", generation=1)
    stored(gov, "database", probe, g1=FIXTURE_VALUE)
    assert method.Method.release_credential_material(object(), PROJECT, str(probe), 1, RELEASE_ID, ACTOR)[
        "reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"
    assert method.Method.release_credential_material(
        object(), PROJECT, str(probe), 1, RELEASE_ID, ACTOR, allow_validated=True)["ok"] is True


@pytest.mark.skipif(not _has_real_port(), reason="needs the real port types (C1009_REAL_PORT_DIR)")
def test_with_the_real_port_the_release_context_reads_and_nothing_else(gov, rel):
    ref_id = active(gov)
    assert rel(ref_id, 2)["ok"] is True
    stores = gov.stores
    ref = stores.StoreRef(ref_id, PROJECT, "database", {})
    ctx = stores.CredentialStoreProvider.mint(
        "release", decision_id=RELEASE_ID, actor_ref=ACTOR, project_id=PROJECT, ref_id=ref_id)
    for operation in ("write", "metadata", "delete_all"):
        with pytest.raises(stores.StoreError) as raised:
            stores.check_context(ctx, ref, operation)
        assert raised.value.code == "DENIED"
    onboard = stores.CredentialStoreProvider.mint(
        "onboard", decision_id=RELEASE_ID, actor_ref=ACTOR, project_id=PROJECT, ref_id=ref_id)
    with pytest.raises(stores.StoreError):
        stores.check_context(onboard, ref, "read")  # a context of another purpose cannot read through this path
    with pytest.raises(TypeError):
        pickle.dumps(rel(ref_id, 2)["value"])  # the carrier cannot be copied out by accident


# --- the batch: release_credential_materials (perf review 2026-10-21, M1 secrets side) ------------------------------

@pytest.fixture(name="batch")
def _batch(gov):
    service = gov.module("utils.credential_release")

    def release_many(refs, project_id=PROJECT, release_id=RELEASE_ID, actor=ACTOR, **kw):
        items = [{"ref_id": ref, "generation": generation} for ref, generation in refs]
        return service.release_materials(project_id, items, release_id, actor, **kw)

    return release_many


@pytest.fixture(name="sessions")
def _sessions(gov, monkeypatch):
    opened = []
    real = gov.tools.db.get_session

    def counting(project_id=None):
        opened.append(project_id)
        return real(project_id)

    monkeypatch.setattr(gov.tools.db, "get_session", counting)
    return opened


def many_active(gov, kinds):
    return [active(gov, kind) for kind in kinds]


@pytest.mark.parametrize("count", [1, 3, 6])
def test_one_session_and_one_store_read_whatever_the_number_of_references(gov, batch, sessions, count):
    refs = many_active(gov, ["database"] * count)
    answer = batch([(ref, 2) for ref in refs])
    assert answer["ok"] is True and set(answer["values"]) == {str(ref) for ref in refs}
    assert all(value.fields["api_key"].get_secret_value() == FIXTURE_VALUE_2 for value in answer["values"].values())
    assert sessions == [PROJECT]  # the references of the whole batch in one session
    store = gov.stores.stores["database"]
    assert len(store.read_many_calls) == 1 and len(store.read_many_calls[0]) == count
    assert gov.stores.get_store_calls == [("database", True)]


def test_one_store_read_per_store_kind(gov, batch, sessions):
    refs = many_active(gov, ["database", "corporate_vault", "database", "corporate_vault", "database"])
    answer = batch([(ref, 2) for ref in refs])
    assert answer["ok"] is True and list(answer["values"]) == [str(ref) for ref in refs]
    assert sessions == [PROJECT]
    assert [len(gov.stores.stores[kind].read_many_calls) for kind in STORE_KINDS] == [1, 1]
    assert [len(gov.stores.stores[kind].read_many_calls[0]) for kind in STORE_KINDS] == [3, 2]
    assert sorted(gov.stores.get_store_calls) == [("corporate_vault", True), ("database", True)]
    for kind in STORE_KINDS:  # every read is the release purpose with the release id as decision id
        assert {call[1:] for call in gov.stores.stores[kind].calls} == {("release", RELEASE_ID)}


def test_the_references_are_one_statement(gov, batch):
    import sqlalchemy as sa  # pylint: disable=C0415
    refs = many_active(gov, ["database"] * 4)
    statements = []
    sa.event.listen(gov.db.engine(PROJECT), "before_cursor_execute", lambda *a: statements.append(a[2]))
    assert batch([(ref, 2) for ref in refs])["ok"] is True
    assert len([s for s in statements if s.lstrip().upper().startswith("SELECT")]) == 1


def test_the_first_refusal_wins_and_nothing_is_read(gov, batch):
    good, stale, suspended = active(gov), active(gov, generation=3), gov.add_reference(PROJECT, state="suspended", generation=2)
    answer = batch([(good, 2), (stale, 2), (suspended, 2)])
    assert answer == {"ok": False, "reason_code": "CREDENTIAL_GENERATION_MISMATCH", "ref_id": str(stale)}
    other = batch([(good, 2), (suspended, 2), (stale, 2)])
    assert other == {"ok": False, "reason_code": "CREDENTIAL_REFERENCE_INACTIVE", "ref_id": str(suspended)}
    assert gov.stores.stores["database"].read_many_calls == [] and gov.stores.get_store_calls == []


def test_a_reference_of_another_project_or_an_unknown_one_refuses_the_whole_batch(gov, batch):
    mine, theirs = active(gov), active(gov, project_id=PROJECT + 1)
    for stranger in (theirs, uuid.uuid4()):
        answer = batch([(mine, 2), (stranger, 2)])
        assert answer == {"ok": False, "reason_code": "CREDENTIAL_REFERENCE_INACTIVE", "ref_id": str(stranger)}
    assert gov.stores.stores["database"].read_many_calls == []


def test_a_store_failure_returns_no_material_from_any_store(gov, batch):
    refs = many_active(gov, ["database", "corporate_vault", "database"])
    gov.stores.stores["corporate_vault"].fail["read"] = "UNAVAILABLE"
    answer = batch([(ref, 2) for ref in refs])
    assert answer == {"ok": False, "reason_code": "STORE_UNAVAILABLE", "ref_id": str(refs[1])}  # the failing one is named
    assert "values" not in answer and FIXTURE_VALUE_2 not in repr(answer)


def test_an_unexpected_store_failure_is_a_dependency_error_that_leaks_nothing(gov, batch):
    refs = many_active(gov, ["database", "database"])

    def boom(*args, **kwargs):
        raise RuntimeError(f"adapter blew up on {FIXTURE_VALUE_2}")

    gov.stores.stores["database"].read_many = boom
    answer = batch([(ref, 2) for ref in refs])
    assert answer == {"ok": False, "reason_code": "DEPENDENCY_UNAVAILABLE", "ref_id": None}
    assert FIXTURE_VALUE_2 not in " ".join(StubLog.records)


def test_a_reference_read_failure_is_a_dependency_error_in_the_batch(gov, batch, monkeypatch):
    refs = many_active(gov, ["database", "database"])

    def down(project_id=None):
        raise RuntimeError("database down")

    monkeypatch.setattr(gov.tools.db, "get_session", down)
    assert batch([(ref, 2) for ref in refs]) == {"ok": False, "reason_code": "DEPENDENCY_UNAVAILABLE", "ref_id": None}
    assert gov.stores.stores["database"].read_many_calls == []


def test_flags_widen_the_states_for_the_whole_batch(gov, batch):
    validated = gov.add_reference(PROJECT, state="validated", generation=1)
    pending = gov.add_reference(PROJECT, state="pending", generation=1)
    for ref in (validated, pending):
        stored(gov, "database", ref, g1=FIXTURE_VALUE)
    assert batch([(validated, 1)])["reason_code"] == "CREDENTIAL_REFERENCE_INACTIVE"
    assert batch([(validated, 1)], allow_validated=True)["ok"] is True
    assert batch([(validated, 1), (pending, 1)], allow_validated=True)["ref_id"] == str(pending)
    assert batch([(validated, 1), (pending, 1)], allow_pending=True)["ok"] is True


def test_a_reference_named_twice_is_read_once(gov, batch):
    ref = active(gov)
    answer = batch([(ref, 2), (str(ref), 2)])
    assert answer["ok"] is True and list(answer["values"]) == [str(ref)]
    assert gov.stores.stores["database"].read_many_calls == [[(ref, 2)]]


@pytest.mark.parametrize("items", [
    [], None, "x", {"ref_id": "a", "generation": 1}, [{"ref_id": "x"}], [{"generation": 1}], ["not a dict"],
    [{"ref_id": "not-a-uuid", "generation": 1}], [{"ref_id": str(uuid.uuid4()), "generation": 0}],
    [{"ref_id": str(uuid.uuid4()), "generation": True}], [{"ref_id": str(uuid.uuid4()), "generation": "2"}],
])
def test_a_malformed_batch_is_a_value_error_before_anything_is_read(gov, sessions, items):
    service = gov.module("utils.credential_release")
    with pytest.raises(ValueError):
        service.release_materials(PROJECT, items, RELEASE_ID, ACTOR)
    assert sessions == [] and gov.stores.get_store_calls == []


def test_more_references_than_the_stores_take_are_refused_before_anything_is_read(gov, batch, sessions):
    refs = [(uuid.uuid4(), 1) for _ in range(65)]
    assert batch(refs) == {"ok": False, "reason_code": "INVALID_REQUEST", "ref_id": None}
    assert sessions == [] and gov.stores.get_store_calls == []
    ok = [active(gov) for _ in range(64)]  # the bound itself is allowed
    assert batch([(ref, 2) for ref in ok])["ok"] is True


def test_the_same_reference_with_two_generations_is_a_value_error(gov, batch):
    ref = active(gov)
    with pytest.raises(ValueError, match="one generation per reference"):
        batch([(ref, 1), (ref, 2)])


@pytest.mark.parametrize("kwargs", [dict(actor=""), dict(actor=None), dict(project_id=True)])
def test_the_batch_validates_the_caller_before_anything_is_read(gov, batch, sessions, kwargs):
    ref = active(gov)
    sessions.clear()
    with pytest.raises(ValueError):
        batch([(ref, 2)], **kwargs)
    assert sessions == [] and gov.stores.get_store_calls == []


def test_the_single_release_is_the_batch_of_one(gov, rel, sessions):
    ref = active(gov, "corporate_vault")
    answer = rel(ref, 2)
    assert answer["ok"] is True and secret_of(answer) == FIXTURE_VALUE_2 and set(answer) == {"ok", "value"}
    assert sessions == [PROJECT] and len(gov.stores.stores["corporate_vault"].read_many_calls) == 1
    assert rel(ref, 1) == {"ok": False, "reason_code": "CREDENTIAL_GENERATION_MISMATCH"}  # no ref_id in the single answer


def test_the_batch_is_never_logged_audited_or_written_back(gov, batch):
    refs = many_active(gov, ["database", "corporate_vault"])
    before = [gov.reference(PROJECT, ref) for ref in refs]
    answers = [batch([(ref, 2) for ref in refs]), batch([(refs[0], 1)]), batch([(uuid.uuid4(), 2)])]
    for needle in (FIXTURE_VALUE, FIXTURE_VALUE_2):
        assert needle not in " ".join(StubLog.records)
        assert needle not in repr([a.get("reason_code") for a in answers if not a["ok"]])
    assert [gov.reference(PROJECT, ref) for ref in refs] == before
    assert gov.db.events(PROJECT) == [] and gov.tracing.autocommit_events == []


def test_the_batch_method_is_a_thin_binding_of_the_service(gov):
    method = gov.module("methods.credential_release")
    refs = many_active(gov, ["database", "corporate_vault"])
    answer = method.Method.release_credential_materials(
        object(), PROJECT, [{"ref_id": str(ref), "generation": 2} for ref in refs], RELEASE_ID, ACTOR)
    assert answer["ok"] is True and set(answer["values"]) == {str(ref) for ref in refs}
    probe = gov.add_reference(PROJECT, state="validated", generation=1)
    stored(gov, "database", probe, g1=FIXTURE_VALUE)
    items = [{"ref_id": str(probe), "generation": 1}]
    assert method.Method.release_credential_materials(object(), PROJECT, items, RELEASE_ID, ACTOR)["ref_id"] == str(probe)
    assert method.Method.release_credential_materials(
        object(), PROJECT, items, RELEASE_ID, ACTOR, allow_validated=True)["ok"] is True


@pytest.mark.skipif(not _has_real_port(), reason="needs the real port types (C1009_REAL_PORT_DIR)")
def test_with_the_real_port_each_reference_has_its_own_release_context(gov, batch):
    refs = many_active(gov, ["database", "database"])
    assert batch([(ref, 2) for ref in refs])["ok"] is True
    store = gov.stores.stores["database"]
    assert [call[1] for call in store.calls] == ["release", "release"]


def test_both_release_methods_take_their_flags_by_keyword_in_the_same_order(gov):
    import inspect  # pylint: disable=C0415
    method = gov.module("methods.credential_release").Method
    flags = {}
    for name in ("release_credential_material", "release_credential_materials"):
        parameters = list(inspect.signature(getattr(method, name)).parameters.values())
        flags[name] = [p.name for p in parameters if p.kind is p.KEYWORD_ONLY]
        assert all(p.kind is p.POSITIONAL_OR_KEYWORD for p in parameters if p.name in ("project_id", "release_id", "actor_ref"))
    assert flags["release_credential_material"] == flags["release_credential_materials"] == ["allow_validated", "allow_pending"]
    ref = active(gov)
    with pytest.raises(TypeError):
        method.release_credential_materials(object(), PROJECT, [{"ref_id": str(ref), "generation": 2}], RELEASE_ID, ACTOR, True)


def test_the_batch_answers_in_canonical_lowercase_ids(gov, batch):
    ref = active(gov)
    answer = batch([(str(ref).upper(), 2)])
    assert list(answer["values"]) == [str(ref)]
    refused = batch([(str(ref).upper(), 9)])
    assert refused["ref_id"] == str(ref)
