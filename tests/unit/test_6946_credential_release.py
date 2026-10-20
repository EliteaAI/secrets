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
