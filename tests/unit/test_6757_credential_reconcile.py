"""C-1009 (#6757): the store reconciler and the store smoke test.

Clock skew (a flake seen once on a freshly started PostgreSQL container, 16 of these tests failing together): a ledger
row's ``updated_at`` is written by the database (``now()``), while the reconciler's cutoff is the Python clock
(``now - older_than_s``). With ``older_than_s=0`` a database clock that runs ahead of the host's, as a container VM
can right after start, puts the row "in the future" and it is not yet eligible. The tests that ask for ``0`` therefore
age the ledger by a minute first (``Governance.age_ledger`` writes ``updated_at`` from the Python clock), which makes
them independent of the skew. The hypothesis was not reproduced; it fits the pattern (all and only the
``older_than_s=0`` tests failed, and a rerun passed).
"""
import json
import uuid

import pytest

from fixtures.governance import FIXTURE_VALUE, Crash
from run_tests import StubLog

PROJECT = 3
CREATOR = 10


class _Module:
    """What the task gets as ``self``: only the project listing is used."""

    projects = [{"id": PROJECT}]

    class context:  # noqa: N801
        class rpc_manager:  # noqa: N801
            class call:  # noqa: N801
                @staticmethod
                def project_list(filter_=None):
                    return list(_Module.projects)


@pytest.fixture(autouse=True)
def _reset_module():
    _Module.projects = [{"id": PROJECT}]
    StubLog.records.clear()
    yield


@pytest.fixture
def rec(gov, monkeypatch):
    reconciler = gov.module("utils.credential_reconcile")
    missing = []
    monkeypatch.setattr(reconciler, "project_ids_missing_credential_tables", lambda: list(missing))  # PostgreSQL's catalog
    reconciler.missing = missing
    original = reconciler.reconcile_project

    def aged(project_id, older_than_s, actor, dry_run=False):
        if older_than_s == 0:  # see the module docstring: eligible whatever the database clock says
            gov.age_ledger(project_id, 60)
        return original(project_id, older_than_s, actor, dry_run)
    monkeypatch.setattr(reconciler, "reconcile_project", aged)
    return reconciler


def run(rec, param=f"project_id={PROJECT};older_than_s=0", actor=CREATOR):
    return rec.reconcile_store(_Module(), param, actor)


def store(gov, kind="database"):
    return gov.stores.stores[kind]


def stage(gov, *, generation=1, state="pending", ledger_state="intent", store_has=True, material_generations=(1,),
          op="write", **ref_overrides):
    """A reference with a write of ``generation`` interrupted, as an import that died would leave it."""
    ref_id = gov.add_reference(PROJECT, state=state, generation=generation - 1, pending_generation=generation,
                               **ref_overrides)
    gov.add_ledger(PROJECT, ref_id, generation, op=op, state=ledger_state)
    if store_has:
        store(gov).versions[ref_id] = {n: {"api_key": FIXTURE_VALUE} for n in material_generations}
    return ref_id


# --- parameters ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("param, fragment", [
    ("", "project_id= is required"), ("older_than_s=5", "project_id= is required"),
    ("project_id=x", "invalid project_id"), ("project_id=0", "invalid project_id"),
    ("project_id=all;older_than_s=x", "invalid older_than_s=x"), ("project_id=all;older_than_s=-1", "invalid older_than_s=-1"),
])
def test_bad_parameters(gov, rec, param, fragment):
    assert fragment in run(rec, param)["error"]


def test_parse_reads_all_projects_the_threshold_and_dry_run(rec):
    assert rec.parse_reconcile_param("project_id=all;dry_run") == (None, 300, True, None)
    assert rec.parse_reconcile_param(" PROJECT_ID=4 ; older_than_s=60 ") == (4, 60, False, None)


def test_the_operator_is_required_except_to_look(gov, rec):
    for actor in (0, None, True):
        assert run(rec, actor=actor)["code"] == "ACTOR_REQUIRED"
    assert run(rec, f"project_id={PROJECT};dry_run", actor=0)["dry_run"] is True


# --- settling -----------------------------------------------------------------------------------------------------

def test_a_staged_generation_that_reached_the_store_is_committed(gov, rec):
    config = gov.configurations.add(PROJECT, generation=6)
    ref_id = stage(gov, configuration_id=config.id, configuration_uuid=uuid.UUID(config.uuid))
    result = run(rec)
    assert result["rolled_forward"] == 1
    ref = gov.reference(PROJECT, ref_id)
    assert (ref.generation, ref.pending_generation, ref.state, ref.configuration_generation) == (1, None, "pending", 6)
    assert gov.ledger(PROJECT, ref_id)[0].state == "committed"
    reasons = [e["reason_code"] for e in gov.db.events(PROJECT)]
    assert reasons == ["CREDENTIAL_RECONCILE_STARTED", "CREDENTIAL_RECONCILED_COMMITTED"]
    started = gov.db.events(PROJECT)[0]
    assert store(gov).calls == [("metadata", "reconcile", started["event_id"])]   # generation 1: nothing to prune


def test_a_staged_generation_the_store_never_got_is_released(gov, rec):
    ref_id = stage(gov, store_has=False)
    result = run(rec)
    assert result["abandoned"] == 1
    ref = gov.reference(PROJECT, ref_id)
    assert (ref.generation, ref.pending_generation) == (0, None)
    assert gov.ledger(PROJECT, ref_id)[0].state == "abandoned"
    assert "CREDENTIAL_RECONCILED_ABANDONED" in [e["reason_code"] for e in gov.db.events(PROJECT)]


def test_a_validated_reference_keeps_its_approval_until_a_roll_forward_replaces_the_material(gov, rec):
    ref_id = gov.add_reference(PROJECT, state="validated", generation=1, validated_generation=1, pending_generation=2,
                               approved_by=20, approval_ref="CHG-1", policy_revision="rev-1")
    gov.add_ledger(PROJECT, ref_id, 2)
    store(gov).versions[ref_id] = {1: {"api_key": "old"}, 2: {"api_key": FIXTURE_VALUE}}
    assert run(rec)["rolled_forward"] == 1
    ref = gov.reference(PROJECT, ref_id)
    assert (ref.state, ref.generation, ref.approved_by, ref.validated_generation) == ("pending", 2, None, None)
    ref_id = gov.add_reference(PROJECT, state="validated", generation=1, validated_generation=1, pending_generation=2,
                               approved_by=20, approval_ref="CHG-1", policy_revision="rev-1")
    gov.add_ledger(PROJECT, ref_id, 2)
    assert run(rec)["abandoned"] == 1  # the store lacks generation 2: the approved validation stands
    ref = gov.reference(PROJECT, ref_id)
    assert (ref.state, ref.generation, ref.approved_by, ref.pending_generation) == ("validated", 1, 20, None)


def test_rows_younger_than_the_threshold_are_left_alone(gov, rec):
    ref_id = stage(gov)
    assert run(rec, f"project_id={PROJECT};older_than_s=300") == {"failed": 0, "failed_projects": [], "dry_run": False}
    assert gov.ledger(PROJECT, ref_id)[0].state == "intent" and store(gov).calls == []
    gov.age_ledger(PROJECT, 3600)
    assert run(rec, f"project_id={PROJECT}")["rolled_forward"] == 1  # default threshold 300 s


def test_dry_run_counts_and_changes_nothing(gov, rec):
    ref_id = stage(gov)
    stage(gov, store_has=False)
    result = run(rec, f"project_id={PROJECT};older_than_s=0;dry_run")
    assert result["candidates"] == 2 and result["dry_run"] is True
    assert gov.ledger(PROJECT, ref_id)[0].state == "intent"
    assert store(gov).calls == [] and gov.db.events(PROJECT) == []


def test_a_store_that_cannot_answer_defers_and_audits_the_failure(gov, rec):
    ref_id = stage(gov)
    store(gov).fail["metadata"] = "UNAVAILABLE"
    result = run(rec)
    assert result["deferred"] == 1
    assert gov.reference(PROJECT, ref_id).pending_generation == 1
    assert gov.ledger(PROJECT, ref_id)[0].state == "intent"
    failed = [e for e in gov.db.events(PROJECT) if e["reason_code"] == "STORE_UNAVAILABLE"]
    assert failed and failed[0]["outcome"] == "failed"
    store(gov).fail.clear()
    assert run(rec)["rolled_forward"] == 1  # the next run settles it


def test_the_material_of_a_retired_reference_is_deleted_and_the_write_abandoned(gov, rec):
    ref_id = stage(gov, state="retired")
    assert run(rec)["abandoned"] == 1
    assert ref_id not in store(gov).versions
    assert gov.ledger(PROJECT, ref_id)[0].state == "abandoned"
    assert store(gov).calls[-1][:2] == ("delete_all", "reconcile")


def test_the_material_of_a_missing_reference_is_deleted(gov, rec):
    ref_id = uuid.uuid4()
    gov.add_ledger(PROJECT, ref_id, 1)
    store(gov).versions[ref_id] = {1: {"api_key": FIXTURE_VALUE}}
    assert run(rec)["abandoned"] == 1
    assert ref_id not in store(gov).versions


def test_an_unfinished_delete_is_completed_for_a_retired_reference_only(gov, rec):
    retired = gov.add_reference(PROJECT, state="retired", generation=1)
    gov.add_ledger(PROJECT, retired, 1, op="delete_all")
    store(gov).versions[retired] = {1: {"api_key": FIXTURE_VALUE}}
    live = gov.add_reference(PROJECT, state="active", generation=1)
    gov.add_ledger(PROJECT, live, 1, op="delete_all")
    store(gov).versions[live] = {1: {"api_key": FIXTURE_VALUE}}
    result = run(rec)
    assert (result["completed"], result["abandoned"]) == (1, 1)
    assert retired not in store(gov).versions
    assert live in store(gov).versions  # never the material of a live reference
    assert [e.state for e in gov.ledger(PROJECT, live)] == ["abandoned"]
    assert [e.state for e in gov.ledger(PROJECT, retired)] == ["committed"]


def test_a_ledger_that_lagged_behind_a_commit_is_closed_without_touching_the_store(gov, rec):
    ref_id = gov.add_reference(PROJECT, generation=1)
    gov.add_ledger(PROJECT, ref_id, 1, state="written")
    assert run(rec)["healed"] == 1
    assert gov.ledger(PROJECT, ref_id)[0].state == "committed" and store(gov).calls == []


def test_nothing_staged_means_the_store_is_left_alone(gov, rec):
    ref_id = gov.add_reference(PROJECT, generation=0)  # pending_generation was cleared elsewhere
    gov.add_ledger(PROJECT, ref_id, 1)
    store(gov).versions[ref_id] = {1: {"api_key": FIXTURE_VALUE}}
    assert run(rec)["abandoned"] == 1
    assert ref_id in store(gov).versions and store(gov).calls == []


def test_a_roll_forward_that_loses_the_race_is_deferred(gov, rec, monkeypatch):
    stage(gov)
    monkeypatch.setattr(rec, "commit_generation", lambda *a, **k: False)
    assert run(rec)["deferred"] == 1


def test_a_roll_forward_when_the_configuration_is_gone_commits_without_a_generation(gov, rec):
    ref_id = stage(gov)
    assert run(rec)["rolled_forward"] == 1
    assert gov.reference(PROJECT, ref_id).configuration_generation is None


def test_a_roll_forward_with_unavailable_configurations_is_deferred(gov, rec):
    stage(gov)
    del gov.this.modules["configurations"]
    assert run(rec)["deferred"] == 1


def test_the_audit_event_is_written_before_the_store_is_asked(gov, rec):
    stage(gov)
    gov.tracing.fail = True
    assert run(rec)["failed"] == 1  # the project failed: nothing happened
    assert store(gov).calls == []


# --- projects and bounds -------------------------------------------------------------------------------------------------

def test_a_failing_project_does_not_stop_the_others(gov, rec, monkeypatch):
    _Module.projects = [{"id": 4}, {"id": PROJECT}, {"id": 5}]
    ref_3 = stage(gov)
    real = rec.reconcile_project

    def flaky(project_id, *args, **kwargs):
        if project_id == 4:
            raise RuntimeError("boom")
        return real(project_id, *args, **kwargs)
    monkeypatch.setattr(rec, "reconcile_project", flaky)
    gov.db.engine(5)
    result = rec.reconcile_store(_Module(), "project_id=all;older_than_s=0", CREATOR)
    assert result["failed"] == 1 and result["failed_projects"] == [{"project_id": 4}] and result["rolled_forward"] == 1
    assert gov.reference(PROJECT, ref_3).generation == 1


def test_projects_without_the_tables_are_skipped(gov, rec):
    _Module.projects = [{"id": PROJECT}, {"id": 9}]
    rec.missing.append(9)
    stage(gov)
    result = rec.reconcile_store(_Module(), "project_id=all;older_than_s=0", CREATOR)
    assert result["failed"] == 0 and result["rolled_forward"] == 1 and 9 not in gov.db.engines


def test_a_failed_project_listing_is_reported(gov, rec, monkeypatch):
    def boom():
        raise RuntimeError("catalog down")
    monkeypatch.setattr(rec, "project_ids_missing_credential_tables", boom)
    assert run(rec) == {"error": "failed to list projects"}


def test_one_run_settles_a_bounded_batch(gov, rec, monkeypatch):
    monkeypatch.setattr(rec, "BATCH_SIZE", 2)
    for _ in range(3):
        stage(gov, store_has=False)
    assert run(rec)["abandoned"] == 2
    assert run(rec)["abandoned"] == 1
    assert run(rec).get("abandoned", 0) == 0


def test_a_crashed_reconcile_resumes_without_a_second_commit(gov, rec, monkeypatch):
    ref_id = stage(gov)
    with monkeypatch.context() as patched:
        patched.setattr(rec, "commit_generation", lambda *a, **k: (_ for _ in ()).throw(Crash()))
        with pytest.raises(Crash):
            run(rec)
    assert gov.reference(PROJECT, ref_id).generation == 0
    assert run(rec)["rolled_forward"] == 1
    assert run(rec).get("rolled_forward", 0) == 0
    assert gov.reference(PROJECT, ref_id).generation == 1


def test_results_and_logs_carry_no_material_or_path(gov, rec):
    stage(gov)
    stage(gov, state="retired")
    results = [run(rec), run(rec, f"project_id={PROJECT};dry_run")]
    blob = json.dumps({"r": results, "e": gov.db.events(PROJECT)}, default=str) + "\n".join(StubLog.records)
    for forbidden in (FIXTURE_VALUE, "section", "locator", "kv-elitea"):
        assert forbidden not in blob


# --- the store smoke test ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("param, fragment", [
    ("", "store_kind=corporate_vault required"), ("store_kind=database", "store_kind=corporate_vault required"),
    ("store_kind=corporate_vault;extra=1", "unknown parameter"), ("canary=canary-x", "unknown parameter"),
])
def test_smoke_parameters(gov, rec, param, fragment):
    assert fragment in rec.run_store_smoke(param, CREATOR)["error"]
    assert gov.stores.get_store_calls == []


def test_smoke_passes_and_audits_both_ends_with_the_decision_id_the_store_saw(gov, rec):
    result = rec.run_store_smoke("store_kind=corporate_vault", CREATOR)
    assert result == {"action": "smoke", "store_kind": "corporate_vault", "dry_run": False, "passed": True,
                      "checks": store(gov, "corporate_vault").smoke_result}
    started, outcome = gov.tracing.autocommit_events
    assert (started["reason_code"], outcome["reason_code"], outcome["outcome"]) == (
        "CREDENTIAL_STORE_SMOKE_STARTED", "CREDENTIAL_STORE_SMOKE_PASSED", "success")
    assert store(gov, "corporate_vault").calls == [("smoke", "smoke", started["event_id"])]
    assert "project_id" not in started and started["caller_ref"] == f"operator:{CREATOR}"
    assert gov.stores.get_store_calls == [("corporate_vault", True)]


def test_a_failed_check_is_reported_and_audited(gov, rec):
    gov.stores.stores["corporate_vault"].smoke_result["list_denied"] = False
    result = rec.run_store_smoke("store_kind=corporate_vault", CREATOR)
    assert result["passed"] is False and result["checks"]["list_denied"] is False
    assert gov.tracing.autocommit_events[-1]["reason_code"] == "CREDENTIAL_STORE_SMOKE_FAILED"
    assert gov.tracing.autocommit_events[-1]["outcome"] == "failed"


@pytest.mark.parametrize("code", ["DENIED", "SEALED", "TLS_INVALID", "UNAVAILABLE"])
def test_a_store_that_cannot_be_reached_is_a_typed_failure(gov, rec, code):
    gov.stores.stores["corporate_vault"].fail["smoke"] = code
    result = rec.run_store_smoke("store_kind=corporate_vault", CREATOR)
    assert result["code"] == f"STORE_{code}"
    assert gov.tracing.autocommit_events[-1]["reason_code"] == f"STORE_{code}"


def test_smoke_without_the_corporate_store_configured(gov, rec):
    gov.stores.unavailable.add("corporate_vault")
    assert rec.run_store_smoke("store_kind=corporate_vault", CREATOR)["code"] == "STORE_UNAVAILABLE"
    assert [e["reason_code"] for e in gov.tracing.autocommit_events] == ["STORE_UNAVAILABLE"]  # the attempt, no start


def test_smoke_does_not_touch_the_store_without_an_audit_trail(gov, rec):
    gov.tracing.fail = True
    assert rec.run_store_smoke("store_kind=corporate_vault", CREATOR)["code"] == "FAILED"
    assert store(gov, "corporate_vault").calls == []


def test_smoke_needs_an_operator_unless_dry_run(gov, rec):
    assert rec.run_store_smoke("store_kind=corporate_vault", 0)["code"] == "ACTOR_REQUIRED"
    assert rec.run_store_smoke("store_kind=corporate_vault;dry_run", 0) == {
        "dry_run": True, "action": "smoke", "store_kind": "corporate_vault"}
    assert gov.stores.get_store_calls == []


# --- pruning old generations after a roll-forward (perf review 2026-10-21, S10) -------------------------------------

def test_a_roll_forward_keeps_the_new_generation_and_the_one_before(gov, rec):
    ref_id = stage(gov, generation=4, material_generations=(1, 2, 3, 4))
    assert run(rec)["rolled_forward"] == 1
    assert sorted(store(gov).versions[ref_id]) == [3, 4]
    assert gov.reference(PROJECT, ref_id).generation == 4
    prunes = [call for call in store(gov).calls if call[0] == "prune"]
    assert len(prunes) == 1 and prunes[0][1] == "reconcile"   # the reconcile purpose, the committed started event as id
    assert prunes[0][2] == gov.db.events(PROJECT)[0]["event_id"]


def test_a_roll_forward_with_a_newer_staged_generation_prunes_nothing(gov, rec):
    ref_id = stage(gov, generation=4, material_generations=(1, 2, 3, 4, 5))   # 5 is staged above the one rolled forward
    assert run(rec)["rolled_forward"] == 1
    assert sorted(store(gov).versions[ref_id]) == [1, 2, 3, 4, 5]
    assert not [call for call in store(gov).calls if call[0] == "prune"]


def test_a_failing_prune_changes_nothing_about_the_settled_outcome(gov, rec):
    ref_id = stage(gov, generation=4, material_generations=(1, 2, 3, 4))

    def refuse(*args, **kwargs):
        raise gov.stores.StoreError("UNAVAILABLE")
    store(gov).prune = refuse
    assert run(rec)["rolled_forward"] == 1
    assert gov.reference(PROJECT, ref_id).generation == 4 and gov.ledger(PROJECT, ref_id)[0].state == "committed"
    assert sorted(store(gov).versions[ref_id]) == [1, 2, 3, 4] and FIXTURE_VALUE not in " ".join(StubLog.records)


def test_nothing_is_pruned_when_the_roll_forward_is_deferred_or_the_ledger_only_lagged(gov, rec, monkeypatch):
    healed = gov.add_reference(PROJECT, generation=2)
    gov.add_ledger(PROJECT, healed, 2, state="written")
    store(gov).versions[healed] = {n: {"api_key": FIXTURE_VALUE} for n in (1, 2)}
    monkeypatch.setattr(rec, "commit_generation", lambda *a, **k: False)
    stage(gov)
    result = run(rec)
    assert (result["healed"], result["deferred"]) == (1, 1)
    assert not [call for call in store(gov).calls if call[0] == "prune"]
