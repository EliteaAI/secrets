"""C-1009 (#6757): staged onboarding of a credential reference - create, import, probe, approve, activate and
the moves out of use. The real services run on real tables; the store, audit trail and configurations are fakes.
"""
import json
import uuid
from types import SimpleNamespace

import pytest

from fixtures.governance import FIXTURE_VALUE, FIXTURE_VALUE_2, Crash
from run_tests import StubLog

PROJECT = 3
CREATOR, APPROVER, OTHER = 10, 20, 30


@pytest.fixture
def ob(gov):
    StubLog.records.clear()
    return gov.module("utils.credential_onboarding")


def params(**kw):
    return ";".join(f"{key}={value}" for key, value in kw.items() if value is not None)


class Flow:
    def __init__(self, gov, ob):
        self.gov, self.ob = gov, ob
        self.results = []

    def run(self, actor=CREATOR, project_id=PROJECT, dry_run=False, **kw):
        result = self.ob.manage_reference(params(project_id=project_id, **kw) + (";dry_run" if dry_run else ""), actor)
        self.results.append(result)
        return result

    def create(self, config=None, store_kind="database", ownership_class="project_shared", actor=CREATOR):
        config = config or self.gov.configurations.add(PROJECT)
        result = self.run(actor, action="create", configuration_uuid=config.uuid, store_kind=store_kind,
                          ownership_class=ownership_class)
        assert "error" not in result, result
        self.config, self.ref = config, result["reference"]
        return self.ref

    def imported(self, **kw):
        self.create(**kw)
        result = self.run(action="import", ref=self.ref)
        assert "error" not in result, result
        return self.ref

    def validated(self, **kw):
        self.imported(**kw)
        result = self.run(action="probe", ref=self.ref)
        assert "error" not in result, result
        return self.ref

    def approved(self, **kw):
        self.validated(**kw)
        result = self.run(APPROVER, action="approve", ref=self.ref, approval_ref="CHG-5", policy_revision="rev-5")
        assert "error" not in result, result
        return self.ref

    def active(self, **kw):
        self.approved(**kw)
        result = self.run(APPROVER, action="activate", ref=self.ref)
        assert "error" not in result, result
        return self.ref

    @property
    def row(self):
        return self.gov.reference(PROJECT, uuid.UUID(self.ref))

    @property
    def events(self):
        return self.gov.db.events(PROJECT)

    def reasons(self):
        return [event["reason_code"] for event in self.events]


@pytest.fixture
def flow(gov, ob):
    return Flow(gov, ob)


# --- parameters ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("param, fragment", [
    ("", "project_id and action required"),
    ("action=create", "project_id and action required"),
    ("project_id=3", "project_id and action required"),
    ("project_id=x;action=import;ref=" + str(uuid.uuid4()), "invalid project_id"),
    ("project_id=0;action=import;ref=" + str(uuid.uuid4()), "invalid project_id"),
    ("project_id=3;action=erase;ref=" + str(uuid.uuid4()), "invalid action"),
    ("project_id=3;action=import", "ref required"),
    ("project_id=3;action=import;ref=not-a-uuid", "invalid ref"),
    ("project_id=3;action=create;store_kind=database;ownership_class=service", "configuration_uuid required"),
    ("project_id=3;action=create;configuration_uuid=%s;ownership_class=service" % uuid.uuid4(), "store_kind required"),
    ("project_id=3;action=create;configuration_uuid=%s;store_kind=managed_vault;ownership_class=service" % uuid.uuid4(),
     "invalid store_kind"),
    ("project_id=3;action=create;configuration_uuid=%s;store_kind=database;ownership_class=personal" % uuid.uuid4(),
     "invalid ownership_class"),
    ("project_id=3;action=create;configuration_uuid=%s;store_kind=database;ownership_class=scheduled" % uuid.uuid4(),
     "invalid ownership_class"),
    ("project_id=3;action=approve;ref=" + str(uuid.uuid4()), "approval_ref, policy_revision required"),
    ("project_id=3;action=probe;ref=" + str(uuid.uuid4()) + ";check_connection", "unknown parameter"),
    ("project_id=3;action=import;ref=" + str(uuid.uuid4()) + ";token=abc", "unknown parameter"),
])
def test_bad_parameters_are_refused_before_anything_runs(gov, ob, param, fragment):
    result = ob.manage_reference(param, CREATOR)
    assert fragment in result["error"]
    assert gov.db.engines == {}  # no database was touched


def test_parameters_are_case_and_space_tolerant(ob):
    ref = str(uuid.uuid4())
    values, error = ob.parse_reference_param(f" PROJECT_ID = 3 ; action = probe ; REF = {ref.upper()} ; DRY_RUN")
    assert error is None and values["dry_run"] and values["ref"] == ref and values["project_id"] == 3


# --- create -------------------------------------------------------------------------------------------------------------

def test_create_registers_a_pending_reference_and_audits_it(gov, flow):
    flow.create(ownership_class="service")
    row = flow.row
    assert (row.state, row.generation, row.project_id, row.provider, row.store_kind, row.ownership_class,
            row.auth_mode, row.created_by, row.configuration_id) == (
        "pending", 0, PROJECT, "api_cred", "database", "service", "static_secret", CREATOR, flow.config.id)
    assert str(row.configuration_uuid) == flow.config.uuid
    (event,) = flow.events
    assert (event["event_type"], event["reason_code"], event["outcome"], event["credential_ref"]) == (
        "lifecycle", "CREDENTIAL_REF_PENDING", "success", flow.ref)
    assert event["caller_ref"] == f"operator:{CREATOR}" and event["credential_generation"] == 0


def test_create_for_a_corporate_vault_reference_needs_that_store(gov, flow):
    gov.stores.unavailable.add("corporate_vault")
    config = gov.configurations.add(PROJECT)
    result = flow.run(action="create", configuration_uuid=config.uuid, store_kind="corporate_vault",
                      ownership_class="service")
    assert result["code"] == "STORE_UNAVAILABLE"
    assert gov.stores.get_store_calls == [("corporate_vault", True)]
    gov.stores.unavailable.clear()
    flow.create(config=config, store_kind="corporate_vault")
    assert flow.row.store_kind == "corporate_vault"


def test_create_refuses_what_cannot_be_registered(gov, flow):
    cases = {
        "unknown": (str(uuid.uuid4()), "CONFIGURATION_NOT_FOUND"),
        "wrong section": (gov.configurations.add(PROJECT, section="llm").uuid, "CONFIGURATION_NOT_ELIGIBLE"),
        "other project": (gov.configurations.add(PROJECT + 1).uuid, "CONFIGURATION_NOT_FOUND"),
    }
    for label, (config_uuid, code) in cases.items():
        result = flow.run(action="create", configuration_uuid=config_uuid, store_kind="database",
                          ownership_class="service")
        assert result["code"] == code, label
    assert gov.db.events(PROJECT) == []


def test_one_live_reference_per_configuration_and_a_retired_one_can_be_replaced(gov, flow):
    flow.create()
    again = flow.run(action="create", configuration_uuid=flow.config.uuid, store_kind="database",
                     ownership_class="service")
    assert again["code"] == "REFERENCE_EXISTS"
    flow.run(action="retire", ref=flow.ref)
    flow.create(config=flow.config)


def test_dry_run_changes_nothing_and_needs_no_operator(gov, flow):
    config = gov.configurations.add(PROJECT)
    result = flow.run(0, dry_run=True, action="create", configuration_uuid=config.uuid, store_kind="database",
                      ownership_class="service")
    assert result == {"dry_run": True, "action": "create", "state": "pending", "provider": "api_cred"}
    assert gov.db.events(PROJECT) == []
    assert flow.run(0, action="create", configuration_uuid=config.uuid, store_kind="database",
                    ownership_class="service")["code"] == "ACTOR_REQUIRED"


@pytest.mark.parametrize("actor", [0, None, -1, True, "10"])
def test_every_change_needs_an_identified_operator(gov, flow, actor):
    config = gov.configurations.add(PROJECT)
    result = flow.run(actor, action="create", configuration_uuid=config.uuid, store_kind="database",
                      ownership_class="service")
    assert result["code"] == "ACTOR_REQUIRED"
    assert gov.db.events(PROJECT) == []


def test_a_failed_audit_leaves_no_reference(gov, flow):
    gov.tracing.fail = True
    config = gov.configurations.add(PROJECT)
    result = flow.run(action="create", configuration_uuid=config.uuid, store_kind="database", ownership_class="service")
    assert result["code"] == "FAILED"
    gov.tracing.fail = False
    flow.create(config=config)  # nothing was left behind to collide with


def test_missing_collaborators_are_a_dependency_error_not_a_crash(gov, flow):
    config = gov.configurations.add(PROJECT)
    del gov.this.modules["configurations"]
    result = flow.run(action="create", configuration_uuid=config.uuid, store_kind="database", ownership_class="service")
    assert result["code"] == "DEPENDENCY_UNAVAILABLE"


# --- import -------------------------------------------------------------------------------------------------------------

def test_import_copies_the_material_into_the_store_as_generation_one(gov, flow):
    flow.imported()
    row = flow.row
    assert (row.generation, row.pending_generation, row.state, row.configuration_generation) == (1, None, "pending", 1)
    store = gov.stores.stores["database"]
    assert store.versions[uuid.UUID(flow.ref)] == {1: {"api_key": FIXTURE_VALUE}}
    (ledger,) = gov.ledger(PROJECT, uuid.UUID(flow.ref))
    assert (ledger.generation, ledger.op, ledger.state, ledger.store_kind, ledger.attempts) == (
        1, "write", "committed", "database", 1)


def test_the_store_call_carries_the_id_of_an_audit_event_written_before_it(gov, flow):
    flow.imported()
    started = next(event for event in flow.events if event["reason_code"] == "CREDENTIAL_IMPORT_STARTED")
    (ledger,) = gov.ledger(PROJECT)
    assert started["event_id"] == ledger.correlation_id
    assert gov.stores.stores["database"].calls == [("write", "onboard", started["event_id"])]
    assert gov.configurations.bundle_calls == [(PROJECT, flow.config.id, "onboard")]
    committed = next(event for event in flow.events if event["reason_code"] == "CREDENTIAL_GENERATION_COMMITTED")
    assert (committed["credential_generation"], committed["vault_request_id"], committed["outcome"]) == (1, "req-write", "success")


def test_the_started_event_is_committed_before_the_store_is_touched(gov, flow):
    flow.create()
    store = gov.stores.stores["database"]
    store.crash_before_write = True
    with pytest.raises(Crash):
        flow.run(action="import", ref=flow.ref)
    assert "CREDENTIAL_IMPORT_STARTED" in flow.reasons() and store.versions == {}


def test_a_second_import_is_the_next_generation_and_the_store_keeps_both(gov, flow):
    flow.imported()
    gov.configurations.edit_secret(flow.config, api_key=FIXTURE_VALUE_2)
    assert "error" not in flow.run(action="import", ref=flow.ref)
    row = flow.row
    assert (row.generation, row.configuration_generation) == (2, 2)
    assert gov.stores.stores["database"].versions[uuid.UUID(flow.ref)] == {
        1: {"api_key": FIXTURE_VALUE}, 2: {"api_key": FIXTURE_VALUE_2}}
    assert [entry.state for entry in gov.ledger(PROJECT)] == ["committed", "committed"]


def test_importing_again_after_a_probe_asks_for_a_new_probe_and_a_new_approval(gov, flow):
    flow.approved()
    assert flow.row.approved_by == APPROVER
    assert "error" not in flow.run(action="import", ref=flow.ref)
    row = flow.row
    assert (row.state, row.generation, row.validated_generation, row.approved_by, row.approval_ref) == (
        "pending", 2, None, None, None)
    flow.run(action="probe", ref=flow.ref)
    assert flow.run(APPROVER, action="activate", ref=flow.ref)["code"] == "APPROVAL_REQUIRED"
    flow.run(APPROVER, action="approve", ref=flow.ref, approval_ref="CHG-6", policy_revision="rev-6")
    assert flow.run(APPROVER, action="activate", ref=flow.ref)["state"] == "active"


def test_an_import_that_finds_one_in_flight_stops(gov, flow):
    flow.create()
    with gov.db.get_session(PROJECT) as session:
        models = gov.module("models.credential_governance")
        session.get(models.CredentialReference, uuid.UUID(flow.ref)).pending_generation = 1
        session.commit()
    result = flow.run(action="import", ref=flow.ref)
    assert result["code"] == "IMPORT_IN_FLIGHT"
    assert gov.stores.stores["database"].calls == [] and gov.ledger(PROJECT) == []


@pytest.mark.parametrize("state", ["active", "suspended", "retired"])
def test_import_is_for_a_pending_or_validated_reference_only(gov, flow, state):
    ref_id = gov.add_reference(PROJECT, state=state, generation=1)
    assert flow.run(action="import", ref=str(ref_id))["code"] == "INVALID_STATE"


def test_import_dry_run_reports_the_generation_and_touches_nothing(gov, flow):
    flow.create()
    result = flow.run(0, dry_run=True, action="import", ref=flow.ref)
    assert result == {"dry_run": True, "action": "import", "reference": flow.ref, "generation": 1}
    assert gov.ledger(PROJECT) == [] and gov.stores.stores["database"].calls == []


@pytest.mark.parametrize("failure, code", [
    ("DENIED", "STORE_DENIED"), ("SEALED", "STORE_SEALED"), ("TLS_INVALID", "STORE_TLS_INVALID"),
])
def test_a_store_that_refuses_the_write_releases_the_generation_at_once(gov, flow, failure, code):
    flow.create()
    gov.stores.stores["database"].fail["write"] = failure
    result = flow.run(action="import", ref=flow.ref)
    assert result["code"] == code and FIXTURE_VALUE not in json.dumps(result)
    row = flow.row
    assert (row.generation, row.pending_generation) == (0, None)
    (ledger,) = gov.ledger(PROJECT)
    assert ledger.state == "abandoned"
    failed = [event for event in flow.events if event["reason_code"] == code]
    assert failed and failed[0]["outcome"] == "failed"
    gov.stores.stores["database"].fail.clear()
    assert "error" not in flow.run(action="import", ref=flow.ref)  # the abandoned ledger row is reused
    (ledger,) = gov.ledger(PROJECT)
    assert (ledger.state, ledger.attempts) == ("committed", 2)


def test_a_timeout_after_the_write_leaves_the_generation_staged_for_the_reconciler(gov, flow):
    flow.create()
    store = gov.stores.stores["database"]
    store.fail_after_effect["write"] = "UNAVAILABLE"
    result = flow.run(action="import", ref=flow.ref)
    assert result["code"] == "STORE_UNAVAILABLE"
    assert (flow.row.generation, flow.row.pending_generation) == (0, 1)
    assert 1 in store.versions[uuid.UUID(flow.ref)]
    assert gov.ledger(PROJECT)[0].state == "intent"
    assert flow.run(action="import", ref=flow.ref)["code"] == "IMPORT_IN_FLIGHT"


def test_a_store_version_that_is_not_the_expected_one_is_a_conflict(gov, flow):
    flow.create()
    store = gov.stores.stores["database"]
    store.versions[uuid.UUID(flow.ref)] = {1: {"other": "x"}}  # someone else wrote generation 1
    result = flow.run(action="import", ref=flow.ref)
    assert result["code"] == "STORE_VERSION_CONFLICT"
    assert (flow.row.generation, flow.row.pending_generation) == (0, None)


@pytest.mark.parametrize("error, code", [
    (ValueError("NO_SECRET_FIELDS"), "NO_SECRET_FIELDS"), (ValueError("SECRET_UNRESOLVED"), "SECRET_UNRESOLVED"),
    (ValueError("something else"), "DEPENDENCY_UNAVAILABLE"), (PermissionError("x"), "DEPENDENCY_UNAVAILABLE"),
    (RuntimeError("x"), "DEPENDENCY_UNAVAILABLE"),
])
def test_a_configuration_that_cannot_give_its_secrets_abandons_the_import_without_touching_the_store(
        gov, flow, error, code):
    flow.create()
    gov.configurations.bundle_error = error
    result = flow.run(action="import", ref=flow.ref)
    assert result["code"] == code
    assert gov.stores.stores["database"].calls == [] and gov.stores.stores["database"].versions == {}
    assert (flow.row.generation, flow.row.pending_generation) == (0, None)
    assert gov.ledger(PROJECT)[0].state == "abandoned"


def test_a_configuration_deleted_before_the_import_is_reported(gov, flow):
    flow.create()
    del gov.configurations.rows[PROJECT][flow.config.id]
    assert flow.run(action="import", ref=flow.ref)["code"] == "CONFIGURATION_NOT_FOUND"
    assert flow.row.pending_generation is None


def test_without_an_audit_trail_nothing_is_staged_and_the_store_is_not_touched(gov, flow):
    flow.create()
    gov.tracing.fail = True
    result = flow.run(action="import", ref=flow.ref)
    assert result["code"] == "FAILED"
    assert flow.row.pending_generation is None and gov.ledger(PROJECT) == []
    assert gov.stores.stores["database"].calls == []


def test_a_lost_commit_race_is_reported_and_leaves_the_ledger_for_the_reconciler(gov, flow, monkeypatch):
    flow.create()
    monkeypatch.setattr(flow.ob, "commit_generation", lambda *a, **k: False)
    assert flow.run(action="import", ref=flow.ref)["code"] == "CONCURRENT_CHANGE"
    assert gov.ledger(PROJECT)[0].state == "written"


# --- crash windows: each ends in exactly one committed generation or a clean abandon ------------------------------------------

@pytest.fixture
def reconcile(gov, monkeypatch):
    reconciler = gov.module("utils.credential_reconcile")
    monkeypatch.setattr(reconciler, "project_ids_missing_credential_tables", lambda: [])  # the catalog is PostgreSQL's

    def run(older_than_s=0):
        return reconciler.reconcile_store(_Module(), f"project_id={PROJECT};older_than_s={older_than_s}", CREATOR)
    return run


class _Module:
    class context:  # noqa: N801
        class rpc_manager:  # noqa: N801
            class call:  # noqa: N801
                @staticmethod
                def project_list(filter_=None):
                    return [{"id": PROJECT}]


def test_crash_after_intent_is_abandoned_and_the_import_can_be_repeated(gov, flow, reconcile):
    flow.create()
    store = gov.stores.stores["database"]
    store.crash_before_write = True
    with pytest.raises(Crash):
        flow.run(action="import", ref=flow.ref)
    assert (flow.row.generation, flow.row.pending_generation) == (0, 1)
    assert gov.ledger(PROJECT)[0].state == "intent"
    store.crash_before_write = False
    assert flow.run(action="import", ref=flow.ref)["code"] == "IMPORT_IN_FLIGHT"
    result = reconcile()
    assert result["abandoned"] == 1 and result["failed"] == 0
    assert (flow.row.generation, flow.row.pending_generation) == (0, None)
    assert [entry.state for entry in gov.ledger(PROJECT)] == ["abandoned"]
    assert "error" not in flow.run(action="import", ref=flow.ref)
    assert flow.row.generation == 1 and list(store.versions[uuid.UUID(flow.ref)]) == [1]


def test_crash_after_the_store_write_is_rolled_forward_to_one_generation(gov, flow, reconcile):
    flow.create()
    store = gov.stores.stores["database"]
    store.crash_after_write = True
    with pytest.raises(Crash):
        flow.run(action="import", ref=flow.ref)
    assert (flow.row.generation, flow.row.pending_generation) == (0, 1)
    assert list(store.versions[uuid.UUID(flow.ref)]) == [1]
    store.crash_after_write = False
    result = reconcile()
    assert result["rolled_forward"] == 1
    row = flow.row
    assert (row.generation, row.pending_generation, row.state, row.configuration_generation) == (1, None, "pending", 1)
    assert [entry.state for entry in gov.ledger(PROJECT)] == ["committed"]
    assert list(store.versions[uuid.UUID(flow.ref)]) == [1]
    assert "CREDENTIAL_RECONCILED_COMMITTED" in flow.reasons()
    assert reconcile() == {"failed": 0, "failed_projects": [], "dry_run": False}  # nothing left to settle
    assert flow.run(action="probe", ref=flow.ref)["state"] == "validated"


def test_crash_after_the_ledger_was_marked_written_is_rolled_forward_too(gov, flow, reconcile, monkeypatch):
    flow.create()

    def die(*_args, **_kwargs):
        raise Crash()
    with monkeypatch.context() as patched:
        patched.setattr(flow.ob, "commit_generation", die)
        with pytest.raises(Crash):
            flow.run(action="import", ref=flow.ref)
    assert gov.ledger(PROJECT)[0].state == "written"
    assert (flow.row.generation, flow.row.pending_generation) == (0, 1)
    assert reconcile()["rolled_forward"] == 1
    assert flow.row.generation == 1 and gov.ledger(PROJECT)[0].state == "committed"
    assert list(gov.stores.stores["database"].versions[uuid.UUID(flow.ref)]) == [1]


# --- probe ----------------------------------------------------------------------------------------------------------------

def test_probe_validates_the_generation_the_store_holds(gov, flow):
    flow.imported()
    result = flow.run(action="probe", ref=flow.ref)
    assert result == {"action": "probe", "reference": flow.ref, "generation": 1, "state": "validated", "dry_run": False}
    row = flow.row
    assert (row.state, row.validated_generation) == ("validated", 1)
    started = next(e for e in flow.events if e["reason_code"] == "CREDENTIAL_PROBE_STARTED")
    passed = next(e for e in flow.events if e["reason_code"] == "CREDENTIAL_REF_VALIDATED")
    assert (passed["event_type"], passed["outcome"], passed["vault_request_id"]) == ("probe", "success", "req-meta")
    store = gov.stores.stores["database"]
    assert store.calls[-2:] == [("metadata", "probe", started["event_id"]), ("read", "probe", started["event_id"])]
    assert gov.configurations.bundle_calls[-1][2] == "probe"


def test_probe_fails_when_the_configuration_secret_moved_on(gov, flow):
    flow.imported()
    gov.configurations.edit_secret(flow.config, api_key=FIXTURE_VALUE_2)
    result = flow.run(action="probe", ref=flow.ref)
    assert result["code"] == "MATERIAL_MISMATCH"
    assert flow.row.state == "pending"
    failed = next(e for e in flow.events if e["reason_code"] == "MATERIAL_MISMATCH")
    assert (failed["event_type"], failed["outcome"]) == ("probe", "failed")
    assert FIXTURE_VALUE not in json.dumps(flow.events) and FIXTURE_VALUE_2 not in json.dumps(flow.events)


def test_probe_fails_when_the_configuration_changed_even_if_the_secret_did_not(gov, flow):
    flow.imported()
    flow.config.generation += 1  # a non-secret edit bumps the generation too
    assert flow.run(action="probe", ref=flow.ref)["code"] == "CONFIGURATION_CHANGED"
    assert flow.row.state == "pending"


def test_probe_fails_when_the_store_lost_the_generation(gov, flow):
    flow.imported()
    gov.stores.stores["database"].versions.clear()
    assert flow.run(action="probe", ref=flow.ref)["code"] == "STORE_NOT_FOUND"
    assert flow.row.state == "pending"


def test_probe_reports_a_sealed_store_and_stays_pending(gov, flow):
    flow.imported()
    gov.stores.stores["database"].fail["metadata"] = "SEALED"
    assert flow.run(action="probe", ref=flow.ref)["code"] == "STORE_SEALED"
    assert flow.row.state == "pending"
    assert any(e["reason_code"] == "STORE_SEALED" and e["outcome"] == "failed" for e in flow.events)


def test_probe_needs_a_committed_generation_and_nothing_staged(gov, flow):
    flow.create()
    assert flow.run(action="probe", ref=flow.ref)["code"] == "INVALID_STATE"  # nothing imported yet
    flow.run(action="import", ref=flow.ref)
    flow.run(action="probe", ref=flow.ref)
    assert flow.run(action="probe", ref=flow.ref)["code"] == "INVALID_STATE"  # already validated


def test_probe_dry_run_does_not_audit_or_read(gov, flow):
    flow.imported()
    store = gov.stores.stores["database"]
    calls, events = list(store.calls), len(flow.events)
    result = flow.run(0, dry_run=True, action="probe", ref=flow.ref)
    assert result["dry_run"] is True and store.calls == calls and len(flow.events) == events


# --- approve and activate -------------------------------------------------------------------------------------------------------

def test_a_second_operator_approves_and_the_approval_is_audited(gov, flow):
    flow.validated()
    result = flow.run(APPROVER, action="approve", ref=flow.ref, approval_ref="CHG-5", policy_revision="rev-5")
    assert result["approved"] is True and result["state"] == "validated"
    row = flow.row
    assert (row.approved_by, row.approval_ref, row.policy_revision) == (APPROVER, "CHG-5", "rev-5")
    event = next(e for e in flow.events if e["reason_code"] == "CREDENTIAL_REF_APPROVED")
    assert (event["event_type"], event["approver_ref"], event["policy_revision"], event["caller_ref"]) == (
        "approval", "CHG-5", "rev-5", f"operator:{APPROVER}")


def test_the_creator_cannot_approve_their_own_reference(gov, flow):
    flow.validated()
    result = flow.run(CREATOR, action="approve", ref=flow.ref, approval_ref="CHG-5", policy_revision="rev-5")
    assert result["code"] == "SELF_APPROVAL"
    assert flow.row.approved_by is None and "CREDENTIAL_REF_APPROVED" not in flow.reasons()


def test_approval_needs_a_validated_reference_and_happens_once(gov, flow):
    flow.imported()
    args = dict(action="approve", ref=flow.ref, approval_ref="CHG-5", policy_revision="rev-5")
    assert flow.run(APPROVER, **args)["code"] == "INVALID_STATE"  # still pending
    flow.run(action="probe", ref=flow.ref)
    assert "error" not in flow.run(APPROVER, **args)
    assert flow.run(OTHER, **args)["code"] == "INVALID_STATE"
    assert flow.row.approved_by == APPROVER


def test_activation_needs_the_approval_first(gov, flow):
    flow.validated()
    assert flow.run(APPROVER, action="activate", ref=flow.ref)["code"] == "APPROVAL_REQUIRED"
    assert flow.row.state == "validated"


def test_the_full_onboarding_ends_active_with_an_audit_trail(gov, flow):
    flow.active()
    row = flow.row
    assert (row.state, row.generation, row.validated_generation, row.approved_by) == ("active", 1, 1, APPROVER)
    assert flow.reasons() == [
        "CREDENTIAL_REF_PENDING", "CREDENTIAL_IMPORT_STARTED", "CREDENTIAL_GENERATION_COMMITTED",
        "CREDENTIAL_PROBE_STARTED", "CREDENTIAL_REF_VALIDATED", "CREDENTIAL_REF_APPROVED", "CREDENTIAL_REF_ACTIVE"]
    active = flow.events[-1]
    assert (active["approver_ref"], active["policy_revision"], active["credential_generation"]) == ("CHG-5", "rev-5", 1)


# --- suspend, resume, retire ----------------------------------------------------------------------------------------------------

def test_suspend_revokes_live_runs_in_the_same_transaction_and_raises_the_epoch(gov, flow):
    flow.active()
    result = flow.run(APPROVER, action="suspend", ref=flow.ref)
    assert result["state"] == "suspended"
    assert gov.core.revoked == [uuid.UUID(flow.ref)]
    assert flow.row.revocation_epoch == 1
    event = flow.events[-1]
    assert (event["reason_code"], event["revocation_epoch"]) == ("CREDENTIAL_REF_SUSPENDED", 1)
    assert flow.run(APPROVER, action="resume", ref=flow.ref)["state"] == "active"
    assert gov.core.revoked == [uuid.UUID(flow.ref)]  # resuming revokes nothing
    assert flow.events[-1]["reason_code"] == "CREDENTIAL_REF_ACTIVE"


def test_a_failing_revocation_rolls_the_whole_change_back(gov, flow):
    flow.active()

    def boom(session, ref):
        raise RuntimeError("admission layer failed")
    gov.core.revoke_credential_contexts = boom
    before = len(flow.events)
    assert flow.run(APPROVER, action="suspend", ref=flow.ref)["code"] == "FAILED"
    assert flow.row.state == "active" and flow.row.revocation_epoch == 0 and len(flow.events) == before


def test_suspend_works_while_the_admission_layer_is_not_installed(gov, flow):
    flow.active()
    gov.this.modules["elitea_core"] = SimpleNamespace(module=object())  # no revoke_credential_contexts
    assert flow.run(APPROVER, action="suspend", ref=flow.ref)["state"] == "suspended"
    assert any("revoke_credential_contexts is not available" in line for line in StubLog.records)


def test_a_failed_audit_rolls_a_state_change_back(gov, flow):
    flow.active()
    gov.tracing.fail = True
    assert flow.run(APPROVER, action="suspend", ref=flow.ref)["code"] == "FAILED"
    assert flow.row.state == "active" and flow.row.revocation_epoch == 0


@pytest.mark.parametrize("action, setup, state", [
    ("suspend", "imported", "pending"), ("resume", "active", "active"), ("suspend", "retired", "retired"),
])
def test_moves_out_of_the_wrong_state_are_refused(gov, flow, action, setup, state):
    if setup == "retired":
        flow.imported()
        flow.run(action="retire", ref=flow.ref)
    else:
        getattr(flow, setup)()
    assert flow.run(APPROVER, action=action, ref=flow.ref)["code"] == "INVALID_STATE"
    assert flow.row.state == state


def test_retire_takes_the_reference_out_of_use_then_deletes_its_material(gov, flow):
    flow.active()
    result = flow.run(APPROVER, action="retire", ref=flow.ref)
    assert (result["state"], result["material_deleted"]) == ("retired", True)
    store = gov.stores.stores["database"]
    assert uuid.UUID(flow.ref) not in store.versions
    assert gov.core.revoked == [uuid.UUID(flow.ref)]
    assert flow.row.revocation_epoch == 1
    ledger = {entry.op: entry for entry in gov.ledger(PROJECT)}
    assert (ledger["delete_all"].state, ledger["delete_all"].generation) == ("committed", 1)
    retired = next(e for e in flow.events if e["reason_code"] == "CREDENTIAL_REF_RETIRED")
    deleted = next(e for e in flow.events if e["reason_code"] == "CREDENTIAL_MATERIAL_DELETED")
    assert retired["event_id"] == ledger["delete_all"].correlation_id
    assert store.calls[-1] == ("delete_all", "retire", retired["event_id"]) and deleted["outcome"] == "success"


def test_retire_with_a_store_that_is_down_still_retires_and_leaves_the_deletion_to_the_reconciler(gov, flow, reconcile):
    flow.active()
    store = gov.stores.stores["database"]
    store.fail["delete_all"] = "UNAVAILABLE"
    result = flow.run(APPROVER, action="retire", ref=flow.ref)
    assert (result["state"], result["material_deleted"]) == ("retired", False)
    assert uuid.UUID(flow.ref) in store.versions
    assert any(e["reason_code"] == "STORE_UNAVAILABLE" and e["outcome"] == "failed" for e in flow.events)
    store.fail.clear()
    assert reconcile()["completed"] == 1
    assert uuid.UUID(flow.ref) not in store.versions and "CREDENTIAL_RECONCILED_DELETED" in flow.reasons()


def test_retire_of_a_reference_with_no_material_does_not_call_the_store(gov, flow):
    flow.create()
    result = flow.run(action="retire", ref=flow.ref)
    assert result == {"action": "retire", "reference": flow.ref, "state": "retired", "dry_run": False}
    assert gov.stores.stores["database"].calls == [] and gov.ledger(PROJECT) == []


def test_retire_also_covers_a_staged_but_uncommitted_generation(gov, flow):
    flow.create()
    store = gov.stores.stores["database"]
    store.crash_after_write = True
    with pytest.raises(Crash):
        flow.run(action="import", ref=flow.ref)
    store.crash_after_write = False
    result = flow.run(action="retire", ref=flow.ref)
    assert result["material_deleted"] is True and uuid.UUID(flow.ref) not in store.versions


def test_dry_runs_of_the_moves_report_without_changing(gov, flow):
    flow.active()
    for action, to in (("suspend", "suspended"), ("retire", "retired")):
        result = flow.run(0, dry_run=True, action=action, ref=flow.ref)
        assert result == {"dry_run": True, "action": action, "reference": flow.ref, "from": "active", "to": to}
    assert flow.row.state == "active" and gov.core.revoked == []


def test_unknown_reference_and_other_project(gov, flow):
    assert flow.run(action="import", ref=str(uuid.uuid4()))["code"] == "REFERENCE_NOT_FOUND"
    flow.create()
    assert flow.run(project_id=PROJECT + 1, action="import", ref=flow.ref)["code"] == "REFERENCE_NOT_FOUND"


# --- nothing sensitive leaves ------------------------------------------------------------------------------------------------------

def test_no_result_event_or_log_line_carries_material_or_a_locator(gov, flow):
    flow.active(store_kind="corporate_vault")
    flow.run(APPROVER, action="suspend", ref=flow.ref)
    flow.run(APPROVER, action="retire", ref=flow.ref)
    gov.stores.stores["database"].fail["write"] = "SEALED"
    other = gov.configurations.add(PROJECT, secrets={"api_key": FIXTURE_VALUE_2})
    flow.create(config=other)
    assert flow.run(action="import", ref=flow.ref)["code"] == "STORE_SEALED"  # a failure path as well
    everything = json.dumps({"results": flow.results, "events": gov.db.events(PROJECT)}, default=str)
    everything += "\n".join(StubLog.records)
    for forbidden in (FIXTURE_VALUE, FIXTURE_VALUE_2, "credential_store", "kv-elitea", "locator", "mount", "section"):
        assert forbidden not in everything, forbidden


def test_the_store_context_is_minted_for_the_exact_reference_and_project(gov, flow):
    flow.imported()
    ref_id = uuid.UUID(flow.ref)
    assert [call[:2] for call in gov.stores.stores["database"].calls] == [("write", "onboard")]
    # a context for another reference or project is refused by the adapter, not by convention
    other = gov.stores.CredentialStoreProvider.mint(
        "onboard", decision_id=str(uuid.uuid4()), actor_ref="operator:1", project_id=PROJECT, ref_id=uuid.uuid4())
    ref = gov.stores.StoreRef(ref_id, PROJECT, "database", {})
    with pytest.raises(gov.stores.StoreError) as caught:
        gov.stores.stores["database"].write(ref, gov.stores.SecretValue({"a": "b"}, 2), expected_version=1, ctx=other)
    assert caught.value.code == "DENIED"
