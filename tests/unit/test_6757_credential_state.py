"""C-1009 (#6757): credential reference and use grant - tables, constraints, immutability, state machines, CAS.

The real models and state functions run against SQLite (PostgreSQL with ELITEA_TEST_PG_DSN): the statements
that decide a race are executed, not compiled.
"""
import itertools
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateIndex, CreateTable

REFERENCE_STATES = ("pending", "validated", "active", "suspended", "retired")
GRANT_STATES = ("pending_approval", "active", "suspended", "revoked")
# Written out here on purpose: the tables in the module must equal this reading of the design.
REFERENCE_ALLOWED = {
    ("pending", "validated"), ("validated", "pending"), ("validated", "active"), ("active", "suspended"),
    ("suspended", "active"), ("pending", "retired"), ("validated", "retired"), ("active", "retired"),
    ("suspended", "retired"),
}
GRANT_ALLOWED = {
    ("pending_approval", "active"), ("active", "suspended"), ("suspended", "active"),
    ("pending_approval", "revoked"), ("active", "revoked"), ("suspended", "revoked"),
}
ENTERING_REVOKED = {"suspended", "retired", "revoked"}
CREATOR, APPROVER, OPERATOR = 10, 20, 7


@pytest.fixture
def st(gov):
    return gov.module("utils.credential_state")


@pytest.fixture
def models(gov):
    return gov.module("models.credential_governance")


def session_for(gov, project_id=1):
    return gov.db.get_session(project_id)


def prepared_reference(gov, expected, **overrides):
    """A reference in ``expected`` with every guard of a move out of it satisfied."""
    if expected in ("pending", "validated"):
        values = dict(generation=1, configuration_generation=1)
        if expected == "validated":
            values.update(validated_generation=1, approved_by=APPROVER, approval_ref="CHG-1", policy_revision="rev-1")
        values.update(overrides)
        return gov.add_reference(state=expected, **values)
    return gov.add_reference(state=expected, **overrides)


def move_reference(gov, st, ref_id, expected, target, actor=OPERATOR, **kwargs):
    with session_for(gov) as session:
        done = st.transition_reference(session, ref_id, expected, target, actor=actor, **kwargs)
        session.commit()
        return done


# --- the tables ---------------------------------------------------------------------------------------------------

def test_transition_tables_equal_the_design(st):
    assert set(st.REFERENCE_TRANSITIONS) == REFERENCE_ALLOWED
    assert set(st.GRANT_TRANSITIONS) == GRANT_ALLOWED
    assert set(st.BUMPS_EPOCH) == ENTERING_REVOKED


@pytest.mark.parametrize("expected, target", list(itertools.product(REFERENCE_STATES, repeat=2)))
def test_reference_state_matrix(gov, st, expected, target):
    ref_id = prepared_reference(gov, expected)
    before = gov.reference(1, ref_id)
    extra = {"validated_generation": 1} if (expected, target) == ("pending", "validated") else {}
    if (expected, target) not in REFERENCE_ALLOWED:
        with pytest.raises(st.InvalidTransition) as caught:
            move_reference(gov, st, ref_id, expected, target, **extra)
        assert caught.value.reason_code == "INVALID_TRANSITION"
        assert gov.reference(1, ref_id) == before
        return
    assert move_reference(gov, st, ref_id, expected, target, **extra) is True
    after = gov.reference(1, ref_id)
    assert after.state == target and after.state_changed_by == OPERATOR
    assert after.revocation_epoch == before.revocation_epoch + (1 if target in ENTERING_REVOKED else 0)


@pytest.mark.parametrize("expected, target", list(itertools.product(GRANT_STATES, repeat=2)))
def test_grant_state_matrix(gov, st, expected, target):
    grant_id = gov.add_grant(state=expected)
    before = gov.grant(1, grant_id)
    legal = (expected, target) in GRANT_ALLOWED and (expected, target) != ("pending_approval", "active")
    with session_for(gov) as session:
        if not legal:
            with pytest.raises(st.InvalidTransition) as caught:
                st.transition_grant(session, grant_id, expected, target, actor=OPERATOR)
            assert caught.value.reason_code == "INVALID_TRANSITION"
            assert gov.grant(1, grant_id) == before
            return
        assert st.transition_grant(session, grant_id, expected, target, actor=OPERATOR) is True
        session.commit()
    after = gov.grant(1, grant_id)
    assert after.state == target and after.state_changed_by == OPERATOR
    assert after.revocation_epoch == before.revocation_epoch + (1 if target in ENTERING_REVOKED else 0)


# --- guards ---------------------------------------------------------------------------------------------------------

def test_a_stale_expected_state_loses_the_race_and_changes_nothing(gov, st):
    ref_id = gov.add_reference(state="active")
    before = gov.reference(1, ref_id)
    assert move_reference(gov, st, ref_id, "validated", "retired") is False
    assert gov.reference(1, ref_id) == before


def test_an_unknown_row_is_false_not_an_error(gov, st):
    assert move_reference(gov, st, uuid.uuid4(), "active", "suspended") is False


@pytest.mark.parametrize("actor", [0, None, -3, True, "7", 7.0])
def test_a_change_needs_an_identified_operator(gov, st, actor):
    ref_id = gov.add_reference(state="active")
    grant_id = gov.add_grant(state="active")
    with session_for(gov) as session:
        for call in (
                lambda: st.transition_reference(session, ref_id, "active", "suspended", actor=actor),
                lambda: st.transition_grant(session, grant_id, "active", "suspended", actor=actor),
                lambda: st.approve_reference(session, ref_id, actor=actor, approval_ref="a", policy_revision="p"),
                lambda: st.approve_grant(session, grant_id, actor=actor, approval_ref="a", policy_revision="p"),
        ):
            with pytest.raises(st.InvalidTransition) as caught:
                call()
            assert caught.value.reason_code == "ACTOR_REQUIRED"
    assert gov.reference(1, ref_id).state == "active" and gov.grant(1, grant_id).state == "active"


def test_activation_needs_an_approval(gov, st):
    ref_id = prepared_reference(gov, "validated", approved_by=None, approval_ref=None, policy_revision=None)
    assert move_reference(gov, st, ref_id, "validated", "active") is False
    assert gov.reference(1, ref_id).state == "validated"


def test_activation_needs_the_probe_to_have_seen_the_committed_generation(gov, st):
    ref_id = prepared_reference(gov, "validated", generation=2, validated_generation=1)
    assert move_reference(gov, st, ref_id, "validated", "active") is False
    ref_id = prepared_reference(gov, "validated", validated_generation=None)
    assert move_reference(gov, st, ref_id, "validated", "active") is False


def test_resuming_has_the_same_guards_as_activating(gov, st):
    ref_id = gov.add_reference(state="suspended", approved_by=None, approval_ref=None, policy_revision=None,
                               validated_generation=None)
    assert move_reference(gov, st, ref_id, "suspended", "active") is False
    ref_id = gov.add_reference(state="suspended")
    assert move_reference(gov, st, ref_id, "suspended", "active") is True


def test_a_probe_result_holds_only_for_the_generation_it_saw(gov, st):
    ref_id = prepared_reference(gov, "pending", generation=2)
    assert move_reference(gov, st, ref_id, "pending", "validated", validated_generation=1) is False
    assert move_reference(gov, st, ref_id, "pending", "validated", validated_generation=2) is True
    assert gov.reference(1, ref_id).validated_generation == 2


def test_a_probe_cannot_validate_while_a_write_is_staged(gov, st):
    ref_id = prepared_reference(gov, "pending", pending_generation=2)
    assert move_reference(gov, st, ref_id, "pending", "validated", validated_generation=1) is False


@pytest.mark.parametrize("probed", [None, 0, -1, "1", True])
def test_pending_to_validated_needs_a_real_generation(gov, st, probed):
    ref_id = prepared_reference(gov, "pending")
    with pytest.raises(st.InvalidTransition):
        move_reference(gov, st, ref_id, "pending", "validated", validated_generation=probed)


def test_invalidating_a_probe_clears_it_and_the_approval(gov, st):
    ref_id = prepared_reference(gov, "validated")
    assert move_reference(gov, st, ref_id, "validated", "pending") is True
    row = gov.reference(1, ref_id)
    assert (row.state, row.validated_generation, row.approved_by, row.approval_ref, row.policy_revision) == (
        "pending", None, None, None, None)


def test_the_epoch_accumulates_across_suspend_resume_suspend_retire(gov, st):
    ref_id = gov.add_reference(state="active")
    for expected, target in (("active", "suspended"), ("suspended", "active"), ("active", "suspended"),
                             ("suspended", "retired")):
        assert move_reference(gov, st, ref_id, expected, target) is True
    assert gov.reference(1, ref_id).revocation_epoch == 3


# --- approval -------------------------------------------------------------------------------------------------------

def approve(gov, st, ref_id, actor=APPROVER, approval_ref="CHG-9", policy_revision="rev-9", kind="reference"):
    with session_for(gov) as session:
        function = st.approve_reference if kind == "reference" else st.approve_grant
        done = function(session, ref_id, actor=actor, approval_ref=approval_ref, policy_revision=policy_revision)
        session.commit()
        return done


def test_approval_records_who_and_leaves_the_state(gov, st):
    ref_id = prepared_reference(gov, "validated", approved_by=None, approval_ref=None, policy_revision=None)
    assert approve(gov, st, ref_id) is True
    row = gov.reference(1, ref_id)
    assert (row.state, row.approved_by, row.approval_ref, row.policy_revision) == ("validated", APPROVER, "CHG-9", "rev-9")


def test_the_creator_cannot_approve(gov, st):
    ref_id = prepared_reference(gov, "validated", approved_by=None, approval_ref=None, policy_revision=None)
    assert approve(gov, st, ref_id, actor=CREATOR) is False
    assert gov.reference(1, ref_id).approved_by is None
    grant_id = gov.add_grant(state="pending_approval")
    assert approve(gov, st, grant_id, actor=CREATOR, kind="grant") is False
    assert gov.grant(1, grant_id).state == "pending_approval"


def test_only_a_validated_reference_can_be_approved_and_only_once(gov, st):
    pending = prepared_reference(gov, "pending")
    assert approve(gov, st, pending) is False
    validated = prepared_reference(gov, "validated", approved_by=None, approval_ref=None, policy_revision=None)
    assert approve(gov, st, validated, actor=APPROVER) is True
    assert approve(gov, st, validated, actor=30) is False
    assert gov.reference(1, validated).approved_by == APPROVER


@pytest.mark.parametrize("approval_ref, policy_revision", [
    ("", "rev"), ("   ", "rev"), ("a", ""), (None, "rev"), ("a", None), ("x" * 129, "rev"), ("a", "x" * 129), (5, "rev"),
])
def test_approval_needs_both_references(gov, st, approval_ref, policy_revision):
    ref_id = prepared_reference(gov, "validated", approved_by=None, approval_ref=None, policy_revision=None)
    with pytest.raises(st.InvalidTransition) as caught:
        approve(gov, st, ref_id, approval_ref=approval_ref, policy_revision=policy_revision)
    assert caught.value.reason_code == "APPROVAL_REQUIRED"


def test_approving_a_grant_activates_it_in_one_statement(gov, st):
    grant_id = gov.add_grant(state="pending_approval")
    assert approve(gov, st, grant_id, kind="grant") is True
    row = gov.grant(1, grant_id)
    assert (row.state, row.approved_by, row.approval_ref, row.policy_revision) == ("active", APPROVER, "CHG-9", "rev-9")
    assert approve(gov, st, grant_id, actor=30, kind="grant") is False


def test_user_delegation_and_mandate_grants_can_both_be_activated(gov, st):
    for kind in ("user_delegation", "mandate"):
        grant_id = gov.add_grant(state="pending_approval", subject_kind=kind)
        assert approve(gov, st, grant_id, kind="grant") is True
        assert gov.grant(1, grant_id).state == "active"


def test_a_grant_cannot_be_resumed_without_an_approval(gov, st):
    grant_id = gov.add_grant(state="suspended", approved_by=None, approval_ref=None, policy_revision=None)
    with session_for(gov) as session:
        assert st.transition_grant(session, grant_id, "suspended", "active", actor=OPERATOR) is False


# --- the database refuses what the code would not do ------------------------------------------------------------------

def run_update(gov, models, model, row_id, **values):
    with session_for(gov) as session:
        session.execute(sa.update(model).where(model.id == row_id).values(**values))
        session.commit()


def test_active_without_an_approval_is_refused_by_the_table(gov, models):
    ref_id = prepared_reference(gov, "validated", approved_by=None, approval_ref=None, policy_revision=None)
    with pytest.raises(IntegrityError):
        run_update(gov, models, models.CredentialReference, ref_id, state="active")
    grant_id = gov.add_grant(state="pending_approval")
    with pytest.raises(IntegrityError):
        run_update(gov, models, models.CredentialUseGrant, grant_id, state="active")


def test_active_must_have_been_probed_at_its_generation(gov, models):
    ref_id = prepared_reference(gov, "validated", generation=2, validated_generation=1)
    with pytest.raises(IntegrityError):
        run_update(gov, models, models.CredentialReference, ref_id, state="active")


def test_the_approver_can_never_be_the_creator(gov, models):
    ref_id = prepared_reference(gov, "validated", approved_by=None)
    with pytest.raises(IntegrityError):
        run_update(gov, models, models.CredentialReference, ref_id, approved_by=CREATOR)
    grant_id = gov.add_grant(state="pending_approval")
    with pytest.raises(IntegrityError):
        run_update(gov, models, models.CredentialUseGrant, grant_id, approved_by=CREATOR)


@pytest.mark.parametrize("column, value", [("state", "frozen"), ("ownership_class", "shared"), ("store_kind", "file")])
def test_closed_lists_are_enforced(gov, models, column, value):
    ref_id = gov.add_reference()
    with pytest.raises(IntegrityError):
        run_update(gov, models, models.CredentialReference, ref_id, **{column: value})


def test_one_live_reference_per_configuration(gov):
    first = gov.add_reference(configuration_id=500)
    with pytest.raises(IntegrityError):
        gov.add_reference(configuration_id=500)
    gov.reference(1, first)
    with session_for(gov) as session:
        session.execute(sa.text(gov.db._qualify(1, "UPDATE tenant.credential_reference SET state = 'retired'")))
        session.commit()
    gov.add_reference(configuration_id=500)  # a retired one does not count


def test_a_grant_key_is_unique(gov):
    key = dict(agent_binding_ref=uuid.uuid4(), toolkit_instance_id="41", credential_ref=uuid.uuid4(),
               subject_ref="idp:t1:u1")
    gov.add_grant(**key)
    with pytest.raises(IntegrityError):
        gov.add_grant(**key)
    gov.add_grant(**{**key, "subject_ref": "idp:t1:u2"})


def test_one_ledger_row_per_reference_generation_and_operation(gov, models):
    ref_id = uuid.uuid4()

    def add(op="write", generation=1):
        with session_for(gov) as session:
            session.add(models.CredentialStoreLedger(
                credential_ref=ref_id, generation=generation, store_kind="database", op=op, correlation_id="c"))
            session.commit()
    add()
    add(op="delete_all")
    add(generation=2)
    with pytest.raises(IntegrityError):
        add()


def test_the_tables_compile_for_postgresql_in_the_tenant_schema(models):
    dialect = postgresql.dialect()
    for table in (models.CredentialReference, models.CredentialUseGrant, models.CredentialStoreLedger):
        ddl = str(CreateTable(table.__table__).compile(dialect=dialect))
        assert f"CREATE TABLE tenant.{table.__tablename__}" in ddl
    indexes = {i.name: i for i in models.CredentialReference.__table__.indexes}
    assert "uq_credential_reference_live_configuration" not in indexes   # replaced by the pair below (#7119)
    shared = str(CreateIndex(indexes["uq_credential_reference_live_shared"]).compile(dialect=dialect))
    assert "UNIQUE INDEX" in shared and "(configuration_id)" in shared
    assert "WHERE state <> 'retired' AND ownership_class <> 'personal'" in shared
    personal = str(CreateIndex(indexes["uq_credential_reference_live_personal"]).compile(dialect=dialect))
    assert "UNIQUE INDEX" in personal and "(configuration_id, (custodian_ref->>'subject_ref'))" in personal
    assert "WHERE state <> 'retired' AND ownership_class = 'personal'" in personal


# --- generation compare-and-set -----------------------------------------------------------------------------------

def claim(gov, st, ref_id, generation):
    with session_for(gov) as session:
        done = st.claim_generation(session, ref_id, generation)
        session.commit()
        return done


def commit(gov, st, ref_id, generation, configuration_generation=4):
    with session_for(gov) as session:
        done = st.commit_generation(session, ref_id, generation, configuration_generation)
        session.commit()
        return done


def test_two_importers_one_wins_the_claim(gov, st):
    ref_id = gov.add_reference()
    assert claim(gov, st, ref_id, 1) is True
    assert claim(gov, st, ref_id, 1) is False
    assert gov.reference(1, ref_id).pending_generation == 1


@pytest.mark.parametrize("generation", [0, 2, 5])
def test_a_claim_must_be_the_next_generation(gov, st, generation):
    ref_id = gov.add_reference()
    assert claim(gov, st, ref_id, generation) is False


@pytest.mark.parametrize("state", ["active", "suspended", "retired"])
def test_a_claim_is_refused_outside_pending_and_validated(gov, st, state):
    ref_id = gov.add_reference(state=state, generation=1)
    assert claim(gov, st, ref_id, 2) is False


def test_a_released_claim_can_be_taken_again(gov, st):
    ref_id = gov.add_reference()
    claim(gov, st, ref_id, 1)
    with session_for(gov) as session:
        assert st.release_generation(session, ref_id, 2) is False  # not the staged generation
        assert st.release_generation(session, ref_id, 1) is True
        session.commit()
    assert claim(gov, st, ref_id, 1) is True


def test_committing_a_staged_generation_moves_it_into_place(gov, st):
    ref_id = gov.add_reference()
    claim(gov, st, ref_id, 1)
    assert commit(gov, st, ref_id, 1, configuration_generation=4) is True
    row = gov.reference(1, ref_id)
    assert (row.generation, row.pending_generation, row.configuration_generation, row.state) == (1, None, 4, "pending")


def test_a_double_commit_has_one_winner(gov, st):
    ref_id = gov.add_reference()
    claim(gov, st, ref_id, 1)
    assert commit(gov, st, ref_id, 1) is True
    assert commit(gov, st, ref_id, 1) is False
    assert gov.reference(1, ref_id).generation == 1


def test_a_stale_expected_generation_cannot_commit(gov, st):
    ref_id = gov.add_reference(generation=3)
    claim(gov, st, ref_id, 4)
    assert commit(gov, st, ref_id, 2) is False  # an old importer arrives late
    assert commit(gov, st, ref_id, 5) is False  # skips a generation
    assert gov.reference(1, ref_id).generation == 3


def test_an_unstaged_generation_cannot_commit(gov, st):
    ref_id = gov.add_reference()
    assert commit(gov, st, ref_id, 1) is False


def test_committing_over_a_validated_reference_sends_it_back_to_pending_and_drops_its_approval(gov, st):
    ref_id = prepared_reference(gov, "validated")
    claim(gov, st, ref_id, 2)
    assert commit(gov, st, ref_id, 2) is True
    row = gov.reference(1, ref_id)
    assert (row.state, row.generation, row.validated_generation, row.approved_by, row.approval_ref,
            row.policy_revision) == ("pending", 2, None, None, None, None)


@pytest.mark.parametrize("state", ["active", "suspended", "retired"])
def test_committing_never_touches_a_reference_in_use_or_retired(gov, st, state):
    ref_id = gov.add_reference(state=state, generation=1, pending_generation=2)
    assert commit(gov, st, ref_id, 2) is False
    assert gov.reference(1, ref_id).generation == 1


# --- immutability ---------------------------------------------------------------------------------------------------------

REFERENCE_NEW_VALUES = {
    "id": lambda: uuid.uuid4(), "project_id": lambda: 99, "configuration_id": lambda: 99,
    "configuration_uuid": lambda: uuid.uuid4(), "provider": lambda: "other", "auth_mode": lambda: "oauth",
    "ownership_class": lambda: "service", "target_ref": lambda: "t", "environment": lambda: "prod",
    "store_kind": lambda: "corporate_vault", "created_by": lambda: 99,
}
GRANT_NEW_VALUES = {
    "id": lambda: uuid.uuid4(), "project_id": lambda: 99, "application_id": lambda: 99,
    "subject_kind": lambda: "mandate", "subject_ref": lambda: "idp:t1:u9", "agent_binding_ref": lambda: uuid.uuid4(),
    "toolkit_instance_id": lambda: "99", "credential_ref": lambda: uuid.uuid4(), "target_ref": lambda: "t",
    "created_by": lambda: 99,
}


def test_the_immutable_sets_are_the_design_columns(models):
    assert set(models.REFERENCE_IMMUTABLE) == set(REFERENCE_NEW_VALUES)
    assert set(models.GRANT_IMMUTABLE) == set(GRANT_NEW_VALUES)


@pytest.mark.parametrize("column", sorted(REFERENCE_NEW_VALUES))
def test_a_reference_column_cannot_change_through_the_orm(gov, models, column):
    ref_id = gov.add_reference(environment="dev", target_ref="x")
    with session_for(gov) as session:
        row = session.get(models.CredentialReference, ref_id)
        setattr(row, column, REFERENCE_NEW_VALUES[column]())
        with pytest.raises(models.ImmutableFieldChanged):
            session.flush()
        session.rollback()


@pytest.mark.parametrize("column", sorted(GRANT_NEW_VALUES))
def test_a_grant_column_cannot_change_through_the_orm(gov, models, column):
    grant_id = gov.add_grant()
    with session_for(gov) as session:
        row = session.get(models.CredentialUseGrant, grant_id)
        setattr(row, column, GRANT_NEW_VALUES[column]())
        with pytest.raises(models.ImmutableFieldChanged):
            session.flush()
        session.rollback()


def test_the_mutable_columns_still_change_and_a_no_op_write_is_not_a_change(gov, models):
    ref_id = gov.add_reference()
    with session_for(gov) as session:
        row = session.get(models.CredentialReference, ref_id)
        row.state, row.generation, row.custodian_ref, row.store_locator = "validated", 3, {"user_id": 1}, {"x": 1}
        row.provider = row.provider  # same value
        session.commit()
    assert gov.reference(1, ref_id).generation == 3


def test_approved_by_is_set_once(gov, models):
    ref_id = gov.add_reference(state="validated", generation=1, validated_generation=1)
    with session_for(gov) as session:
        row = session.get(models.CredentialReference, ref_id)
        row.approved_by = APPROVER  # unset -> set is the approval
        session.commit()
    for new in (30, None):
        with session_for(gov) as session:
            row = session.get(models.CredentialReference, ref_id)
            row.approved_by = new
            with pytest.raises(models.ImmutableFieldChanged):
                session.flush()
            session.rollback()
    assert gov.reference(1, ref_id).approved_by == APPROVER


# --- real concurrency (PostgreSQL only) ----------------------------------------------------------------------------------------

@pytest.mark.skipif(not os.environ.get("ELITEA_TEST_PG_DSN"), reason="needs ELITEA_TEST_PG_DSN: row locks, not SQLite")
def test_concurrent_importers_and_committers_have_exactly_one_winner(gov, st):
    ref_id = gov.add_reference()

    def race(operation):
        def attempt(_):
            with session_for(gov) as session:
                done = operation(session)
                session.commit()
                return done
        with ThreadPoolExecutor(max_workers=8) as pool:
            return sum(pool.map(attempt, range(8)))

    assert race(lambda session: st.claim_generation(session, ref_id, 1)) == 1
    assert race(lambda session: st.commit_generation(session, ref_id, 1, 4)) == 1
    row = gov.reference(1, ref_id)
    assert (row.generation, row.pending_generation) == (1, None)
