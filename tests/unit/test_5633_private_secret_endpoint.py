"""Unit tests for the private-project secret resolver (issue #5633).

The endpoint lets a code node running in a shared project read a secret from the
*executing user's* personal project, so the tests focus on the security-relevant
properties: whose vault gets opened, in what order access is decided, and what the
response body and audit log are allowed to contain.
"""
import sys
import types
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.api_loader import load_api_module  # noqa: E402  pylint: disable=C0413
from run_tests import (  # noqa: E402  pylint: disable=C0413
    StubAuth, StubLog, StubModule, StubVaultClient, _RpcCalls,
)

private_secret = load_api_module("private_secret")

CALLING_PROJECT = 7
ALICE_ID = 11
BOB_ID = 22
ALICE_PROJECT = 101
BOB_PROJECT = 202

app = Flask(__name__)


@pytest.fixture(autouse=True)
def _reset_stubs():
    StubVaultClient.projects = {
        CALLING_PROJECT: {
            'secrets': {'TOKEN': 'shared-project-value', 'secrets_header_value': 'right-secret'},
        },
        ALICE_PROJECT: {
            'secrets': {'TOKEN': 'alice-value'},
            'external_access': {'TOKEN': True},
        },
        BOB_PROJECT: {
            'secrets': {'TOKEN': 'bob-value'},
            'external_access': {'TOKEN': True},
        },
    }
    StubVaultClient.opened = []
    StubAuth.user = {'id': ALICE_ID}
    StubAuth.sessions = {}
    StubLog.records = []
    _RpcCalls.personal_projects = {ALICE_ID: ALICE_PROJECT, BOB_ID: BOB_PROJECT}
    _elitea_core_config({})
    yield


def _elitea_core_config(config):
    from tools import this  # pylint: disable=import-outside-toplevel
    this.modules['elitea_core'] = types.SimpleNamespace(
        descriptor=types.SimpleNamespace(config=config),
    )


def _handler():
    return private_secret.ProjectAPI(api=types.SimpleNamespace(module=StubModule()))


def _get(secret='TOKEN', headers=None, project_id=CALLING_PROJECT):
    with app.test_request_context(headers=headers or {}):
        return _handler().get(project_id, secret)


# --- happy path -----------------------------------------------------------------


def test_returns_the_callers_own_value():
    body, status = _get()

    assert status == 200
    assert body['value'] == 'alice-value'


def test_reads_the_personal_project_not_the_calling_one():
    _get()

    assert ALICE_PROJECT in StubVaultClient.opened
    assert CALLING_PROJECT not in StubVaultClient.opened


def test_same_request_shape_resolves_per_user():
    alice_body, _ = _get()
    StubAuth.user = {'id': BOB_ID}
    bob_body, _ = _get()

    assert alice_body['value'] == 'alice-value'
    assert bob_body['value'] == 'bob-value'


def test_hidden_secrets_are_reachable_when_shared():
    StubVaultClient.projects[ALICE_PROJECT] = {
        'secrets': {},
        'hidden_secrets': {'TOKEN': 'alice-hidden'},
        'external_access': {'TOKEN': True},
    }

    body, status = _get()

    assert status == 200
    assert body['value'] == 'alice-hidden'
    assert body['is_hidden'] is True


def test_response_reports_the_flag_it_enforced():
    body, _ = _get()

    assert body['allow_external_access'] is True


# --- opt-in enforcement ---------------------------------------------------------


def test_unflagged_secret_is_refused_even_for_its_owner():
    StubVaultClient.projects[ALICE_PROJECT]['external_access'] = {}

    body, status = _get()

    assert status == 403
    assert body == {'error': 'not_shared'}


def test_flag_set_to_false_is_refused():
    StubVaultClient.projects[ALICE_PROJECT]['external_access'] = {'TOKEN': False}

    _body, status = _get()

    assert status == 403


def test_unknown_secret_is_indistinguishable_from_an_unshared_one():
    """The flag is checked before existence so the endpoint can't enumerate secrets."""
    unshared, unshared_status = _get(secret='TOKEN')
    StubVaultClient.projects[ALICE_PROJECT]['external_access'] = {}
    missing, missing_status = _get(secret='DOES_NOT_EXIST')

    assert unshared_status == 200  # sanity: TOKEN is shared in the fixture
    assert unshared['value'] == 'alice-value'
    assert (missing_status, missing) == (403, {'error': 'not_shared'})


def test_flagged_but_absent_secret_reports_not_found():
    StubVaultClient.projects[ALICE_PROJECT]['external_access'] = {'GONE': True}

    body, status = _get(secret='GONE')

    assert status == 404
    assert body == {'error': 'not_found'}


def test_no_fallback_to_a_same_named_shared_project_secret():
    StubVaultClient.projects[ALICE_PROJECT] = {'secrets': {}, 'external_access': {'TOKEN': True}}

    body, status = _get()

    assert status == 404
    assert 'shared-project-value' not in str(body)


# --- caller identification ------------------------------------------------------


def test_missing_personal_project_is_reported_distinctly():
    _RpcCalls.personal_projects = {}

    body, status = _get()

    assert status == 404
    assert body == {'error': 'no_personal_project'}


def test_acting_as_user_requires_a_valid_secret_header():
    StubAuth.sessions = {'session-ref': {'user_id': BOB_ID}}

    body, status = _get(headers={'X-USERSESSION': 'session-ref', 'X-SECRET': 'wrong'})

    assert status == 401
    assert body == {'error': 'unidentified_caller'}


def test_acting_as_user_with_a_valid_secret_header_resolves_that_user():
    StubAuth.user = {'id': ALICE_ID}
    StubAuth.sessions = {'session-ref': {'user_id': BOB_ID}}

    body, status = _get(headers={'X-USERSESSION': 'session-ref', 'X-SECRET': 'right-secret'})

    assert status == 200
    assert body['value'] == 'bob-value'


def test_unknown_session_reference_is_refused():
    _body, status = _get(headers={'X-USERSESSION': 'nope', 'X-SECRET': 'right-secret'})

    assert status == 401


def test_placeholder_session_falls_back_to_the_current_user():
    body, status = _get(headers={'X-USERSESSION': '-'})

    assert status == 200
    assert body['value'] == 'alice-value'


def test_anonymous_caller_is_refused():
    StubAuth.user = {}

    _body, status = _get()

    assert status == 401


# --- platform default secrets ---------------------------------------------------


def test_default_secret_keys_are_blocked_when_the_platform_disables_them():
    _elitea_core_config({
        'default_secret_keys': ['TOKEN'],
        'ignore_default_secret_api': True,
    })

    body, status = _get()

    assert status == 400
    assert body == {'error': 'default_secret'}


def test_a_valid_secret_header_does_not_lift_the_default_secret_guard():
    _elitea_core_config({
        'default_secret_keys': ['TOKEN'],
        'ignore_default_secret_api': True,
    })
    StubAuth.sessions = {'session-ref': {'user_id': BOB_ID}}

    _body, status = _get(headers={'X-USERSESSION': 'session-ref', 'X-SECRET': 'right-secret'})

    assert status == 400


def test_default_secret_keys_pass_through_when_the_platform_allows_them():
    _elitea_core_config({'default_secret_keys': ['TOKEN'], 'ignore_default_secret_api': False})

    _body, status = _get()

    assert status == 200


# --- audit log ------------------------------------------------------------------


def test_audit_log_records_the_grant_without_the_value():
    _get()

    joined = ' '.join(StubLog.records)
    assert str(ALICE_ID) in joined
    assert 'alice-value' not in joined


def test_audit_log_records_the_refusal_reason():
    StubVaultClient.projects[ALICE_PROJECT]['external_access'] = {}

    _get()

    assert any('not_shared' in record for record in StubLog.records)
