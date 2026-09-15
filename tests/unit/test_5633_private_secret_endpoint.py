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
pd_secrets = sys.modules["secretsplugin.pd.secrets"]

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


# --- secret name validation -----------------------------------------------------


def test_an_encoded_newline_cannot_forge_an_audit_line():
    """`%250A` in the path decodes to a newline, which would read as a second record."""
    body, status = _get(secret='MISSING%0Aoutcome=granted user=999')

    assert (status, body) == (400, {'error': 'invalid_secret_name'})
    joined = ' '.join(StubLog.records)
    assert '\n' not in joined
    assert 'outcome=granted' not in joined


def test_a_trailing_newline_alone_is_refused():
    """`TOKEN%0A` carries no forged content, but `$` would still have let it through."""
    body, status = _get(secret='TOKEN\n')

    assert (status, body) == (400, {'error': 'invalid_secret_name'})
    assert '\n' not in ' '.join(StubLog.records)


def test_the_shared_charset_rejects_a_trailing_newline_at_creation_too():
    """Otherwise a name that splits audit lines could be stored in the first place."""
    with pytest.raises(ValueError):
        pd_secrets.SecretCreate(name='TOKEN\n')


def test_rejected_names_are_not_echoed_into_the_log():
    _get(secret='../../etc/passwd')

    assert not any('passwd' in record for record in StubLog.records)


@pytest.mark.parametrize('secret', [
    '', 'has space', 'has-dash', 'dot.dot', 'sub/path', 'quote"',
    'TOKEN\n', '\nTOKEN', 'TOKEN\r', 'TOKEN\n\n', 'TOKEN\nMORE',
])
def test_names_outside_the_creation_charset_are_refused(secret):
    body, status = _get(secret=secret)

    assert (status, body) == (400, {'error': 'invalid_secret_name'})


def test_validation_runs_before_the_caller_is_resolved():
    """An invalid name must not reach a vault or the personal-project lookup."""
    _get(secret='bad name')

    assert StubVaultClient.opened == []


@pytest.mark.parametrize('secret', ['TOKEN', 'my_token_2', 'ABC123', '_leading'])
def test_names_within_the_creation_charset_are_accepted(secret):
    StubVaultClient.projects[ALICE_PROJECT] = {
        'secrets': {secret: 'ok'}, 'external_access': {secret: True},
    }

    body, status = _get(secret=secret)

    assert (status, body['value']) == (200, 'ok')


# --- SDK-facing response contract -----------------------------------------------
#
# The SDK maps failures by reading the 'error' key, because status alone is ambiguous:
# no_personal_project and not_found are both 404. These pin the wire format so a rename
# on either side breaks here rather than in a code node.


def _no_personal_project():
    _RpcCalls.personal_projects = {}


def _not_shared():
    StubVaultClient.projects[ALICE_PROJECT]['external_access'] = {}


def _not_found():
    StubVaultClient.projects[ALICE_PROJECT] = {'secrets': {}, 'external_access': {'TOKEN': True}}


def _unidentified_caller():
    StubAuth.user = {}


def _default_secret():
    _elitea_core_config({'default_secret_keys': ['TOKEN'], 'ignore_default_secret_api': True})


def _invalid_secret_name():
    return {'secret': 'not valid'}


@pytest.mark.parametrize(('arrange', 'expected_status', 'expected_error'), [
    (_unidentified_caller, 401, 'unidentified_caller'),
    (_no_personal_project, 404, 'no_personal_project'),
    (_default_secret, 400, 'default_secret'),
    (_not_shared, 403, 'not_shared'),
    (_not_found, 404, 'not_found'),
    (_invalid_secret_name, 400, 'invalid_secret_name'),
])
def test_every_failure_reports_its_reason_under_the_error_key(
        arrange, expected_status, expected_error,
):
    kwargs = arrange() or {}

    body, status = _get(**kwargs)

    assert status == expected_status
    assert body == {'error': expected_error}


def test_the_two_404s_are_told_apart_by_the_body_not_the_status():
    _no_personal_project()
    no_project, no_project_status = _get()

    _RpcCalls.personal_projects = {ALICE_ID: ALICE_PROJECT}
    _not_found()
    missing, missing_status = _get()

    assert no_project_status == missing_status == 404
    assert no_project['error'] != missing['error']


def test_success_carries_no_error_key():
    body, _status = _get()

    assert 'error' not in body


# --- declared authorization -----------------------------------------------------
#
# check_api itself lives in pylon and cannot run in this harness, so these assert what
# the handlers declare. That turns a dropped decorator or a widened permission into a
# failure here; enforcement of the decorator itself belongs to pylon's own tests.


def test_reading_a_private_secret_requires_the_unsecret_permission():
    declared = StubAuth.decorators.requirements['ProjectAPI.get']

    assert declared['permissions'] == ['configuration.secrets.secret.unsecret']


def test_viewers_are_never_recommended_the_permission():
    roles = StubAuth.decorators.requirements['ProjectAPI.get']['recommended_roles']

    assert roles, 'both modes must state their recommended roles'
    assert all(mode['viewer'] is False for mode in roles.values())


def test_the_administration_mode_handler_is_guarded_too():
    assert StubAuth.decorators.requirements.get('AdminAPI.get') is not None
