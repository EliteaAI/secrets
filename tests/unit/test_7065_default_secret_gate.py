"""Issue #7065 - the ignore_default_secret_api gate no longer has an X-SECRET bypass.

When elitea_core's `ignore_default_secret_api` flag is on, the secrets API refuses the
platform-managed keys listed in `default_secret_keys`. A request carrying the matching
`X-SECRET` header used to be exempt. That header defaulted to a public value and is gone
in #7065, so the flag now applies to every caller. The flag is unset (off) on local, dev
and next, so the practical behaviour there is unchanged.

Covered: secret GET/PUT/DELETE, secrets list/POST, hide POST, each with the flag on and
off, with and without the legacy header.

Run via:
    python tests/run_tests.py unit/test_7065_default_secret_gate.py -v
"""
import sys
import types
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.api_loader import load_api_module  # noqa: E402  pylint: disable=C0413
from run_tests import StubVaultClient  # noqa: E402  pylint: disable=C0413

secret_api = load_api_module("secret")
secrets_api = load_api_module("secrets")
hide_api = load_api_module("hide")

PROJECT = 5
LEGACY_HEADERS = {'X-SECRET': 'secret'}

app = Flask(__name__)


@pytest.fixture(autouse=True)
def _reset_stubs():
    StubVaultClient.projects = {PROJECT: {
        'secrets': {'project_llm_key': 'platform-value', 'MY_TOKEN': 'user-value',
                    'secrets_header_value': 'secret'},
        'external_access': {},
    }}
    StubVaultClient.opened = []
    yield


def _flag(on):
    from tools import this  # pylint: disable=import-outside-toplevel
    this.modules['elitea_core'] = types.SimpleNamespace(descriptor=types.SimpleNamespace(config={
        'default_secret_keys': ['project_llm_key'],
        'ignore_default_secret_api': on,
    }))


def _resource():
    return types.SimpleNamespace(module=None)


def _call(api, method, *args, headers=None, json=None):
    with app.test_request_context(headers=headers or {}, json=json):
        return getattr(api.ProjectAPI(api=_resource()), method)(PROJECT, *args)


@pytest.mark.parametrize('headers', [None, LEGACY_HEADERS])
def test_reading_a_default_key_is_refused_when_the_flag_is_on(headers):
    _flag(True)

    _body, status = _call(secret_api, 'get', 'project_llm_key', headers=headers)

    assert status == 400


@pytest.mark.parametrize('headers', [None, LEGACY_HEADERS])
def test_updating_a_default_key_is_refused_when_the_flag_is_on(headers):
    _flag(True)

    _body, status = _call(secret_api, 'put', 'project_llm_key', headers=headers, json={'value': 'x'})

    assert status == 400
    assert StubVaultClient.projects[PROJECT]['secrets']['project_llm_key'] == 'platform-value'


@pytest.mark.parametrize('headers', [None, LEGACY_HEADERS])
def test_deleting_a_default_key_is_refused_when_the_flag_is_on(headers):
    _flag(True)

    _body, status = _call(secret_api, 'delete', 'project_llm_key', headers=headers)

    assert status == 400
    assert 'project_llm_key' in StubVaultClient.projects[PROJECT]['secrets']


@pytest.mark.parametrize('headers', [None, LEGACY_HEADERS])
def test_the_list_hides_default_keys_when_the_flag_is_on(headers):
    _flag(True)

    body, status = _call(secrets_api, 'get', headers=headers)

    assert status == 200
    assert 'project_llm_key' not in [s['name'] for s in body]


@pytest.mark.parametrize('headers', [None, LEGACY_HEADERS])
def test_creating_a_default_key_is_refused_when_the_flag_is_on(headers):
    _flag(True)

    _body, status = _call(secrets_api, 'post', headers=headers,
                          json={'name': 'project_llm_key', 'value': 'x'})

    assert status == 400


@pytest.mark.parametrize('headers', [None, LEGACY_HEADERS])
def test_hiding_a_default_key_is_refused_when_the_flag_is_on(headers):
    _flag(True)

    _body, status = _call(hide_api, 'post', 'project_llm_key', headers=headers)

    assert status == 400


def test_default_keys_are_readable_when_the_flag_is_off():
    _flag(False)

    body, status = _call(secret_api, 'get', 'project_llm_key')

    assert status == 200
    assert body['value'] == 'platform-value'


def test_ordinary_keys_are_unaffected_by_the_flag():
    _flag(True)

    body, status = _call(secret_api, 'get', 'MY_TOKEN')

    assert status == 200


def test_the_vault_is_not_read_for_a_header_value():
    # The handlers used to call get_all_secrets() only to compare the header
    calls = []
    original = StubVaultClient.get_all_secrets
    StubVaultClient.get_all_secrets = lambda self: calls.append(1) or original(self)
    try:
        _flag(True)
        _call(secret_api, 'get', 'MY_TOKEN', headers=LEGACY_HEADERS)
        _call(secrets_api, 'get', headers=LEGACY_HEADERS)
    finally:
        StubVaultClient.get_all_secrets = original

    assert calls == []
