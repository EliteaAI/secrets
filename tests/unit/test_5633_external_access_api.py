"""Unit tests for the allow_external_access flag on the secrets CRUD API (issue #5633).

The flag is what makes a personal secret readable by a shared-project code node, so a
value rotation must not silently change it, and deleting or renaming a secret must not
leave a flag behind that a recreated secret would inherit.
"""
import sys
import types
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.api_loader import load_api_module  # noqa: E402  pylint: disable=C0413
from run_tests import StubVaultClient  # noqa: E402  pylint: disable=C0413

secrets_api = load_api_module("secrets")
secret_api = load_api_module("secret")

PROJECT = 5

app = Flask(__name__)


@pytest.fixture(autouse=True)
def _reset_stubs():
    StubVaultClient.projects = {PROJECT: {'secrets': {}, 'external_access': {}}}
    StubVaultClient.opened = []
    from tools import this  # pylint: disable=import-outside-toplevel
    this.modules['elitea_core'] = types.SimpleNamespace(
        descriptor=types.SimpleNamespace(config={}),
    )
    yield


def _flags():
    return StubVaultClient.projects[PROJECT].get('external_access', {})


def _stored():
    return StubVaultClient.projects[PROJECT].get('secrets', {})


def _resource():
    return types.SimpleNamespace(module=None)


def _create(payload):
    with app.test_request_context(json=payload):
        return secrets_api.ProjectAPI(api=_resource()).post(PROJECT)


def _update(name, payload):
    with app.test_request_context(json=payload):
        return secret_api.ProjectAPI(api=_resource()).put(PROJECT, name)


def _delete(name):
    with app.test_request_context():
        return secret_api.ProjectAPI(api=_resource()).delete(PROJECT, name)


def _read(name):
    with app.test_request_context():
        return secret_api.ProjectAPI(api=_resource()).get(PROJECT, name)


def _list():
    with app.test_request_context():
        return secrets_api.ProjectAPI(api=_resource()).get(PROJECT)


# --- create ---------------------------------------------------------------------


def test_create_defaults_to_not_shared():
    _body, status = _create({'name': 'TOKEN', 'value': 'v'})

    assert status == 201
    assert _flags().get('TOKEN', False) is False


def test_create_can_opt_in():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': True})

    assert _flags()['TOKEN'] is True


def test_create_with_explicit_false_does_not_share():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': False})

    assert _flags().get('TOKEN', False) is False


# --- update ---------------------------------------------------------------------


def test_rotating_a_value_keeps_the_secret_shared():
    _create({'name': 'TOKEN', 'value': 'v1', 'allow_external_access': True})

    _update('TOKEN', {'value': 'v2'})

    assert _flags()['TOKEN'] is True
    assert _stored()['TOKEN'] == 'v2'


def test_rotating_a_value_keeps_an_unshared_secret_unshared():
    _create({'name': 'TOKEN', 'value': 'v1'})

    _update('TOKEN', {'value': 'v2'})

    assert _flags().get('TOKEN', False) is False


def test_update_can_share_an_existing_secret():
    _create({'name': 'TOKEN', 'value': 'v'})

    _update('TOKEN', {'value': 'v', 'allow_external_access': True})

    assert _flags()['TOKEN'] is True


def test_update_can_unshare():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': True})

    _update('TOKEN', {'value': 'v', 'allow_external_access': False})

    assert _flags().get('TOKEN', False) is False


def test_sharing_without_resending_the_value_keeps_it():
    """The UI flips the flag alone, so an omitted value must not blank the secret."""
    _create({'name': 'TOKEN', 'value': 'v'})

    _body, status = _update('TOKEN', {'allow_external_access': True})

    assert status == 200
    assert _stored()['TOKEN'] == 'v'
    assert _flags()['TOKEN'] is True


def test_unsharing_without_resending_the_value_keeps_it():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': True})

    _update('TOKEN', {'allow_external_access': False})

    assert _stored()['TOKEN'] == 'v'
    assert _flags().get('TOKEN', False) is False


def test_an_explicit_empty_value_still_clears_the_secret():
    _create({'name': 'TOKEN', 'value': 'v'})

    _update('TOKEN', {'value': ''})

    assert _stored()['TOKEN'] == ''


def test_update_of_a_missing_secret_leaves_flags_alone():
    _create({'name': 'OTHER', 'value': 'v', 'allow_external_access': True})

    _body, status = _update('TOKEN', {'value': 'v', 'allow_external_access': True})

    assert status == 400
    assert _flags() == {'OTHER': True}


# --- delete ---------------------------------------------------------------------


def test_delete_clears_the_flag_so_a_recreated_secret_is_not_shared():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': True})

    _delete('TOKEN')
    _create({'name': 'TOKEN', 'value': 'v'})

    assert _flags().get('TOKEN', False) is False


def test_delete_leaves_other_flags_intact():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': True})
    _create({'name': 'OTHER', 'value': 'v', 'allow_external_access': True})

    _delete('TOKEN')

    assert _flags() == {'OTHER': True}


# --- read ----------------------------------------------------------------------


def test_get_reports_the_flag():
    _create({'name': 'TOKEN', 'value': 'v', 'allow_external_access': True})

    body, status = _read('TOKEN')

    assert status == 200
    assert body['allow_external_access'] is True


def test_get_reports_absence_of_the_flag_as_false():
    _create({'name': 'TOKEN', 'value': 'v'})

    body, _status = _read('TOKEN')

    assert body['allow_external_access'] is False


def test_list_reports_the_flag_per_secret():
    _create({'name': 'SHARED', 'value': 'v', 'allow_external_access': True})
    _create({'name': 'PRIVATE', 'value': 'v'})

    body, status = _list()

    assert status == 200
    by_name = {item['name']: item['allow_external_access'] for item in body}
    assert by_name == {'SHARED': True, 'PRIVATE': False}
