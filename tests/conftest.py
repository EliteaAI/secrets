"""Pytest configuration - install stubs before any test module imports the API handlers."""
import pathlib
import sys

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))

from run_tests import install_stubs  # noqa: E402  pylint: disable=C0413

install_stubs()


@pytest.fixture(scope="session")
def plugin_root() -> pathlib.Path:
    """Absolute path to the secrets plugin root."""
    return TESTS_DIR.parent


@pytest.fixture
def gov(tmp_path):
    """Credential governance environment: real models and services over SQLite, fake collaborators."""
    from fixtures.governance import GOV  # pylint: disable=C0415
    GOV.install()
    GOV.reset(tmp_path)
    yield GOV
    GOV.restore()


def pytest_collection_modifyitems(items):
    for item in items:
        if '/unit/' in str(item.fspath):
            item.add_marker(pytest.mark.unit)
