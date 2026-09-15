#!/usr/bin/env python3
"""
Test runner that installs Pylon stubs before pytest.

Usage:
    python tests/run_tests.py [pytest args...]
"""
import sys
import types
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


class StubLog:
    """Collects log calls so tests can assert on audit lines."""

    records = []

    @classmethod
    def _record(cls, message, *args, **kwargs):
        _ = kwargs
        cls.records.append(message % args if args else message)

    info = _record
    debug = _record
    warning = _record
    error = _record
    exception = _record
    critical = _record


class StubVaultClient:
    """Per-project vault stand-in. Tests populate `projects` keyed by project id."""

    projects = {}
    opened = []

    def __init__(self, project_id=None):
        self.project_id = project_id

    @classmethod
    def from_project(cls, project_id):
        cls.opened.append(int(project_id))
        return cls(int(project_id))

    def _data(self):
        return self.projects.setdefault(self.project_id, {})

    def get_secrets(self):
        return dict(self._data().get('secrets', {}))

    def get_project_hidden_secrets(self):
        return dict(self._data().get('hidden_secrets', {}))

    def get_all_secrets(self):
        data = self._data()
        return {**data.get('hidden_secrets', {}), **data.get('secrets', {})}

    def get_external_access(self):
        return dict(self._data().get('external_access', {}))

    def set_secrets(self, secrets):
        self._data()['secrets'] = dict(secrets)

    def set_hidden_secrets(self, secrets):
        self._data()['hidden_secrets'] = dict(secrets)

    def set_external_access(self, flags):
        self._data()['external_access'] = dict(flags)

    def update_external_access(self, add=None, remove=None):
        flags = self.get_external_access()
        flags.update(add or {})
        for name in (remove or ()):
            flags.pop(name, None)
        self.set_external_access(flags)
        return flags


class StubAuth:
    """Auth stand-in; tests set `user` and `sessions`."""

    user = {}
    sessions = {}

    class decorators:  # pylint: disable=invalid-name,too-few-public-methods
        # qualname -> the descriptor the endpoint passed to check_api. The real decorator
        # lives in pylon and cannot run here, so recording what each handler *declares* is
        # what lets a test catch a dropped decorator or a widened permission.
        requirements = {}

        @staticmethod
        def check_api(descriptor=None, *a, **kw):  # pylint: disable=keyword-arg-before-vararg
            _ = a, kw

            def decorate(func):
                StubAuth.decorators.requirements[func.__qualname__] = descriptor
                return func

            return decorate

    @classmethod
    def current_user(cls):
        return dict(cls.user)

    @classmethod
    def get_referenced_auth_context(cls, reference):
        return cls.sessions.get(reference)


class StubModule:
    """Stands in for the API resource's `.module`, exposing the RPC manager."""

    def __init__(self):
        self.context = types.SimpleNamespace(rpc_manager=types.SimpleNamespace(call=_RpcCalls()))


class _RpcCalls:
    """Tests set `personal_projects` to map user_id -> personal project id."""

    personal_projects = {}

    def projects_get_personal_project_id(self, user_id):
        return self.personal_projects.get(user_id)


def install_stubs():
    """Install minimal stubs to prevent ImportError on pylon/tools imports."""
    pylon_stub = types.ModuleType('pylon')
    pylon_core = types.ModuleType('pylon.core')
    pylon_core_tools = types.ModuleType('pylon.core.tools')
    pylon_core_tools.log = StubLog
    pylon_core_tools.module = types.ModuleType('pylon.core.tools.module')
    pylon_core_tools.web = types.ModuleType('pylon.core.tools.web')
    pylon_core_tools.web.rpc = lambda *a, **kw: (lambda func: func)

    sys.modules.setdefault('pylon', pylon_stub)
    sys.modules.setdefault('pylon.core', pylon_core)
    sys.modules.setdefault('pylon.core.tools', pylon_core_tools)
    sys.modules.setdefault('pylon.core.tools.log', pylon_core_tools.log)
    sys.modules.setdefault('pylon.core.tools.module', pylon_core_tools.module)
    sys.modules.setdefault('pylon.core.tools.web', pylon_core_tools.web)

    api_tools = types.ModuleType('tools.api_tools')

    class APIModeHandler:  # pylint: disable=too-few-public-methods
        def __init__(self, api=None, mode='default'):
            self._api = api
            self.mode = mode

        def __getattr__(self, item):
            try:
                return self.__dict__[item]
            except KeyError:
                return getattr(self._api, item)

    class APIBase:  # pylint: disable=too-few-public-methods
        ...

    api_tools.APIModeHandler = APIModeHandler
    api_tools.APIBase = APIBase
    api_tools.with_modes = lambda params: list(params)

    config_stub = types.ModuleType('tools.config')
    config_stub.DEFAULT_MODE = 'default'
    config_stub.ADMINISTRATION_MODE = 'administration'

    this_stub = types.ModuleType('tools.this')
    this_stub.modules = {}
    this_stub.for_module = lambda name: this_stub.modules[name]

    tools_stub = types.ModuleType('tools')
    tools_stub.api_tools = api_tools
    tools_stub.config = config_stub
    tools_stub.this = this_stub
    tools_stub.auth = StubAuth
    tools_stub.VaultClient = StubVaultClient
    tools_stub.register_openapi = lambda *a, **kw: (lambda func: func)

    sys.modules.setdefault('tools', tools_stub)
    sys.modules.setdefault('tools.api_tools', api_tools)
    sys.modules.setdefault('tools.config', config_stub)

    # Deliberately NOT adding the plugins root to sys.path: this plugin's directory is named
    # `secrets`, which would shadow the stdlib module of the same name (werkzeug imports it).
    # Plugin files are loaded by path instead, see fixtures/api_loader.py.


def main():
    # conftest.py installs the stubs. Doing it here too would leave two copies of this
    # module (`__main__` and `run_tests`), and tests mutating the stubs would configure
    # the copy the handlers don't see.
    import pytest
    tests_dir = Path(__file__).parent
    sys.exit(pytest.main([str(tests_dir)] + sys.argv[1:]))


if __name__ == '__main__':
    main()
