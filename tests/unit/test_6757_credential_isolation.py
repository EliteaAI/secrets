"""C-1009 (#6757): credential material stays out of reach of everything that is not the onboarding services.

What this plugin can prove: the existing reveal routes (project secret GET/PUT/DELETE/list/hide and the private
project secret) neither return nor touch a ``credential_store`` section, no code outside the three custody
modules mentions the store or the engine, and the store context can only be minted by the onboarding and
reconcile services. What belongs to other plugins' suites: that ``VaultClient.unsecret("{{secret.<ref>:1}}")``
does not resolve the section (``shared`` tests/unit/test_secret_stores_database.py: template resolution merges
``secrets`` and ``hidden_secrets`` only) and that ``worker_client`` ``unsecret_data`` /
``restricted_get_admin_secret`` cannot return it (the ``worker_client`` suite; that bridge delegates to the same
VaultClient and is allow-listed by key).
"""
import ast
import copy
import json
import sys
import types
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.api_loader import load_api_module  # noqa: E402  pylint: disable=C0413
from run_tests import StubAuth, StubLog, StubModule, StubVaultClient, _RpcCalls  # noqa: E402  pylint: disable=C0413

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
PROJECT, PERSONAL, USER = 5, 105, 11
STORE_KEY = f"{'ab' * 16}:1"
FIXTURE = "fixture-credential-material"  # fake, test only

secret_api = load_api_module("secret")
secrets_api = load_api_module("secrets")
hide_api = load_api_module("hide")
private_api = load_api_module("private_secret")
app = Flask(__name__)


def project_data():
    return {
        "secrets": {"TOKEN": "shared-project-value"}, "hidden_secrets": {"HIDDEN": "hidden-value"},
        "external_access": {"TOKEN": True},
        "credential_store": {STORE_KEY: {"api_key": FIXTURE}},
    }


@pytest.fixture(autouse=True)
def _stubs():
    from tools import this  # pylint: disable=C0415
    saved = dict(this.modules)
    StubVaultClient.projects = {PROJECT: project_data(), PERSONAL: project_data()}
    StubVaultClient.opened = []
    StubAuth.user = {"id": USER}
    StubLog.records = []
    _RpcCalls.personal_projects = {USER: PERSONAL}
    this.modules["elitea_core"] = types.SimpleNamespace(descriptor=types.SimpleNamespace(config={}))
    yield
    this.modules.clear()
    this.modules.update(saved)


def call(api, method, *args, json_body=None, project_id=PROJECT):
    with app.test_request_context(json=json_body):
        handler = api.ProjectAPI(api=types.SimpleNamespace(module=StubModule()))
        return getattr(handler, method)(project_id, *args)


def test_no_reveal_route_returns_or_changes_the_credential_store_section():
    original = copy.deepcopy(StubVaultClient.projects[PROJECT]["credential_store"])
    answers = [
        call(secret_api, "get", STORE_KEY),
        call(secret_api, "put", STORE_KEY, json_body={"value": "overwritten"}),
        call(secret_api, "delete", STORE_KEY),
        call(secrets_api, "get"),
        call(secrets_api, "post", json_body={"name": STORE_KEY, "value": "created"}),
        call(hide_api, "post", STORE_KEY),
        call(private_api, "get", "api_key"),
        call(private_api, "get", STORE_KEY.replace(":", "_")),
    ]
    assert FIXTURE not in json.dumps([body for body, _ in answers], default=str)
    for project in (PROJECT, PERSONAL):
        assert StubVaultClient.projects[project]["credential_store"] == original
    assert [status for _, status in answers[:3]] == [404, 400, 204]
    assert [item["name"] for item in answers[3][0]] == ["TOKEN"]


def test_the_secret_list_and_lookups_know_only_the_project_secret_sections():
    body, status = call(secrets_api, "get")
    assert status == 200 and STORE_KEY not in json.dumps(body) and FIXTURE not in json.dumps(body)
    for name in ("api_key", STORE_KEY, "credential_store", "credential_store." + STORE_KEY):
        _, status = call(secret_api, "get", name)
        assert status == 404, name


def python_files():
    for path in sorted(PLUGIN_ROOT.rglob("*.py")):
        relative = path.relative_to(PLUGIN_ROOT)
        if relative.parts[0] in ("tests", "wt") or ".git" in relative.parts:
            continue
        yield relative, ast.parse(path.read_text(encoding="utf-8"))


def names_used(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                yield alias.name.split(".")[-1]
            if isinstance(node, ast.ImportFrom) and node.module:
                yield from node.module.split(".")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def test_the_existing_api_layers_never_mention_the_store_or_the_engine():
    forbidden = {"credential_store", "secret_stores", "CredentialStoreProvider", "_update_section", "secret_engines",
                 "get_store"}
    checked = 0
    for relative, tree in python_files():
        if relative.parts[0] in ("api", "rpc", "slots", "pd"):
            checked += 1
            assert not forbidden & set(names_used(tree)), relative
    assert checked >= 8


CUSTODY_MODULES = ("utils/credential_onboarding.py", "utils/credential_reconcile.py", "utils/credential_release.py",
                   "utils/credential_offline_material.py")   # a mandate owner's offline consent (#7131)


def mint_users(tree):
    return [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr == "mint"]


def test_only_the_custody_services_mint_store_contexts():
    seen = {}
    for relative, tree in python_files():
        if mint_users(tree) or "CredentialStoreProvider" in set(names_used(tree)):
            seen[relative.as_posix()] = len(mint_users(tree))
    assert set(seen) == set(CUSTODY_MODULES), seen


def test_the_mint_lint_catches_a_stray_caller():
    stray = ast.parse("from tools import secret_stores\nctx = secret_stores.CredentialStoreProvider.mint('probe')")
    assert mint_users(stray) and "CredentialStoreProvider" in set(names_used(stray))


STORE_CALLS = {  # store method -> the only modules that may call it
    "write": {"utils/credential_onboarding.py", "utils/credential_offline_material.py"},
    "read": {"utils/credential_onboarding.py", "utils/credential_release.py", "utils/credential_offline_material.py"},
    "metadata": {"utils/credential_onboarding.py", "utils/credential_reconcile.py"},
    "delete_all": {"utils/credential_onboarding.py", "utils/credential_reconcile.py",
                   "utils/credential_offline_material.py"},
    "smoke": {"utils/credential_reconcile.py"},
}


def test_store_operations_are_called_only_from_the_services_that_own_them():
    for relative, tree in python_files():
        used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        for operation, owners in STORE_CALLS.items():
            if operation in used and relative.as_posix().startswith("utils/credential_"):
                assert relative.as_posix() in owners, (relative, operation)


def test_the_custody_code_does_not_reach_the_engines_or_a_vault_client_directly():
    forbidden = {"VaultClient", "secret_engines", "hvac", "requests", "Fernet", "unsecret", "get_secrets",
                 "get_all_secrets", "get_project_hidden_secrets", "_read", "_update_section"}
    for relative, tree in python_files():
        if relative.as_posix().startswith(("utils/credential_", "models/credential_", "methods/")):
            assert not forbidden & set(names_used(tree)), relative


def test_a_store_context_cannot_be_built_by_hand(gov):
    stores = gov.stores
    with pytest.raises(TypeError):
        stores.AuthorizedStoreContext(purpose="onboard", decision_id="x", actor_ref="a", project_id=1, ref_id="r")
    with pytest.raises(ValueError):
        stores.CredentialStoreProvider.mint("unlisted", decision_id="x", actor_ref="a", project_id=1,
                                            ref_id=__import__("uuid").uuid4())
