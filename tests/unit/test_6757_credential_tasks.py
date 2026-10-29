"""C-1009 (#6757): the schema guard, the admin tasks and how the module wires them (R-2.0.8)."""
import contextlib
import json
import types
import uuid
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa

from fixtures.governance import FIXTURE_VALUE
from fixtures.permissions import effective_roles
from run_tests import StubAuth, StubLog

TABLES = ["credential_reference", "credential_use_grant", "credential_store_ledger", "credential_offline_material"]
USAGE = "project_id= is required. Format: project_id=<all|N>[;dry_run]"
TASKS = ["create_credential_governance_tables", "manage_credential_reference", "manage_credential_grant",
         "reconcile_credential_store", "credential_store_smoke"]
PROJECTS = [{"id": 1}, {"id": 2}, {"id": 5}]


@pytest.fixture
def schema(gov):
    return gov.module("utils.credential_schema")


@pytest.fixture
def tasks(gov):
    return gov.module("methods.admin_tasks").Method


class Session:
    def __init__(self, pid, log, rows=()):
        self.pid, self.log, self.rows = pid, log, rows

    def connection(self):
        return f"connection-{self.pid}"

    def commit(self):
        self.log.append(("commit", self.pid))

    def execute(self, statement, params=None):
        self.log.append(("execute", str(statement), params))
        return types.SimpleNamespace(fetchall=lambda: list(self.rows))


def use_sessions(gov, monkeypatch, log, rows=(), fail_open=()):
    @contextlib.contextmanager
    def get_session(pid=None):
        if pid in fail_open:
            raise RuntimeError("no connection")
        yield Session(pid, log, rows)
    monkeypatch.setattr(gov.tools.db, "get_session", get_session)


def record_creates(monkeypatch, log, fail_for=()):
    def create(self, bind, checkfirst=False):
        pid = int(bind.rsplit("-", 1)[1])
        if pid in fail_for:
            raise RuntimeError("boom")
        log.append(("create", pid, self.name, checkfirst))
    monkeypatch.setattr(sa.Table, "create", create)


# --- schema helpers ---------------------------------------------------------------------------------------------------

def test_the_governance_tables_are_created_per_project_in_one_transaction_and_only_if_missing(gov, schema, monkeypatch):
    log = []
    use_sessions(gov, monkeypatch, log)
    record_creates(monkeypatch, log)
    assert schema.apply_credential_tables([4, 9]) == ([4, 9], [])
    assert log == [
        *[("create", 4, name, True) for name in TABLES], ("commit", 4),
        *[("create", 9, name, True) for name in TABLES], ("commit", 9)]


def test_dry_run_reports_without_touching_the_database(gov, schema, monkeypatch):
    log = []
    use_sessions(gov, monkeypatch, log)
    record_creates(monkeypatch, log)
    assert schema.apply_credential_tables([4, 9], dry_run=True) == ([4, 9], [])
    assert log == []


def test_one_broken_project_does_not_stop_the_others(gov, schema, monkeypatch):
    log = []
    use_sessions(gov, monkeypatch, log)
    record_creates(monkeypatch, log, fail_for={2})
    migrated, failed = schema.apply_credential_tables([1, 2, 3])
    assert migrated == [1, 3] and failed == [{"project_id": 2}]
    assert ("commit", 2) not in log and ("commit", 1) in log and ("commit", 3) in log


def test_a_session_that_cannot_open_fails_that_project_only(gov, schema, monkeypatch):
    log = []
    use_sessions(gov, monkeypatch, log, fail_open={1})
    record_creates(monkeypatch, log)
    assert schema.apply_credential_tables([1, 2]) == ([2], [{"project_id": 1}])


def test_the_guard_asks_the_catalog_once_and_decodes_project_ids(gov, schema, monkeypatch):
    log = []
    use_sessions(gov, monkeypatch, log, rows=[("p_3",), ("p_12",)])
    assert schema.project_ids_missing_credential_tables() == [3, 12]
    (entry,) = [e for e in log if e[0] == "execute"]
    _, sql, params = entry
    assert "information_schema.tables" in sql and "p_[0-9]+" in sql and "'configuration'" in sql
    assert params == {"names": TABLES, "expected": 4}


def test_nothing_to_do_means_no_ddl_at_boot(gov, schema, monkeypatch):
    log = []
    use_sessions(gov, monkeypatch, log, rows=[])
    record_creates(monkeypatch, log)
    assert schema.project_ids_missing_credential_tables() == []
    assert not [e for e in log if e[0] == "create"]


@pytest.mark.parametrize("param, expected", [
    ("project_id=all", (None, False, None)), ("project_id=all;dry_run", (None, True, None)),
    ("dry_run;project_id=7", (7, True, None)), (" PROJECT_ID=7 ; DRY_RUN ", (7, True, None)),
    ("project_id=x", (None, False, "invalid project_id: 'x'")), ("project_id=0", (None, False, "invalid project_id: '0'")),
    ("project_id=-2", (None, False, "invalid project_id: '-2'")),
    ("", (None, False, USAGE)), (None, (None, False, USAGE)), ("dry_run", (None, False, USAGE)),
])
def test_project_parameter_parsing(schema, param, expected):
    assert schema.parse_project_param(param) == expected


# --- the create-tables task ---------------------------------------------------------------------------------------------------

class Module:
    """The task's ``self``: projects come from the platform's project listing."""

    def __init__(self, projects=PROJECTS, fail=False):
        calls = types.SimpleNamespace(project_list=self._project_list)
        self.context = types.SimpleNamespace(rpc_manager=types.SimpleNamespace(call=calls))
        self.projects, self.fail, self.listed = projects, fail, []

    def _project_list(self, filter_=None):
        self.listed.append(filter_)
        if self.fail:
            raise RuntimeError("rpc down")
        return self.projects


@pytest.fixture
def patch_schema(gov, schema, monkeypatch):
    state = types.SimpleNamespace(missing=[1, 2, 5], applied=[], no_subject_column=[], column_applied=[])

    def apply(ids, dry_run=False):
        state.applied.append((list(ids), dry_run))
        return list(ids), []

    def apply_column(ids, dry_run=False):
        state.column_applied.append((list(ids), dry_run))
        return list(ids), []
    monkeypatch.setattr(schema, "project_ids_missing_credential_tables", lambda: list(state.missing))
    monkeypatch.setattr(schema, "apply_credential_tables", apply)
    monkeypatch.setattr(schema, "project_ids_missing_grant_subject_user_id", lambda: list(state.no_subject_column))
    monkeypatch.setattr(schema, "apply_grant_subject_user_id", apply_column)
    return state


def test_the_task_creates_the_missing_tables_everywhere(tasks, patch_schema):
    module = Module()
    result = tasks.create_credential_governance_tables(module, param="project_id=all")
    assert result == {"migrated": 3, "failed": 0, "failed_projects": [], "dry_run": False,
                      "personal_index": {"migrated": 0, "failed": 0, "failed_projects": []},
                      "grant_subject_user_id": {"migrated": 0, "failed": 0, "failed_projects": []}}
    assert patch_schema.applied == [([1, 2, 5], False)] and module.listed == [{"create_success": True}]


def test_the_task_adds_the_grant_subject_column_in_the_targeted_projects_only(tasks, patch_schema):
    patch_schema.missing = []
    patch_schema.no_subject_column = [1, 2, 9]
    result = tasks.create_credential_governance_tables(Module(), param="project_id=all")
    assert result["grant_subject_user_id"] == {"migrated": 2, "failed": 0, "failed_projects": []}
    assert patch_schema.column_applied == [([1, 2], False)]   # project 9 is not in the project list
    dry = tasks.create_credential_governance_tables(Module(), param="project_id=1;dry_run")
    assert dry["grant_subject_user_id"]["migrated"] == 1 and patch_schema.column_applied[-1] == ([1], True)


def test_the_task_dry_run_reports_what_it_would_create(tasks, patch_schema):
    result = tasks.create_credential_governance_tables(Module(), param="project_id=all;dry_run")
    assert result["migrated"] == 3 and result["dry_run"] is True and patch_schema.applied == [([1, 2, 5], True)]


def test_the_task_skips_projects_that_already_have_the_tables(tasks, patch_schema):
    patch_schema.missing = [2]
    assert tasks.create_credential_governance_tables(Module(), param="project_id=all")["migrated"] == 1
    assert patch_schema.applied == [([2], False)]


def test_the_task_for_one_project_does_not_list_projects(tasks, patch_schema):
    module = Module()
    result = tasks.create_credential_governance_tables(module, param="project_id=5")
    assert result["migrated"] == 1 and module.listed == [] and patch_schema.applied == [([5], False)]


@pytest.mark.parametrize("param, error", [("", USAGE), ("dry_run", USAGE), ("project_id=x", "invalid project_id: 'x'")])
def test_the_task_refuses_a_bad_parameter(tasks, patch_schema, param, error):
    assert tasks.create_credential_governance_tables(Module(), param=param) == {"migrated": 0, "error": error}
    assert patch_schema.applied == []


def test_the_task_reports_a_failed_project_listing(tasks, patch_schema):
    result = tasks.create_credential_governance_tables(Module(fail=True), param="project_id=all")
    assert result == {"migrated": 0, "error": "failed to list projects"}


# --- the operator tasks pass the executing user and keep results clean ------------------------------------------------------------

def test_the_reference_task_uses_the_executing_user_as_the_actor(gov, tasks):
    config = gov.configurations.add(3)
    param = f"project_id=3;action=create;configuration_uuid={config.uuid};store_kind=database;ownership_class=service"
    result = tasks.manage_credential_reference(Module(), param=param, _executing_user_id=42)
    assert gov.reference(3, uuid.UUID(result["reference"])).created_by == 42
    assert tasks.manage_credential_reference(Module(), param=param)["code"] == "ACTOR_REQUIRED"
    assert tasks.manage_credential_reference(Module(), param=param, _executing_user_id=None)["code"] == "ACTOR_REQUIRED"


def test_the_grant_task_uses_the_executing_user_as_the_actor(gov, tasks):
    param = (f"project_id=3;action=create;binding_ref={uuid.uuid4()};toolkit_id=1;ref={uuid.uuid4()};"
             "subject_ref=idp:t:u")
    assert tasks.manage_credential_grant(Module(), param=param, _executing_user_id=42)["code"] == "REFERENCE_NOT_FOUND"
    assert tasks.manage_credential_grant(Module(), param=param)["code"] == "ACTOR_REQUIRED"


def test_the_reconcile_and_smoke_tasks_use_the_executing_user(gov, tasks, monkeypatch):
    reconciler = gov.module("utils.credential_reconcile")
    monkeypatch.setattr(reconciler, "project_ids_missing_credential_tables", lambda: [])
    assert tasks.reconcile_credential_store(Module([]), param="project_id=all", _executing_user_id=42)["failed"] == 0
    assert tasks.reconcile_credential_store(Module([]), param="project_id=all")["code"] == "ACTOR_REQUIRED"
    assert tasks.credential_store_smoke(Module(), param="store_kind=corporate_vault", _executing_user_id=42)["passed"]
    assert tasks.credential_store_smoke(Module(), param="store_kind=corporate_vault")["code"] == "ACTOR_REQUIRED"


def test_a_full_task_run_logs_and_returns_no_material(gov, tasks):
    StubLog.records.clear()
    config = gov.configurations.add(3)
    module = Module()
    created = tasks.manage_credential_reference(
        module, _executing_user_id=10,
        param=f"project_id=3;action=create;configuration_uuid={config.uuid};store_kind=database;ownership_class=service")
    ref = created["reference"]
    outputs = [created, tasks.manage_credential_reference(module, param=f"project_id=3;action=import;ref={ref}",
                                                          _executing_user_id=10),
               tasks.manage_credential_reference(module, param=f"project_id=3;action=probe;ref={ref}",
                                                 _executing_user_id=10)]
    assert [o.get("state") for o in outputs] == ["pending", "pending", "validated"]
    blob = json.dumps(outputs) + "\n".join(StubLog.records) + json.dumps(gov.db.events(3))
    assert FIXTURE_VALUE not in blob and "section" not in blob and "locator" not in blob


def test_every_task_documents_its_parameter_format(tasks):
    for name in TASKS:
        doc = getattr(tasks, name).__doc__
        assert "R-2.0.8" in doc and "Param format" in doc, name


# --- the module -----------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def plugin(gov, monkeypatch):
    registered = []
    monkeypatch.setattr(StubAuth, "register_permissions", staticmethod(registered.append), raising=False)
    module_file = gov.module("module")
    descriptor = MagicMock()
    descriptor.metadata = {}
    instance = module_file.Module(context=MagicMock(), descriptor=descriptor)
    return types.SimpleNamespace(module=instance, descriptor=descriptor, registered=registered, file=module_file)


def test_init_loads_the_methods_and_registers_the_credential_permissions(plugin):
    plugin.module.init()
    plugin.descriptor.init_methods.assert_called_once_with()
    permissions = {entry["permissions"][0]: entry["recommended_roles"] for entry in plugin.registered
                   if entry["permissions"][0].startswith("credentials.")}
    assert sorted(permissions) == ["credentials.approve", "credentials.manage", "credentials.probe",
                                   "credentials.reveal", "credentials.set_own_value", "credentials.use", "credentials.view"]
    assert permissions["credentials.use"]["default"] == {"admin": True, "viewer": True, "editor": True}
    for name in ("credentials.manage", "credentials.probe", "credentials.approve"):
        # what the role model grants after its defaults: operators only, never the system role
        administration = effective_roles(permissions[name])["administration"]
        assert (administration["super_admin"], administration["admin"]) == (True, True)
        assert not (administration["editor"] or administration["viewer"] or administration["system"]), name
        default = effective_roles(permissions[name])["default"]
        assert (default["admin"], default["editor"], default["viewer"], default["system"]) == (True, False, False, False)
    assert not any(any(permissions["credentials.reveal"][mode].values()) for mode in ("default", "administration"))
    assert any(entry["permissions"] == ["configuration.secrets"] for entry in plugin.registered)  # untouched


def test_ready_registers_the_five_tasks_in_the_release_group_and_deinit_removes_them(gov, plugin, monkeypatch):
    monkeypatch.setattr(plugin.file, "Thread", lambda target, daemon: types.SimpleNamespace(start=lambda: None))
    plugin.module.ready()
    assert sorted(gov.admin.tasks) == sorted(TASKS)
    assert set(gov.admin.groups) == set(TASKS) and set(gov.admin.groups.values()) == {"R-2.0.8"}
    for name in TASKS:  # the wrapper keeps the docstring the admin UI shows
        assert gov.admin.tasks[name].__doc__ and gov.admin.tasks[name].__name__ == name
    plugin.module.deinit()
    assert gov.admin.tasks == {}
    plugin.module.deinit()  # and a second deinit is harmless


def test_a_registered_task_runs_the_method_on_the_module(gov, plugin, monkeypatch):
    monkeypatch.setattr(plugin.file, "Thread", lambda target, daemon: types.SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(plugin.module, "context", Module(), raising=False)
    plugin.module.ready()
    monkeypatch.setattr(gov.module("utils.credential_schema"), "project_ids_missing_credential_tables", lambda: [])
    monkeypatch.setattr(gov.module("utils.credential_schema"), "project_ids_missing_grant_subject_user_id", lambda: [])
    result = gov.admin.tasks["create_credential_governance_tables"](param="project_id=7;dry_run")
    assert result == {"migrated": 0, "failed": 0, "failed_projects": [], "dry_run": True,
                      "personal_index": {"migrated": 0, "failed": 0, "failed_projects": []},
                      "grant_subject_user_id": {"migrated": 0, "failed": 0, "failed_projects": []}}


def test_a_failing_registration_does_not_break_ready(gov, plugin, monkeypatch):
    monkeypatch.setattr(plugin.file, "Thread", lambda target, daemon: types.SimpleNamespace(start=lambda: None))
    del gov.this.modules["admin"]
    plugin.module.ready()  # logged, not raised
    assert gov.admin.tasks == {}


def run_guard(plugin, monkeypatch, gov, pending, apply=None, unwritten=(), ungranted=()):
    monkeypatch.setattr(plugin.file, "Thread", lambda target, daemon: types.SimpleNamespace(start=target))
    schema = gov.module("utils.credential_schema")
    applied = []
    plugin.written, plugin.granted = [], []
    monkeypatch.setattr(schema, "project_ids_missing_grant_subject_user_id", lambda: list(ungranted))
    monkeypatch.setattr(schema, "apply_grant_subject_user_id",
                        lambda ids: plugin.granted.append(list(ids)) or (ids, []))
    monkeypatch.setattr(schema, "project_ids_missing_written_by", lambda: list(unwritten))
    monkeypatch.setattr(schema, "apply_written_by", lambda ids: plugin.written.append(list(ids)) or (ids, []))
    monkeypatch.setattr(schema, "project_ids_missing_credential_tables",
                        pending if callable(pending) else (lambda: list(pending)))
    monkeypatch.setattr(schema, "apply_credential_tables", apply or (lambda ids: applied.append(list(ids)) or (ids, [])))
    plugin.module._ensure_credential_schema()  # pylint: disable=W0212
    return applied


def test_the_startup_guard_migrates_only_what_is_missing(gov, plugin, monkeypatch):
    assert run_guard(plugin, monkeypatch, gov, [3, 4]) == [[3, 4]]
    assert run_guard(plugin, monkeypatch, gov, []) == []  # steady state: no DDL


def test_a_failing_startup_guard_never_raises(gov, plugin, monkeypatch):
    def boom():
        raise RuntimeError("catalog down")
    assert run_guard(plugin, monkeypatch, gov, boom) == []


def test_the_startup_guard_adds_the_written_by_column_where_it_is_missing(gov, plugin, monkeypatch):
    assert run_guard(plugin, monkeypatch, gov, [], unwritten=[3, 9]) == [] and plugin.written == [[3, 9]]
    assert run_guard(plugin, monkeypatch, gov, [4], unwritten=[]) == [[4]] and plugin.written == []   # tables first
    assert run_guard(plugin, monkeypatch, gov, [], unwritten=[]) == [] and plugin.written == []        # steady state


def test_the_startup_guard_adds_the_grant_subject_column_where_it_is_missing(gov, plugin, monkeypatch):
    assert run_guard(plugin, monkeypatch, gov, [], ungranted=[3, 9]) == [] and plugin.granted == [[3, 9]]
    assert run_guard(plugin, monkeypatch, gov, [4], ungranted=[]) == [[4]] and plugin.granted == []   # tables first
    assert run_guard(plugin, monkeypatch, gov, [], ungranted=[]) == [] and plugin.granted == []        # steady state


def _grant_columns(gov, project_id):
    return {row["name"] for row in gov.db.execute(project_id, 'PRAGMA table_info("credential_use_grant")')}


def test_the_grant_subject_column_is_added_once_and_a_dry_run_changes_nothing(gov, schema):
    gov.db.execute(3, "ALTER TABLE tenant.credential_use_grant DROP COLUMN subject_user_id")
    assert "subject_user_id" not in _grant_columns(gov, 3)
    assert schema.apply_grant_subject_user_id([3], dry_run=True) == ([3], [])
    assert "subject_user_id" not in _grant_columns(gov, 3)
    assert schema.apply_grant_subject_user_id([3]) == ([3], [])
    assert "subject_user_id" in _grant_columns(gov, 3)
    assert schema.apply_grant_subject_user_id([3]) == ([3], [])   # idempotent
    row = gov.grant(3, gov.add_grant(3))
    assert row.subject_user_id is None   # additive and nullable: a grant made before it needs nothing


# --- the startup guard: independent steps, retried on a busy table, idempotent DDL (review of the perf PR) -----------

def test_a_project_that_hit_the_lock_timeout_is_tried_again_three_times_five_seconds_apart(schema):
    seen, slept = [], []

    def apply(ids):
        seen.append(list(ids))
        if len(seen) < 3:   # busy twice
            return [], [{"project_id": pid} for pid in ids]
        return list(ids), []
    migrated, failed = schema.apply_with_retry(apply, [3, 9], sleep=slept.append)
    assert (migrated, failed) == ([3, 9], []) and seen == [[3, 9], [3, 9], [3, 9]] and slept == [5, 5]

    def stuck(ids):
        seen.append(list(ids))
        return [], [{"project_id": pid} for pid in ids]
    seen.clear(), slept.clear()
    migrated, failed = schema.apply_with_retry(stuck, [4], sleep=slept.append)
    assert (migrated, failed) == ([], [{"project_id": 4}]) and len(seen) == 4 and slept == [5, 5, 5]   # 1 try + 3 retries


def test_only_the_failed_projects_are_retried(schema):
    seen = []

    def apply(ids):
        seen.append(list(ids))
        return ([pid for pid in ids if pid != 9], [{"project_id": 9}]) if len(seen) == 1 else (list(ids), [])
    assert schema.apply_with_retry(apply, [3, 9], sleep=lambda _s: None) == ([3, 9], []) and seen == [[3, 9], [9]]


def test_the_startup_guard_steps_do_not_stop_each_other(gov, plugin, monkeypatch):
    def boom():
        raise RuntimeError("catalog down")
    assert run_guard(plugin, monkeypatch, gov, boom, unwritten=[3], ungranted=[5]) == []
    assert plugin.written == [[3]] and plugin.granted == [[5]]   # the tables step failed; the two column steps ran


def test_the_startup_guard_retries_a_busy_project(gov, plugin, monkeypatch):
    schema = gov.module("utils.credential_schema")
    monkeypatch.setattr(schema.time, "sleep", lambda _s: None)
    run_guard(plugin, monkeypatch, gov, [], ungranted=[5])
    tries = []

    def busy_once(ids):
        tries.append(list(ids))
        return ([], [{"project_id": pid} for pid in ids]) if len(tries) == 1 else (list(ids), [])
    monkeypatch.setattr(schema, "apply_grant_subject_user_id", busy_once)
    plugin.module._ensure_credential_schema()   # pylint: disable=W0212
    assert tries == [[5], [5]]


def test_the_column_is_added_with_if_not_exists_on_postgresql(schema):
    class Preparer:
        @staticmethod
        def quote_schema(name):
            return f'"{name}"'

        @staticmethod
        def quote(name):
            return f'"{name}"'

    def run(dialect):
        sql = []
        connection = types.SimpleNamespace(
            dialect=types.SimpleNamespace(name=dialect, identifier_preparer=Preparer),
            schema_for_object=lambda _t: "p_1", execute=lambda statement: sql.append(str(statement)))
        schema._add_integer_column(connection, types.SimpleNamespace(name="credential_use_grant"), "subject_user_id", set())  # pylint: disable=W0212
        schema._add_integer_column(connection, types.SimpleNamespace(name="credential_use_grant"), "subject_user_id", {"subject_user_id"})  # pylint: disable=W0212
        return sql
    assert run("postgresql") == ['ALTER TABLE "p_1"."credential_use_grant" ADD COLUMN IF NOT EXISTS subject_user_id INTEGER']
    assert run("sqlite") == ['ALTER TABLE "p_1"."credential_use_grant" ADD COLUMN subject_user_id INTEGER']   # present: no second
