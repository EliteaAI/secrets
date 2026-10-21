"""Fixtures for credential governance tests (#6757): the real models, state machines and services run
over SQLite files (one per project, ``schema_translate_map`` like production), with fake collaborators:
the ``secret_stores`` port, ``tracing`` (an outbox table in the same database, so rollbacks and commits
apply to audit rows exactly as they do to the change), ``configurations`` and ``elitea_core``.

Set ``ELITEA_TEST_PG_DSN`` to run the same tests on PostgreSQL (one scratch schema per project).
Set ``C1009_REAL_PORT_DIR`` to the ``tools/secret_stores`` directory of the ``shared`` checkout to run
against the real port types (``StoreError``, ``SecretValue``, ``AuthorizedStoreContext`` ...) instead
of the minimal copies below.
"""
import contextlib
import importlib
import importlib.util
import json
import os
import re
import sys
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

import sqlalchemy as sa
from pydantic import SecretStr
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, declarative_base

PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent
ALIAS = "secretsplugin"
SCHEMA = "tenant"
FIXTURE_VALUE = "fixture-api-key-0001"  # fake, test only
FIXTURE_VALUE_2 = "fixture-api-key-0002"
PG_DSN = os.environ.get("ELITEA_TEST_PG_DSN")


@compiles(JSONB, "sqlite")
def _jsonb_on_sqlite(_element, _compiler, **_kw):
    return "JSON"


TEST_TABLES = sa.MetaData()
BINDING = sa.Table("agent_identity_binding", TEST_TABLES, sa.Column("id", sa.Uuid, primary_key=True),
                   sa.Column("project_id", sa.Integer), sa.Column("application_id", sa.Integer),
                   sa.Column("version_id", sa.Integer), schema=SCHEMA)
TOOL_MAPPING = sa.Table("entity_tool_mapping", TEST_TABLES, sa.Column("id", sa.Integer, primary_key=True),
                        sa.Column("tool_id", sa.Integer), sa.Column("entity_version_id", sa.Integer),
                        sa.Column("entity_type", sa.String), schema=SCHEMA)
MANDATE = sa.Table("autonomous_mandate", TEST_TABLES, sa.Column("id", sa.Uuid, primary_key=True),
                   sa.Column("project_id", sa.Integer), sa.Column("agent_binding_ref", sa.Uuid),
                   sa.Column("owner_user_id", sa.Integer), sa.Column("state", sa.String), schema=SCHEMA)
APPLICATION = sa.Table("applications", TEST_TABLES, sa.Column("id", sa.Integer, primary_key=True),
                       sa.Column("name", sa.String), schema=SCHEMA)
VERSION = sa.Table("application_versions", TEST_TABLES, sa.Column("id", sa.Integer, primary_key=True),
                   sa.Column("name", sa.String), schema=SCHEMA)
TOOL = sa.Table("elitea_tools", TEST_TABLES, sa.Column("id", sa.Integer, primary_key=True),
                sa.Column("type", sa.String), sa.Column("name", sa.String), schema=SCHEMA)
CONFIGURATION = sa.Table("configuration", TEST_TABLES, sa.Column("id", sa.Integer, primary_key=True),
                         sa.Column("uuid", sa.Uuid, unique=True), sa.Column("elitea_title", sa.String),
                         sa.Column("generation", sa.Integer), schema=SCHEMA)
AUDIT_OUTBOX = sa.Table("audit_outbox", TEST_TABLES, sa.Column("event_id", sa.String, primary_key=True),
                        sa.Column("body", sa.Text), schema=SCHEMA)


# --- the secret_stores port -------------------------------------------------------------------------------------

class Crash(BaseException):
    """The process died here: not an Exception, so no handler in the code under test sees it."""


def _port_types():
    real_dir = os.environ.get("C1009_REAL_PORT_DIR")
    if real_dir:
        spec = importlib.util.spec_from_file_location(
            "secret_stores_real", Path(real_dir) / "__init__.py", submodule_search_locations=[real_dir])
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    return _minimal_port_types()


def _minimal_port_types():  # the shapes of shared/tools/secret_stores, enough for these tests
    port = types.ModuleType("secret_stores_minimal")
    messages = {
        "DENIED": "The secret store denied the operation.", "SEALED": "The secret store is sealed.",
        "UNAVAILABLE": "The secret store is unavailable.", "TLS_INVALID": "The secret store connection failed TLS validation.",
        "NOT_FOUND": "The secret was not found in the store.",
        "VERSION_CONFLICT": "The secret store version did not match the expected version.",
    }

    class StoreError(Exception):
        def __init__(self, code):
            self.code = code if code in messages else "UNAVAILABLE"
            self.message = messages[self.code]
            super().__init__(self.message)

        @property
        def audit_code(self):
            return f"STORE_{self.code}"

    seal = object()
    purposes = frozenset({"onboard", "probe", "retire", "reconcile", "smoke", "release"})
    operation_purposes = {
        "read": {"probe", "reconcile", "smoke", "release"}, "write": {"onboard"}, "metadata": {"probe", "reconcile", "smoke"},
        "prune": {"retire", "reconcile"}, "delete_all": {"retire", "reconcile"},
    }

    class AuthorizedStoreContext:
        __slots__ = ("purpose", "decision_id", "actor_ref", "project_id", "ref_id")

        def __init__(self, *, _seal=None, **fields):
            if _seal is not seal:
                raise TypeError("AuthorizedStoreContext is not constructible")
            for name, value in fields.items():
                object.__setattr__(self, name, value)

        def __setattr__(self, name, value):
            raise AttributeError("immutable")

    class CredentialStoreProvider:
        @staticmethod
        def mint(purpose, *, decision_id, actor_ref, project_id, ref_id):
            if purpose not in purposes:
                raise ValueError("unknown purpose")
            if not isinstance(ref_id, uuid.UUID) or isinstance(project_id, bool) or not isinstance(project_id, int):
                raise ValueError("invalid reference")
            if not isinstance(actor_ref, str) or not actor_ref:
                raise ValueError("invalid actor_ref")
            return AuthorizedStoreContext(_seal=seal, purpose=purpose, decision_id=str(decision_id),
                                          actor_ref=actor_ref, project_id=project_id, ref_id=ref_id)

    class StoreRef:
        def __init__(self, ref_id, project_id, store_kind, locator=None):
            self.ref_id, self.project_id, self.store_kind, self.locator = ref_id, project_id, store_kind, locator or {}

        def __repr__(self):
            return f"StoreRef({self.ref_id}, {self.project_id}, {self.store_kind})"

    class SecretValue:
        def __init__(self, fields, generation):
            self.fields = {name: value if isinstance(value, SecretStr) else SecretStr(value)
                           for name, value in dict(fields).items()}
            self.generation = int(generation)

        def __repr__(self):
            return f"SecretValue(fields={sorted(self.fields)}, generation={self.generation})"

    class SecretMetadata:
        def __init__(self, current_version, versions, request_id=None):
            self.current_version, self.versions, self.request_id = current_version, frozenset(versions), request_id

    def check_context(ctx, ref, operation):
        if (type(ctx) is not AuthorizedStoreContext or ctx.ref_id != ref.ref_id or ctx.project_id != ref.project_id
                or ctx.purpose not in operation_purposes[operation]):
            raise StoreError("DENIED")

    for name, value in dict(
            StoreError=StoreError, AuthorizedStoreContext=AuthorizedStoreContext,
            CredentialStoreProvider=CredentialStoreProvider, StoreRef=StoreRef, SecretValue=SecretValue,
            SecretMetadata=SecretMetadata, check_context=check_context).items():
        setattr(port, name, value)
    return port


class MemoryStore:
    """An in-memory store with the port's semantics (compare-and-set, one version per generation) and switches
    to make it fail, or the process die, at chosen points."""

    def __init__(self, port, kind):
        self.port, self.kind = port, kind
        self.versions = {}  # ref_id -> {generation: {field: value}}
        self.calls = []  # (operation, purpose, decision_id)
        self.read_many_calls = []  # one list of (ref_id, generation) per read_many call
        self.fail = {}  # operation -> store code, raised before any effect
        self.fail_after_effect = {}  # operation -> store code, raised after the effect (a timeout that did happen)
        self.crash_before_write = False
        self.crash_after_write = False
        self.smoke_result = {"read_canary": True, "list_denied": True, "foreign_tenant_denied": True,
                             "write_without_cas_refused": True}

    def _enter(self, operation, ref, ctx):
        self.calls.append((operation, getattr(ctx, "purpose", None), getattr(ctx, "decision_id", None)))
        self.port.check_context(ctx, ref, operation)
        if operation in self.fail:
            raise self.port.StoreError(self.fail[operation])

    def _exit(self, operation):
        if operation in self.fail_after_effect:
            raise self.port.StoreError(self.fail_after_effect[operation])

    def read(self, ref, generation, ctx):
        self._enter("read", ref, ctx)
        bundle = self.versions.get(ref.ref_id, {}).get(generation)
        if bundle is None:
            raise self.port.StoreError("NOT_FOUND")
        return self.port.SecretValue(bundle, generation)

    def read_many(self, refs, generations, ctx):
        """The port's ``read_many``: every context checked before any read, all or nothing, keyed
        ``(ref_id, generation)``; a failing ref is named in ``details``. ``read_many_calls`` counts the calls."""
        refs, generations = list(refs), [int(item) for item in generations]
        contexts = list(ctx) if isinstance(ctx, (list, tuple)) else [ctx] * len(refs)
        if len(refs) != len(generations) or len(refs) != len(contexts) or len(refs) > 64:
            raise ValueError("invalid read_many arguments")
        self.read_many_calls.append([(ref.ref_id, generation) for ref, generation in zip(refs, generations)])
        for ref, item_ctx in zip(refs, contexts):
            self.port.check_context(item_ctx, ref, "read")
        found = {}
        for ref, generation, item_ctx in zip(refs, generations, contexts):
            try:
                found[(ref.ref_id, generation)] = self.read(ref, generation, item_ctx)
            except self.port.StoreError as exc:
                exc.details = {"ref_id": str(ref.ref_id)}
                raise
        return found

    def write(self, ref, value, *, expected_version, ctx):
        self._enter("write", ref, ctx)
        if self.crash_before_write:
            raise Crash()
        stored = self.versions.setdefault(ref.ref_id, {})
        if max(stored, default=0) != expected_version:
            raise self.port.StoreError("VERSION_CONFLICT")
        stored[expected_version + 1] = {name: secret.get_secret_value() for name, secret in value.fields.items()}
        if self.crash_after_write:
            raise Crash()
        self._exit("write")
        return self.port.SecretMetadata(expected_version + 1, {expected_version + 1}, request_id="req-write")

    def metadata(self, ref, ctx):
        self._enter("metadata", ref, ctx)
        found = set(self.versions.get(ref.ref_id, {}))
        return self.port.SecretMetadata(max(found, default=0), found, request_id="req-meta")

    def prune(self, ref, keep_generations, ctx):
        self._enter("prune", ref, ctx)
        stored = self.versions.get(ref.ref_id, {})
        for generation in sorted(stored)[:-keep_generations]:
            del stored[generation]
        found = set(stored)
        return self.port.SecretMetadata(max(found, default=0), found)

    def delete_all(self, ref, ctx):
        self._enter("delete_all", ref, ctx)
        self.versions.pop(ref.ref_id, None)
        self._exit("delete_all")

    def smoke(self, ctx):
        self.calls.append(("smoke", ctx.purpose, ctx.decision_id))
        if "smoke" in self.fail:
            raise self.port.StoreError(self.fail["smoke"])
        return dict(self.smoke_result)


class FakeSecretStores(types.ModuleType):
    """What ``from tools import secret_stores`` gives the services."""

    def __init__(self):
        super().__init__("tools.secret_stores")
        self.reset()

    def reset(self):
        port = _port_types()
        for name in ("StoreError", "AuthorizedStoreContext", "CredentialStoreProvider", "StoreRef", "SecretValue",
                     "SecretMetadata", "check_context"):
            setattr(self, name, getattr(port, name))
        self.port = port
        self.stores = {"database": MemoryStore(port, "database"), "corporate_vault": MemoryStore(port, "corporate_vault")}
        self.unavailable = set()
        self.get_store_calls = []

    def get_store(self, store_kind, *, governed):
        self.get_store_calls.append((store_kind, governed))
        if not governed or store_kind in self.unavailable or store_kind not in self.stores:
            raise self.StoreError("UNAVAILABLE")
        return self.stores[store_kind]


# --- tracing: an audit outbox in the same database ------------------------------------------------------------------

EVENT_FIELDS = frozenset({
    "event_id", "event_type", "occurred_at", "tenant", "project_id", "application_id", "environment", "caller_ref",
    "user_ref", "mandate_ref", "agent_binding_ref", "runtime_identity_ref", "run_id", "attempt", "parent_call_id",
    "toolkit_instance_id", "operation_id", "target_ref", "credential_ref", "credential_generation", "decision",
    "reason_code", "policy_revision", "revocation_epoch", "approver_ref", "vault_request_id", "provider_request_id",
    "outcome", "traceparent", "ocsf_class"})
EVENT_TYPES = frozenset({"admission", "decision", "approval", "credential_acquired", "probe", "refresh", "rotation",
                         "withdrawal", "issuer_action", "lifecycle", "execution_outcome"})
OUTCOMES = frozenset({"success", "denied", "interaction_required", "failed", "target_outcome_unknown"})


def validate_event(event):
    """The rules of SecurityAuditEventV1 that these services can break."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    if set(event) - EVENT_FIELDS:
        raise ValueError(f"unknown audit fields {sorted(set(event) - EVENT_FIELDS)}")
    if event.get("event_type") not in EVENT_TYPES:
        raise ValueError("bad event_type")
    if not re.fullmatch(r"[A-Z0-9_]{1,64}", event.get("reason_code") or ""):
        raise ValueError("bad reason_code")
    if event.get("outcome") is not None and event["outcome"] not in OUTCOMES:
        raise ValueError("bad outcome")
    if "event_id" in event:
        uuid.UUID(event["event_id"])
    for value in event.values():
        if isinstance(value, str) and len(value) > 256:
            raise ValueError("value too long")


class FakeTracing:
    def __init__(self):
        self.autocommit_events = []
        self.fail = False

    def security_audit_record(self, session, event):
        if self.fail:
            raise RuntimeError("audit trail unavailable")
        validate_event(event)
        event_id = event.get("event_id") or str(uuid.uuid4())
        session.execute(AUDIT_OUTBOX.insert().values(
            event_id=event_id, body=json.dumps({**event, "event_id": event_id}, default=str)))
        return {"event_id": event_id}

    def security_audit_record_autocommit(self, event):
        if self.fail:
            raise RuntimeError("audit trail unavailable")
        validate_event(event)
        self.autocommit_events.append(dict(event))
        return {"event_id": event.get("event_id")}


# --- configurations ---------------------------------------------------------------------------------------------------

class FakeConfigurations:
    """The in-process methods, over an in-memory table. ``bundle`` is as strict about the context as the real one."""

    instances = 0

    def __init__(self, stores, databases=None):
        self.stores = stores
        self.databases = databases  # the table the credential lists join with is kept in step with ``rows``
        self.rows = {}  # project_id -> {id: row}
        self.bundle_calls = []
        self.bundle_error = None
        self.secret_paths = {"api_cred": ["api_key"]}  # type -> secret field paths (``headers.*`` = a map of passwords)
        self.secret_fields_error = None
        FakeConfigurations.instances += 1
        # a registry version no other fake instance used, so the plugin's in-process cache never answers for a test
        # other than the one that filled it
        self.registry_version = FakeConfigurations.instances * 1_000_000
        self.secret_fields_calls = []  # the types asked of ``configuration_secret_fields``, one list per call

    def add(self, project_id, *, type_="api_cred", section="credentials", secrets=None, generation=1, title=None):
        rows = self.rows.setdefault(project_id, {})
        row = SimpleNamespace(
            id=len(rows) + 1, uuid=str(uuid.uuid4()), project_id=project_id, type=type_, section=section,
            generation=generation, title=title,
            secrets=dict(secrets if secrets is not None else {"api_key": FIXTURE_VALUE}))
        rows[row.id] = row
        self._mirror(row, insert=True)
        return row

    def _mirror(self, row, insert=False):
        if self.databases is None:
            return
        with self.databases.get_session(row.project_id) as session:
            if insert:
                session.execute(CONFIGURATION.insert().values(
                    id=row.id, uuid=uuid.UUID(row.uuid), elitea_title=row.title, generation=row.generation))
            else:
                session.execute(CONFIGURATION.update().where(CONFIGURATION.c.id == row.id).values(
                    generation=row.generation))
            session.commit()

    def edit_secret(self, row, **secrets):
        row.secrets.update(secrets)
        row.generation += 1
        self._mirror(row)

    def configuration_credential_facts(self, project_id, uuids):
        """The shape of the real method: ``{uuid: {id, project_id, type, section, generation, title}}`` (``title`` is the
        configuration's ``elitea_title``; test_7119 pins the key set)."""
        return {row.uuid: {"id": row.id, "project_id": row.project_id, "type": row.type, "section": row.section,
                           "generation": row.generation, "title": row.title}
                for row in self.rows.get(project_id, {}).values() if row.uuid in uuids}

    def configuration_registry_version(self):
        """The shape of the real method: a number that changes whenever a configuration type is (un)registered."""
        return self.registry_version

    def configuration_secret_fields(self, types):
        """The shape of the real method: ``{type: [path, ...]}``, an unregistered type left out."""
        self.secret_fields_calls.append(list(types))
        if self.secret_fields_error:
            raise self.secret_fields_error
        return {name: list(self.secret_paths[name]) for name in types if name in self.secret_paths}

    def configuration_secret_bundle(self, project_id, configuration_id, ctx):
        self.bundle_calls.append((project_id, configuration_id, getattr(ctx, "purpose", None)))
        if (type(ctx) is not self.stores.AuthorizedStoreContext or ctx.purpose not in ("onboard", "probe")
                or ctx.project_id != project_id):
            raise PermissionError("not authorized")
        if self.bundle_error:
            raise self.bundle_error
        row = self.rows.get(project_id, {}).get(configuration_id)
        if row is None:
            return None
        if not row.secrets:
            raise ValueError("NO_SECRET_FIELDS")
        return {"configuration_generation": row.generation,
                "fields": {name: SecretStr(value) for name, value in row.secrets.items()}}


class FakeAdmin:
    def __init__(self):
        self.tasks, self.groups = {}, {}

    def register_admin_task(self, name, func, group=None):
        if name in self.tasks:
            raise RuntimeError(f"Task already registered: {name}")
        self.tasks[name] = func
        if group is not None:
            self.groups[name] = group

    def unregister_admin_task(self, name, func):
        _ = func
        if name not in self.tasks:
            raise RuntimeError(f"Task is not registered: {name}")
        self.tasks.pop(name)
        self.groups.pop(name, None)


class FakeCore:
    def __init__(self):
        self.revoked = []
        self.checks = []  # (project_id, configuration_uuid, type, user_id, actor_user_id, onboarding) of governed_check_connection
        self.check_answer = {"success": True}
        self.check_error = None

    def revoke_credential_contexts(self, session, credential_ref):
        _ = session
        self.revoked.append(credential_ref)

    def governed_check_connection(self, project_id, configuration_uuid, config_type, user_id, actor_user_id=None,
                                  onboarding=False):
        self.checks.append((project_id, configuration_uuid, config_type, user_id, actor_user_id, onboarding))
        if self.check_error:
            raise self.check_error
        return dict(self.check_answer)


# --- databases --------------------------------------------------------------------------------------------------------

class Databases:
    """One database per project. ``get_session`` is what ``tools.db`` offers the services."""

    def __init__(self, base):
        self.Base = base
        self.directory = None
        self.engines = {}

    def start(self, directory):
        self.directory, self.engines = Path(directory), {}

    def engine(self, project_id):
        if project_id not in self.engines:
            if PG_DSN:
                schema = f"t6757_{uuid.uuid4().hex[:10]}"
                base = sa.create_engine(PG_DSN)
                with base.begin() as conn:
                    conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
                engine = base.execution_options(schema_translate_map={SCHEMA: schema})
            else:
                engine = sa.create_engine(f"sqlite:///{self.directory}/p{project_id}.db").execution_options(
                    schema_translate_map={SCHEMA: None})
            self._create_tables(engine)
            self.engines[project_id] = engine
        return self.engines[project_id]

    def _create_tables(self, engine):
        governance = [table for name, table in self.Base.metadata.tables.items()
                      if table.name.startswith("credential_")]
        if not PG_DSN:  # SQLite: no ::jsonb casts, partial indexes spelled for its dialect
            for table in governance:
                for column in table.columns:
                    if column.server_default is not None and "::" in str(getattr(column.server_default, "arg", "")):
                        column.server_default = None
                for index in table.indexes:
                    where = index.dialect_options["postgresql"]["where"]
                    if where is not None:
                        index.dialect_options["sqlite"]["where"] = where
        self.Base.metadata.create_all(engine, tables=governance)
        TEST_TABLES.create_all(engine)

    @contextlib.contextmanager
    def get_session(self, project_id=None):
        session = Session(self.engine(project_id), expire_on_commit=False)
        try:
            yield session
        finally:
            session.close()

    # -- test helpers
    def execute(self, project_id, sql, **params):
        """Run raw SQL on the project's database; ``tenant.`` names are translated as the models' are."""
        with self.get_session(project_id) as session:
            result = session.execute(sa.text(self._qualify(project_id, sql)), params)
            rows = [dict(row._mapping) for row in result] if result.returns_rows else []
            session.commit()
            return rows

    def _qualify(self, project_id, sql):
        schema = self.engine(project_id).get_execution_options()["schema_translate_map"][SCHEMA]
        return re.sub(r"\btenant\.", f'"{schema}".' if schema else "", sql)

    def events(self, project_id):
        with self.get_session(project_id) as session:
            return [json.loads(body) for (body,) in session.execute(sa.select(AUDIT_OUTBOX.c.body))]

    def dispose(self):
        for engine in self.engines.values():
            engine.dispose()


# --- the environment --------------------------------------------------------------------------------------------------

class Governance:
    """Everything a credential governance test touches, installed once and reset for each test."""

    def __init__(self):
        self.installed = False

    def install(self):
        if self.installed:
            return
        tools = sys.modules["tools"]
        tools.config.POSTGRES_TENANT_SCHEMA = SCHEMA
        base = declarative_base()
        self.db = Databases(base)
        tools.db = SimpleNamespace(Base=base, get_session=self.db.get_session)
        tools.db_tools = SimpleNamespace(AbstractBaseMixin=type("AbstractBaseMixin", (), {}))
        self.this = tools.this  # the shared stub: modules is a dict, for_module(name) returns modules[name]
        self.stores = FakeSecretStores()
        tools.secret_stores = self.stores
        for name, path in ((ALIAS, PLUGIN_ROOT), (f"{ALIAS}.models", PLUGIN_ROOT / "models"),
                           (f"{ALIAS}.utils", PLUGIN_ROOT / "utils"), (f"{ALIAS}.methods", PLUGIN_ROOT / "methods")):
            if name not in sys.modules:
                package = types.ModuleType(name)
                package.__path__ = [str(path)]
                sys.modules[name] = package
        self.tools = tools
        self.installed = True

    def reset(self, directory):
        self.stores.reset()
        self.db.dispose()
        self.db.start(directory)
        self.tracing = FakeTracing()
        self.configurations = FakeConfigurations(self.stores, self.db)
        self.admin = FakeAdmin()
        self.core = FakeCore()
        self._saved_modules = dict(self.this.modules)  # other suites keep their own entries (elitea_core config)
        self.this.modules.update(
            tracing=SimpleNamespace(module=self.tracing), configurations=SimpleNamespace(module=self.configurations),
            admin=SimpleNamespace(module=self.admin), elitea_core=SimpleNamespace(module=self.core))

    def restore(self):
        self.db.dispose()
        self.this.modules.clear()
        self.this.modules.update(self._saved_modules)

    def module(self, dotted):
        return importlib.import_module(f"{ALIAS}.{dotted}")

    # -- rows
    _counter = 0

    def _next(self):
        Governance._counter += 1
        return Governance._counter

    @staticmethod
    def _snapshot(row):
        return SimpleNamespace(**{c.name: getattr(row, c.name) for c in row.__table__.columns})

    def add_reference(self, project_id=1, *, state="pending", generation=0, **overrides):
        """A reference row in the given state (an active one carries the approval its CHECK demands)."""
        models = self.module("models.credential_governance")
        values = dict(
            project_id=project_id, configuration_id=self._next(), configuration_uuid=uuid.uuid4(), provider="api_cred",
            ownership_class="project_shared", store_kind="database", store_locator={"section": "credential_store"},
            created_by=10, state=state, generation=generation)
        if state in ("active", "suspended"):
            values.update(generation=max(generation, 1), approved_by=20, approval_ref="CHG-1", policy_revision="rev-1",
                          configuration_generation=1)
            values["validated_generation"] = values["generation"]
        values.update(overrides)
        with self.db.get_session(project_id) as session:
            row = models.CredentialReference(**values)
            session.add(row)
            session.commit()
            return row.id

    def reference(self, project_id, ref_id):
        models = self.module("models.credential_governance")
        with self.db.get_session(project_id) as session:
            return self._snapshot(session.get(models.CredentialReference, ref_id))

    def add_grant(self, project_id=1, *, state="pending_approval", credential_ref=None, **overrides):
        models = self.module("models.credential_governance")
        values = dict(
            project_id=project_id, application_id=5, subject_kind="user_delegation", subject_ref="idp:t1:u1",
            agent_binding_ref=uuid.uuid4(), toolkit_instance_id="41", credential_ref=credential_ref or uuid.uuid4(),
            target_ref="*", created_by=10, state=state)
        if state in ("active", "suspended"):
            values.update(approved_by=20, approval_ref="CHG-2", policy_revision="rev-1")
        values.update(overrides)
        with self.db.get_session(project_id) as session:
            row = models.CredentialUseGrant(**values)
            session.add(row)
            session.commit()
            return row.id

    def grant(self, project_id, grant_id):
        models = self.module("models.credential_governance")
        with self.db.get_session(project_id) as session:
            return self._snapshot(session.get(models.CredentialUseGrant, grant_id))

    def ledger(self, project_id, ref_id=None):
        models = self.module("models.credential_governance")
        with self.db.get_session(project_id) as session:
            query = sa.select(models.CredentialStoreLedger).order_by(models.CredentialStoreLedger.created_at)
            if ref_id is not None:
                query = query.where(models.CredentialStoreLedger.credential_ref == ref_id)
            return [self._snapshot(row) for row in session.execute(query).scalars()]

    def add_ledger(self, project_id, ref_id, generation, op="write", state="intent", store_kind="database"):
        models = self.module("models.credential_governance")
        with self.db.get_session(project_id) as session:
            row = models.CredentialStoreLedger(
                credential_ref=ref_id, generation=generation, store_kind=store_kind, op=op, state=state,
                correlation_id=str(uuid.uuid4()))
            session.add(row)
            session.commit()
            return row.id

    def age_ledger(self, project_id, seconds=3600):
        """Make every ledger row look ``seconds`` older, so the reconciler's age threshold passes."""
        models = self.module("models.credential_governance")
        from datetime import datetime, timedelta, timezone  # pylint: disable=C0415
        with self.db.get_session(project_id) as session:
            session.execute(sa.update(models.CredentialStoreLedger).values(
                updated_at=datetime.now(timezone.utc) - timedelta(seconds=seconds)))
            session.commit()


GOV = Governance()
