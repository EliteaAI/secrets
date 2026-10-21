"""The value of a personal credential reference (#7119, C-1009): a write-only, staged write into the reference's store.

``write_material`` is the one function behind ``PUT .../credential_material/...``. It takes the fields as
``SecretStr`` and writes them the way an import does: stake the next generation (a compare-and-set on the row), record
the intent in the store ledger, write the store with check-and-set, mark the ledger written, commit the generation.
The store write is outside any transaction, so a crash at any point leaves a ledger row ``reconcile_credential_store``
settles exactly as it settles an import.

The value is never read back, logged, audited or put in a result: events carry ids and the generation only (no value, no
length, no field name), and a refusal is a fixed code. A committed write puts the reference back to ``pending``: the new
value has to be probed and approved again, by someone other than its creator and the writer (``written_by``). A
``suspended`` reference takes a new value too: suspend, write, probe, approve, activate is the rotation path, and the
grants keep the reference id.

A value holds at least one secret field of the type and nothing else (a key under a ``<path>.*`` map or array of secrets
counts as one). It need not hold them all: a type can offer alternative ways to authenticate (an access token, a
password, a private key) and a credential uses one. Whether the value works is for the probe to say.
"""
import uuid

from pylon.core.tools import log
from pydantic import SecretStr
from tools import secret_stores, this

from . import credential_audit as audit
from .credential_errors import CredentialTaskError, require_actor, store_error_result
from .credential_onboarding import (
    _configuration_facts, _event, _import_failed, _load, _open_ledger, write_to_store,
)
from .credential_schema import project_tx
from .credential_state import (
    WRITABLE_STATES, InvalidTransition, claim_generation, commit_generation, set_ledger_state,
)

MAX_FIELDS = 32
MAX_FIELD_VALUE_BYTES = 8 * 1024   # one value, as UTF-8
MAX_BODY_BYTES = 32 * 1024         # the request body, all fields together
MAX_FIELD_NAME_CHARS = 128


def _field_allowed(name, paths) -> bool:
    """``name`` is one of the type's secret field paths, or a key under a ``<path>.*`` wildcard (a map or array of
    passwords)."""
    for path in paths:
        if path == name:
            return True
        if path.endswith(".*") and name.startswith(path[:-1]) and len(name) > len(path) - 1:
            return True
    return False


# The secret field paths are a pure function of the configuration type's registered schema, so they are asked for once per
# type and kept until the registry of configuration types changes (its version, read from the same process each call).
# Schema only, never material. A configurations plugin without the version is asked every time.
_PATHS = {"version": None, "by_type": {}}


def _secret_field_paths(provider) -> list:
    try:
        service = this.for_module("configurations").module
        try:
            version = service.configuration_registry_version()
        except Exception:  # pylint: disable=W0703
            version = None   # cannot tell when the registry changes: no cache
        if version is not None and version == _PATHS["version"] and provider in _PATHS["by_type"]:
            return list(_PATHS["by_type"][provider])
        found = service.configuration_secret_fields([provider])
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    if not isinstance(found, dict) or provider not in found:
        raise CredentialTaskError("INVALID_REQUEST")   # a type nobody can say the secret fields of
    paths = tuple(found[provider])
    if version is not None:
        if version != _PATHS["version"]:
            _PATHS["version"], _PATHS["by_type"] = version, {}
        _PATHS["by_type"][provider] = paths
    return list(paths)


def _as_secrets(fields) -> dict:
    """The fields as the store port wants them (``pydantic.SecretStr``), whatever secret type the request model used
    (the REST models are pydantic v1) and only if they are bounded: at most ``MAX_FIELDS`` fields, each a non-empty
    text of at most ``MAX_FIELD_VALUE_BYTES`` under a name of at most ``MAX_FIELD_NAME_CHARS``."""
    if not isinstance(fields, dict) or not 0 < len(fields) <= MAX_FIELDS:
        raise CredentialTaskError("INVALID_REQUEST")
    secrets = {}
    for name, secret in fields.items():
        value = secret.get_secret_value() if hasattr(secret, "get_secret_value") else secret
        if (not isinstance(name, str) or not 0 < len(name) <= MAX_FIELD_NAME_CHARS
                or not isinstance(value, str) or not 0 < len(value.encode("utf-8")) <= MAX_FIELD_VALUE_BYTES):
            raise CredentialTaskError("INVALID_REQUEST")
        secrets[name] = SecretStr(value)
    return secrets


def _check_names(fields, paths):
    """At least one field, and only secret fields of the type (or keys under a wildcard path): nothing more is required."""
    if not fields or not all(_field_allowed(name, paths) for name in fields):
        raise CredentialTaskError("INVALID_REQUEST")


def _require_writable(ref, expected_generation):
    """A personal reference that is not in use (pending, validated or suspended), at the generation the caller saw."""
    if ref.ownership_class != "personal":
        raise CredentialTaskError("PERSONAL_ONLY")
    if ref.state not in WRITABLE_STATES:
        raise CredentialTaskError("INVALID_STATE")
    if ref.generation != expected_generation:
        raise CredentialTaskError("CONCURRENT_CHANGE")


def _stage(project_id, ref_id, expected_generation, actor):
    """Check the request against the reference and stake the next generation in one short transaction (the claim is
    the compare-and-set that lets one writer win). Returns ``(reference, generation, ledger id, correlation id)``."""
    with project_tx(project_id) as session:
        ref = _load(session, project_id, ref_id)
        _require_writable(ref, expected_generation)
        generation = ref.generation + 1
        correlation = audit.new_event_id()
        if not claim_generation(session, ref.id, generation):
            session.rollback()
            raise CredentialTaskError("IMPORT_IN_FLIGHT")
        ledger_id = _open_ledger(session, ref, generation, "write", correlation)
        audit.record(session, _event(
            "CREDENTIAL_MATERIAL_WRITE_STARTED", ref, actor, event_id=correlation, credential_generation=generation))
        session.commit()
    return ref, generation, ledger_id, correlation


def _write(project_id, ref_id, fields, expected_generation, actor):
    with project_tx(project_id) as session:
        ref = _load(session, project_id, ref_id)
    _require_writable(ref, expected_generation)
    _check_names(fields, _secret_field_paths(ref.provider))
    facts = _configuration_facts(project_id, str(ref.configuration_uuid))
    if facts is None:
        raise CredentialTaskError("CONFIGURATION_NOT_FOUND")
    ref, generation, ledger_id, correlation = _stage(project_id, ref_id, expected_generation, actor)
    try:
        meta = write_to_store(ref, fields, generation, correlation, actor)
    except secret_stores.StoreError as exc:
        return _import_failed(project_id, ref, generation, ledger_id, actor, exc)
    with project_tx(project_id) as session:
        set_ledger_state(session, ledger_id, ("intent",), "written")
        session.commit()
    with project_tx(project_id) as session:
        if not commit_generation(session, ref.id, generation, facts.get("generation"), written_by=actor):
            session.rollback()
            raise CredentialTaskError("CONCURRENT_CHANGE")
        set_ledger_state(session, ledger_id, ("intent", "written"), "committed")
        audit.record(session, _event(
            "CREDENTIAL_MATERIAL_WRITTEN", ref, actor, credential_generation=generation, outcome="success",
            vault_request_id=getattr(meta, "request_id", None)))
        session.commit()
    return {"generation": generation, "state": "pending"}


def write_material(project_id, ref_id, fields, expected_generation, actor_user_id=0) -> dict:
    """Write the value of a personal reference. ``fields`` maps names to ``SecretStr``. Returns
    ``{"generation", "state"}``, or ``{"error": ..., "code": ...}`` with the reference as it was (a failure after the
    write began has recorded itself; a store timeout leaves the staged generation for ``reconcile_credential_store``).
    Never logs, audits or returns a value."""
    try:
        require_actor(actor_user_id)
        uuid.UUID(str(ref_id))
        return _write(project_id, str(ref_id), _as_secrets(fields), expected_generation, actor_user_id)
    except CredentialTaskError as exc:
        return exc.result()
    except secret_stores.StoreError as exc:
        return store_error_result(exc)
    except InvalidTransition as exc:
        return {"error": f"{exc.reason_code}: {exc}", "code": exc.reason_code}
    except Exception as exc:  # pylint: disable=W0703
        log.error("credential material: failed (%s)", type(exc).__name__)
        code = "AUDIT_UNAVAILABLE" if isinstance(exc, audit.AuditUnavailable) else "FAILED"
        return {"error": "failed; if a write was running, run reconcile_credential_store", "code": code}
