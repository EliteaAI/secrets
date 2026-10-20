"""In-process read of credential governance state for admission (#6757, C-1009).

``credential_use_facts`` answers what admission and the re-check of a queued run need: the live
credential references of some configurations (or by reference id) and the live grants of some grant
keys. Two bounded queries in the project's schema. Metadata only: no secret, no store locator.
"""
import uuid

from pylon.core.tools import web
from sqlalchemy import or_, select
from tools import db  # pylint: disable=E0401

from ..models.credential_governance import CredentialReference, CredentialUseGrant

MAX_SELECTORS = 64
KEY_FIELDS = ("agent_binding_ref", "toolkit_instance_id", "credential_ref", "target_ref", "subject_ref")


def grant_key_string(parts) -> str:
    """The ``|``-joined form of a grant key, as ``credential_use_facts`` returns it."""
    return "|".join(parts)


def _bounded(name, values):
    if values is None:
        return []
    if not isinstance(values, (list, tuple)) or len(values) > MAX_SELECTORS:
        raise ValueError(f"{name}: a list of at most {MAX_SELECTORS}")
    return list(values)


def _uuid(value) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _key(item) -> tuple:
    """A grant key from a tuple/list in ``KEY_FIELDS`` order or a dict with those fields, as strings."""
    if isinstance(item, dict):
        if set(item) != set(KEY_FIELDS):
            raise ValueError("grant key needs exactly " + ", ".join(KEY_FIELDS))
        item = [item[name] for name in KEY_FIELDS]
    if not isinstance(item, (list, tuple)) or len(item) != len(KEY_FIELDS):
        raise ValueError("grant key needs exactly " + ", ".join(KEY_FIELDS))
    binding, toolkit, credential, target, subject = item
    return str(_uuid(binding)), str(toolkit), str(_uuid(credential)), str(target), str(subject)


def _iso(value):
    return value.isoformat() if value is not None else None


class Method:
    @web.method()
    def credential_use_facts(self, project_id: int, config_ids: list, grant_keys: list, ref_ids: list = None) -> dict:
        """Live credential references and grants, for admission and the re-check of a queued run.

        ``config_ids``: configuration ids; ``ref_ids`` (optional): credential reference ids; ``grant_keys``: grant
        unique keys as ``(agent_binding_ref, toolkit_instance_id, credential_ref, target_ref, subject_ref)`` tuples
        or dicts. At most 64 of each (``ValueError`` beyond that or for a malformed one). Retired references and
        revoked grants are not returned. Returns::

            {"references": {configuration_id: {ref_id, state, generation, configuration_generation, store_kind,
                                               ownership_class, revocation_epoch}},
             "grants": {"<key joined with |>": {grant_id, state, revocation_epoch, valid_from, valid_until,
                                                 operations}}}

        References are keyed by configuration id whichever selector found them. Times are ISO-8601 strings.
        """
        configs = [int(item) for item in _bounded("config_ids", config_ids)]
        refs = [_uuid(item) for item in _bounded("ref_ids", ref_ids)]
        keys = {_key(item) for item in _bounded("grant_keys", grant_keys)}
        references, grants = {}, {}
        with db.get_session(project_id) as session:
            if configs or refs:
                selected = [CredentialReference.configuration_id.in_(configs)] if configs else []
                selected += [CredentialReference.id.in_(refs)] if refs else []
                for row in session.execute(select(CredentialReference).where(
                        CredentialReference.project_id == project_id, CredentialReference.state != "retired",
                        or_(*selected))).scalars():
                    references[row.configuration_id] = {
                        "ref_id": str(row.id), "state": row.state, "generation": row.generation,
                        "configuration_generation": row.configuration_generation, "store_kind": row.store_kind,
                        "ownership_class": row.ownership_class, "revocation_epoch": row.revocation_epoch}
            if keys:
                for row in session.execute(select(CredentialUseGrant).where(
                        CredentialUseGrant.project_id == project_id, CredentialUseGrant.state != "revoked",
                        CredentialUseGrant.agent_binding_ref.in_([_uuid(key[0]) for key in keys]),
                        CredentialUseGrant.toolkit_instance_id.in_({key[1] for key in keys}),
                        CredentialUseGrant.credential_ref.in_([_uuid(key[2]) for key in keys]),
                        CredentialUseGrant.target_ref.in_({key[3] for key in keys}),
                        CredentialUseGrant.subject_ref.in_({key[4] for key in keys}))).scalars():
                    found = (str(row.agent_binding_ref), row.toolkit_instance_id, str(row.credential_ref),
                             row.target_ref, row.subject_ref)
                    if found in keys:  # the IN lists are a superset of the pairs asked for
                        grants[grant_key_string(found)] = {
                            "grant_id": str(row.id), "state": row.state, "revocation_epoch": row.revocation_epoch,
                            "valid_from": _iso(row.valid_from), "valid_until": _iso(row.valid_until),
                            "operations": list(row.operations or [])}
        return {"references": references, "grants": grants}
