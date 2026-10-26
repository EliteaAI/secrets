"""In-process read of credential governance state for admission (#6757, C-1009).

``credential_use_facts`` answers what admission and the re-check of a queued run need: the live
credential references of some configurations (or by reference id) and the live grants of some grant
keys. Two bounded queries in the project's schema. Metadata only: no secret, no store locator.

Personal references (#7119). A configuration can have a shared reference and one personal reference per owner. For a
caller, the caller's own personal reference wins over the shared one *whatever its state*: a personal reference that is
still pending, validated or suspended refuses the owner's runs until it is active (fail closed; the shared credential
is never a silent fallback for someone who has registered their own). That reference carries a ``note`` saying so, for
the UI to show.

Known limits (follow-ups, no code yet): a mandate's owner is read at admission and a change of the owner after it is not
re-read when a queued run is re-checked; the fallback query for a configuration with only other people's personal
references is capped at ``MAX_SELECTORS`` rows, so one crowded configuration can crowd out another's fallback; and
``ref_ids`` are keyed by configuration id, so two references of one configuration asked for together return one.
"""
import uuid

from pylon.core.tools import web
from sqlalchemy import and_, false, or_, select
from tools import db  # pylint: disable=E0401

from ..models.credential_governance import CredentialReference, CredentialUseGrant

MAX_SELECTORS = 64
MAX_SUBJECT_CHARS = 160
# 2: grant facts carry ``subject_kind`` and reference facts ``custodian_user_id`` (read by elitea_core's startup check).
# 3: reference facts carry ``custodian_subject_ref``, and ``credential_use_facts`` takes the caller's identity to find
#    the caller's own personal reference of a configuration (#7119).
# 4: ``credential_use_facts`` takes ``grants_for`` (grant keys whose credential may be named by configuration id), so
#    references and the grants on them are one session (perf review 2026-10-21, M4/M5). The result shape is v3's.
# 5: ``credential_use_facts`` takes ``subject_grants`` (``(credential, subject_ref)`` pairs) and answers the active grants
#    a subject holds on a credential whatever the binding and toolkit, for development runs (#7213). The result shape
#    gains ``subject_grants`` only when asked.
CREDENTIAL_FACTS_VERSION = 5
MAX_SUBJECT_GRANT_ROWS = 64   # active grants returned for all the subject_grants pairs of one call together
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


def _grant_for(item) -> tuple:
    """A ``grants_for`` key: a grant key whose credential is a reference id, or the id (an integer) of a configuration
    in this call's ``config_ids``/``ref_ids``, meaning the reference the call resolved for it. Returns the key with
    the credential as ``uuid.UUID`` or ``int``."""
    if isinstance(item, dict):
        if set(item) != set(KEY_FIELDS):
            raise ValueError("grant key needs exactly " + ", ".join(KEY_FIELDS))
        item = [item[name] for name in KEY_FIELDS]
    if not isinstance(item, (list, tuple)) or len(item) != len(KEY_FIELDS):
        raise ValueError("grant key needs exactly " + ", ".join(KEY_FIELDS))
    binding, toolkit, credential, target, subject = item
    if isinstance(credential, bool):
        raise ValueError("grant key: a reference id or a configuration id")
    if isinstance(credential, int):
        wanted = credential
    else:
        wanted = _uuid(credential)
    return str(_uuid(binding)), str(toolkit), wanted, str(target), str(subject)


def _subject_grant(item) -> tuple:
    """A ``subject_grants`` pair: ``(credential, subject_ref)``, the credential a reference id or (as in ``grants_for``) the
    id of a configuration among this call's ``config_ids``/``ref_ids``. Returns the pair with the credential as
    ``uuid.UUID`` or ``int``."""
    if not isinstance(item, (list, tuple)) or len(item) != 2:
        raise ValueError("subject grant key needs exactly credential, subject_ref")
    credential, subject = item
    if isinstance(credential, bool) or not isinstance(subject, str) or not 0 < len(subject) <= MAX_SUBJECT_CHARS:
        raise ValueError("subject grant key: a reference id or a configuration id, and a subject reference")
    return (credential if isinstance(credential, int) else _uuid(credential)), subject


def _grant_facts(row) -> dict:
    return {
        "grant_id": str(row.id), "state": row.state, "subject_kind": row.subject_kind,
        "revocation_epoch": row.revocation_epoch, "valid_from": _iso(row.valid_from),
        "valid_until": _iso(row.valid_until), "operations": list(row.operations or [])}


def _custodian_user_id(custodian_ref):
    """The user id in a reference's ``custodian_ref`` JSON, or ``None`` when it names no user."""
    user_id = custodian_ref.get("user_id") if isinstance(custodian_ref, dict) else None
    return user_id if isinstance(user_id, int) and not isinstance(user_id, bool) else None


def _custodian_subject(custodian_ref):
    """The identity-provider subject in a reference's ``custodian_ref`` JSON, or ``None``."""
    subject = custodian_ref.get("subject_ref") if isinstance(custodian_ref, dict) else None
    return subject if isinstance(subject, str) else None


def _iso(value):
    return value.isoformat() if value is not None else None


def _present(row) -> dict:
    facts = {
        "ref_id": str(row.id), "state": row.state, "generation": row.generation,
        "configuration_generation": row.configuration_generation, "store_kind": row.store_kind,
        "ownership_class": row.ownership_class, "revocation_epoch": row.revocation_epoch,
        "custodian_user_id": _custodian_user_id(row.custodian_ref),
        "custodian_subject_ref": _custodian_subject(row.custodian_ref)}
    if row.ownership_class == "personal" and row.state != "active":
        facts["note"] = f"personal reference {row.state}: runs of its owner are refused until it is active"
    return facts


def _caller_subject(personal_subject_ref, personal_user_id):
    if personal_subject_ref is not None and (
            not isinstance(personal_subject_ref, str) or not 0 < len(personal_subject_ref) <= MAX_SUBJECT_CHARS):
        raise ValueError("personal_subject_ref: a subject reference")
    if personal_user_id is not None and (isinstance(personal_user_id, bool) or not isinstance(personal_user_id, int)):
        raise ValueError("personal_user_id: an integer")


def _references_of_configurations(session, project_id, wanted, personal_subject_ref, personal_user_id) -> dict:
    """One live reference per configuration id: the caller's own personal reference when there is one, else the
    non-personal one (at most one by the index). A configuration with only other people's personal references gets
    one of them, so the decision can name the class; the caller never uses it."""
    base = (CredentialReference.project_id == project_id, CredentialReference.state != "retired",
            CredentialReference.configuration_id.in_(wanted))
    owner = []
    if personal_subject_ref is not None:
        owner.append(CredentialReference.custodian_ref["subject_ref"].as_string() == personal_subject_ref)
    if personal_user_id is not None:
        owner.append(CredentialReference.custodian_ref["user_id"].as_integer() == personal_user_id)
    mine = and_(CredentialReference.ownership_class == "personal", or_(*owner)) if owner else false()
    chosen = {}
    for row in session.execute(select(CredentialReference).where(
            *base, or_(CredentialReference.ownership_class != "personal", mine))).scalars():
        rank = 1 if row.ownership_class == "personal" else 0
        if row.configuration_id not in chosen or rank > chosen[row.configuration_id][0]:
            chosen[row.configuration_id] = (rank, row)
    found = {configuration_id: _present(row) for configuration_id, (_, row) in chosen.items()}
    if len(found) < len(set(wanted)):
        for row in session.execute(select(CredentialReference).where(
                *base[:2], CredentialReference.configuration_id.in_([i for i in wanted if i not in found]))
                .order_by(CredentialReference.created_at, CredentialReference.id).limit(MAX_SELECTORS)).scalars():
            found.setdefault(row.configuration_id, _present(row))
    return found


class Method:
    CREDENTIAL_FACTS_VERSION = CREDENTIAL_FACTS_VERSION

    @web.method()
    def credential_facts_version(self) -> int:
        """The shape version of ``credential_use_facts`` (a startup check reads it; undecorated attributes do not bind)."""
        return CREDENTIAL_FACTS_VERSION

    @web.method()
    def credential_use_facts(  # pylint: disable=R0913
        self, project_id: int, config_ids: list, grant_keys: list, ref_ids: list = None,
        personal_subject_ref: str = None, personal_user_id: int = None, grants_for: list = None,
        subject_grants: list = None,
    ) -> dict:
        """Live credential references and grants, for admission and the re-check of a queued run.

        ``config_ids``: configuration ids; ``ref_ids`` (optional): credential reference ids; ``grant_keys``: grant
        unique keys as ``(agent_binding_ref, toolkit_instance_id, credential_ref, target_ref, subject_ref)`` tuples
        or dicts. At most 64 of each (``ValueError`` beyond that or for a malformed one). Retired references and
        revoked grants are not returned. Returns::

            {"references": {configuration_id: {ref_id, state, generation, configuration_generation, store_kind,
                                               ownership_class, revocation_epoch,
                                               custodian_user_id}},
             "grants": {"<key joined with |>": {grant_id, state, subject_kind, revocation_epoch, valid_from,
                                                 valid_until, operations}}}

        References are keyed by configuration id whichever selector found them. Times are ISO-8601 strings.

        ``grants_for`` (optional, at most 64): grant keys in the same form as ``grant_keys``, answered in the same
        session as the references, for the callers that learn the reference only from this call. The credential of a
        key is either a reference id (then it is exactly ``grant_keys``) or an integer: the id of a configuration
        among ``config_ids`` (or of a reference found by ``ref_ids``), meaning the reference this call resolved for it,
        the caller's own personal one first. The grant is returned under the key string built with that reference's
        id (``grant_key_string((binding, toolkit, references[config]["ref_id"], target, subject))``); a configuration
        with no reference has no grant. One ``db.get_session`` per call, whatever the number of selectors.

        A configuration can have a shared reference and personal ones (one per owner). ``ref_ids`` return exactly
        those references. ``config_ids`` return the personal reference whose custodian is the caller
        (``personal_subject_ref`` = ``idp:<tenant>:<object>``, or ``personal_user_id``), else the non-personal one,
        else (so the class can be refused by name) another owner's personal reference. ``custodian_subject_ref`` is the
        owner's subject of a personal reference.

        ``subject_grants`` (optional, at most 64, #7213): ``(credential, subject_ref)`` pairs, the credential a reference
        id or the id of a configuration this call resolves (as in ``grants_for``). The answer gains a third key,
        ``"subject_grants": {"<ref_id>|<subject_ref>": [grant, ...]}``: the ``active`` grants that subject holds on that
        reference whatever their binding and toolkit (each as in ``grants`` plus ``agent_binding_ref`` and
        ``toolkit_instance_id``), at most ``MAX_SUBJECT_GRANT_ROWS`` rows for the whole call, oldest first (ties in any order); a pair with
        none is absent. Whether a grant is in force (its validity window) is for the caller to decide, as for ``grants``.
        """
        _caller_subject(personal_subject_ref, personal_user_id)
        configs = [int(item) for item in _bounded("config_ids", config_ids)]
        refs = [_uuid(item) for item in _bounded("ref_ids", ref_ids)]
        keys = {_key(item) for item in _bounded("grant_keys", grant_keys)}
        later = [_grant_for(item) for item in _bounded("grants_for", grants_for)]
        by_subject = [_subject_grant(item) for item in _bounded("subject_grants", subject_grants)]
        references, grants, held = {}, {}, {}
        with db.get_session(project_id) as session:
            if refs:
                for row in session.execute(select(CredentialReference).where(
                        CredentialReference.project_id == project_id, CredentialReference.state != "retired",
                        CredentialReference.id.in_(refs))).scalars():
                    references[row.configuration_id] = _present(row)
            wanted = [item for item in configs if item not in references]
            if wanted:
                references.update(_references_of_configurations(
                    session, project_id, wanted, personal_subject_ref, personal_user_id))
            for binding, toolkit, credential, target, subject in later:  # the reference is known now
                if isinstance(credential, int):
                    found_ref = references.get(credential)
                    if found_ref is None:
                        continue
                    credential = found_ref["ref_id"]
                keys.add((binding, toolkit, str(credential), target, subject))
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
                        grants[grant_key_string(found)] = _grant_facts(row)
            pairs = set()
            for credential, subject in by_subject:   # the reference is known now
                if isinstance(credential, int):
                    found_ref = references.get(credential)
                    if found_ref is None:
                        continue
                    credential = found_ref["ref_id"]
                pairs.add((str(credential), subject))
            if pairs:
                for row in session.execute(select(CredentialUseGrant).where(
                        CredentialUseGrant.project_id == project_id, CredentialUseGrant.state == "active",
                        CredentialUseGrant.credential_ref.in_([_uuid(pair[0]) for pair in pairs]),
                        CredentialUseGrant.subject_ref.in_({pair[1] for pair in pairs}))
                        .order_by(CredentialUseGrant.created_at, CredentialUseGrant.id)
                        .limit(MAX_SUBJECT_GRANT_ROWS)).scalars():
                    pair = (str(row.credential_ref), row.subject_ref)
                    if pair in pairs:  # the IN lists are a superset of the pairs asked for
                        held.setdefault("|".join(pair), []).append({
                            **_grant_facts(row), "agent_binding_ref": str(row.agent_binding_ref),
                            "toolkit_instance_id": row.toolkit_instance_id})
        result = {"references": references, "grants": grants}
        if subject_grants is not None:
            result["subject_grants"] = held
        return result
