"""Entra-delegated credential references (#6756, C-1009 step 4): a container with no value.

An ``entra_delegated`` reference stores no secret, no refresh token and no token. It is a descriptor of how a token is
obtained at release, on behalf of the person who runs the agent (OAuth 2.0 on-behalf-of, done by ``elitea_core``):
which app to exchange through (``oauth_app_id``: ``"platform"`` or an admin-managed OAuth app, #7149), the tenant, the
resource and the scopes, and where the person's assertion comes from. The site stays the configuration's own field.

The descriptor lives in the reference's ``capabilities["delegation"]`` and never changes (a new descriptor is a new
reference). It is validated strictly: only these keys, only these shapes, so nothing secret-shaped can ride in it.
"""
import re
import uuid

from tools import auth, this

from .credential_errors import CredentialTaskError

AUTH_MODE = "entra_delegated"
STATIC_AUTH_MODE = "static_secret"
AUTH_MODES = (STATIC_AUTH_MODE, AUTH_MODE)
CAPABILITY_KEY = "delegation"
PROVIDERS = frozenset({"sharepoint"})
PLATFORM_APP = "platform"
GRAPH_RESOURCE = "https://graph.microsoft.com"
ASSERTION_SOURCES = ("login", "connected_account")
DESCRIPTOR_KEYS = frozenset({"oauth_app_id", "tenant_id", "resource", "scopes", "assertion_source"})
MAX_SCOPES = 16
DEFAULT_SCOPE = f"{GRAPH_RESOURCE}/.default"
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SCOPE = re.compile(r"^https://graph\.microsoft\.com/(\.default|[A-Za-z][A-Za-z.]{0,63})$")


def is_delegated(ref) -> bool:
    return getattr(ref, "auth_mode", None) == AUTH_MODE


def parse_descriptor(value) -> dict:
    """The descriptor in its canonical shape, or ``CredentialTaskError("INVALID_DESCRIPTOR")`` for anything else: an
    unknown or missing key, a value of another shape (a client id or secret, a token, a URL of another host)."""
    if not isinstance(value, dict) or set(value) != DESCRIPTOR_KEYS:
        raise CredentialTaskError("INVALID_DESCRIPTOR")
    app_id, tenant, resource = value["oauth_app_id"], value["tenant_id"], value["resource"]
    scopes, source = value["scopes"], value["assertion_source"]
    if not isinstance(app_id, str) or (app_id != PLATFORM_APP and not _canonical_uuid(app_id)):
        raise CredentialTaskError("INVALID_DESCRIPTOR")
    if not isinstance(tenant, str) or not _GUID.match(tenant.lower()):
        raise CredentialTaskError("INVALID_DESCRIPTOR")
    if resource != GRAPH_RESOURCE or source not in ASSERTION_SOURCES:
        raise CredentialTaskError("INVALID_DESCRIPTOR")
    if not isinstance(scopes, list) or not 1 <= len(scopes) <= MAX_SCOPES or \
            not all(isinstance(scope, str) and _SCOPE.match(scope) for scope in scopes):
        raise CredentialTaskError("INVALID_DESCRIPTOR")
    if DEFAULT_SCOPE in scopes and len(set(scopes)) > 1:
        raise CredentialTaskError("INVALID_DESCRIPTOR")   # Entra refuses .default next to named scopes
    return {"oauth_app_id": app_id, "tenant_id": tenant.lower(), "resource": resource,
            "scopes": sorted(set(scopes)), "assertion_source": source}


def _canonical_uuid(value) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def descriptor_of(ref) -> dict:
    """The stored descriptor of a delegated reference (re-validated: a row is not trusted to be well formed)."""
    capabilities = getattr(ref, "capabilities", None)
    return parse_descriptor((capabilities or {}).get(CAPABILITY_KEY) if isinstance(capabilities, dict) else None)


def require_container(bundle_reader) -> None:
    """A delegated reference governs a configuration that holds no secret value: ``bundle_reader()`` (the
    configuration's secret bundle) must answer ``NO_SECRET_FIELDS``. Anything it finds is ``DELEGATED_SECRET_PRESENT``."""
    try:
        bundle = bundle_reader()
    except CredentialTaskError as exc:
        if exc.code == "NO_SECRET_FIELDS":
            return
        raise
    if bundle is not None and (bundle.get("fields") or {}):
        raise CredentialTaskError("DELEGATED_SECRET_PRESENT")


def require_app(project_id, descriptor) -> None:
    """The descriptor's app resolves now (elitea_core's seam: the platform client, or an admin-managed app of #7149);
    a descriptor that could never be exchanged is not stored. ``OAUTH_APP_UNAVAILABLE`` otherwise."""
    try:
        available = this.for_module("elitea_core").module.entra_delegated_app_available(project_id, descriptor)
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    if available is not True:
        raise CredentialTaskError("OAUTH_APP_UNAVAILABLE")


def person_of(user_id) -> dict:
    """``{issuer, tid, oid}`` of a platform user, from the identity service (never from a caller)."""
    try:
        user = auth.get_user(user_id=user_id)
    except Exception:  # pylint: disable=W0703
        raise CredentialTaskError("DEPENDENCY_UNAVAILABLE") from None
    user = user if isinstance(user, dict) else {}
    person = {"issuer": user.get("idp_issuer"), "tid": user.get("idp_tid"), "oid": user.get("idp_oid")}
    if not (person["tid"] and person["oid"]):
        raise CredentialTaskError("SUBJECT_UNLINKED")
    return person


def probe(ref, user_id) -> None:
    """Can ``user_id`` obtain a token through this reference now? One exchange by ``elitea_core`` (which keeps the
    outcome a minute and never the token). Raises ``CredentialTaskError("DELEGATION_PROBE_FAILED")`` naming nothing
    more: the refusal code of the exchange is in the audit event the caller writes."""
    person = person_of(user_id)
    delegation = {**descriptor_of(ref), "ownership_class": ref.ownership_class,
                  "custodian_subject_ref": (ref.custodian_ref or {}).get("subject_ref")
                  if isinstance(ref.custodian_ref, dict) else None}
    try:
        code = this.for_module("elitea_core").module.entra_delegated_probe(
            ref.project_id, str(ref.id), delegation, person)
    except Exception:  # pylint: disable=W0703
        code = "DEPENDENCY_UNAVAILABLE"
    if code is not None:
        error = CredentialTaskError("DELEGATION_PROBE_FAILED")
        error.reason = code if isinstance(code, str) and re.fullmatch(r"[A-Z0-9_]{1,64}", code) else "DEPENDENCY_UNAVAILABLE"
        raise error


class DelegatedValue:  # pylint: disable=R0903
    """What a release answers for a delegated reference instead of a ``SecretValue``: the generation and the descriptor
    with the custody facts the exchange binds to. It holds nothing secret."""

    __slots__ = ("generation", "delegation")

    def __init__(self, ref):
        self.generation = ref.generation
        custodian = ref.custodian_ref if isinstance(ref.custodian_ref, dict) else {}
        self.delegation = {**descriptor_of(ref), "ownership_class": ref.ownership_class,
                           "custodian_subject_ref": custodian.get("subject_ref")}

    def __repr__(self):
        return f"DelegatedValue(generation={self.generation})"
