"""Operator-task failures of credential governance (#6757, C-1009): a stable code and a fixed message.

Store failures keep their own ``STORE_*`` codes (``StoreError.audit_code``). Nothing here takes a
value from the caller, so a message can never carry a path, a secret or a store answer.
"""
MESSAGES = {
    "ACTOR_REQUIRED": "This action needs an identified operator.",
    "SELF_APPROVAL": "The creator of a record cannot approve it.",
    "APPROVAL_REQUIRED": "Approval needs an approval reference and a policy revision.",
    "INVALID_STATE": "The record is not in a state this action can start from.",
    "CONCURRENT_CHANGE": "The record changed while this ran; read it again and retry.",
    "REFERENCE_NOT_FOUND": "No such credential reference in this project.",
    "REFERENCE_EXISTS": "A live credential reference already exists for this configuration.",
    "GRANT_NOT_FOUND": "No such credential use grant in this project.",
    "GRANT_EXISTS": "This credential use grant already exists.",
    "CONFIGURATION_NOT_FOUND": "The configuration does not exist in this project.",
    "CONFIGURATION_CHANGED": "The configuration changed since its material was imported; import it again.",
    "CONFIGURATION_NOT_ELIGIBLE": "Only credentials of this project can be registered for governed use.",
    "BINDING_NOT_FOUND": "No such agent identity binding in this project.",
    "TOOLKIT_NOT_IN_BINDING": "The toolkit does not belong to the binding's agent version.",
    "IMPORT_IN_FLIGHT": "An import is in flight or was interrupted; run reconcile_credential_store first.",
    "NO_SECRET_FIELDS": "The configuration has no secret fields to import.",
    "SECRET_UNRESOLVED": "A secret field of the configuration could not be resolved.",
    "MATERIAL_MISMATCH": "The stored material does not match the configuration.",
    "UNSUPPORTED_STORE_KIND": "This store kind cannot be used for credential references.",
    "UNSUPPORTED_OWNERSHIP_CLASS": "This ownership class cannot be registered for governed use.",
    "DEPENDENCY_UNAVAILABLE": "A required service is unavailable; nothing was changed.",
}


class CredentialTaskError(Exception):
    """A refused or failed operator action. ``result()`` is what the admin task returns."""

    def __init__(self, code: str):
        self.code = code
        self.message = MESSAGES[code]
        super().__init__(self.message)

    def result(self) -> dict:
        return {"error": f"{self.code}: {self.message}", "code": self.code}


def store_error_result(exc) -> dict:
    """Result for a ``StoreError``: its ``STORE_*`` code and fixed message."""
    return {"error": f"{exc.audit_code}: {exc.message}", "code": exc.audit_code}


def require_actor(actor_user_id) -> int:
    """The executing operator's user id; anything else (0, None, a bool, text) is refused."""
    if isinstance(actor_user_id, bool) or not isinstance(actor_user_id, int) or actor_user_id <= 0:
        raise CredentialTaskError("ACTOR_REQUIRED")
    return actor_user_id
