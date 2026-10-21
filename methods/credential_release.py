"""In-process release of credential material for the trusted resolver (#6946, C-1009)."""
from pylon.core.tools import web

from ..utils.credential_release import release_material


class Method:
    @web.method()
    def release_credential_material(  # pylint: disable=R0913
        self, project_id: int, ref_id: str, generation: int, release_id: str, actor_ref: str,
        allow_validated: bool = False, allow_pending: bool = False,
    ) -> dict:
        """The material of one credential reference at one generation, for a run or a probe that was admitted.

        Called in-process by the admission layer after it decided and before it audited the release; it does not
        decide. ``release_id`` becomes the store ``decision_id`` (the Vault ``X-Correlation-Id``), ``actor_ref``
        is the caller's identity for the store. ``allow_validated`` widens the allowed reference states from
        ``active`` to ``validated|active`` (a probe of saved material precedes activation); ``allow_pending`` also admits ``pending`` (the onboarding
        probe of a personal value, before it is validated). ``ValueError`` for a
        malformed request. Returns::

            {"ok": True, "value": SecretValue}                  # fields: name -> SecretStr, generation
            {"ok": False, "reason_code": CREDENTIAL_REFERENCE_INACTIVE | CREDENTIAL_GENERATION_MISMATCH
                                         | STORE_DENIED|SEALED|UNAVAILABLE|TLS_INVALID|NOT_FOUND
                                         | DEPENDENCY_UNAVAILABLE}

        The value is never logged, audited or kept here; do not put it in a result, a task meta or an event.
        """
        return release_material(
            project_id, ref_id, generation, release_id, actor_ref, allow_validated=allow_validated,
            allow_pending=allow_pending)
