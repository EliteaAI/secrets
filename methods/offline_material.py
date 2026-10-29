"""In-process store adapter of a person's offline delegated consent, for elitea_core's autonomous mandates (#7131)."""
from pylon.core.tools import web

from ..utils import credential_offline_material as offline_material


class Method:
    @web.method()
    def keep_offline_material(  # pylint: disable=R0913
        self, project_id: int, *, holder_ref: str, custodian_user_id: int, custodian_subject_ref: str, source: str,
        refresh_token, actor_user_id: int,
    ) -> dict:
        """Keep the refresh token a person consented with (``SecretStr``) for ``holder_ref`` (``mandate:<uuid>``):
        ``{"ok": True, "material_ref", "generation"}`` or ``{"ok": False, "reason_code"}``. Only the custodian keeps
        their own. The value is never logged, audited or returned."""
        return offline_material.keep(
            project_id, holder_ref=holder_ref, custodian_user_id=custodian_user_id,
            custodian_subject_ref=custodian_subject_ref, source=source, refresh_token=refresh_token,
            actor_user_id=actor_user_id)

    @web.method()
    def release_offline_material(  # pylint: disable=R0913
        self, project_id: int, material_ref: str, *, holder_ref: str, custodian_subject_ref: str, release_id: str,
        actor_ref: str,
    ) -> dict:
        """The refresh token of an active material, for its own holder and custodian only: ``{"ok": True,
        "refresh_token": SecretStr, "source", "generation"}`` or ``{"ok": False, "reason_code"}``. The caller has
        decided and audits the use. Do not put the value in a result, a task meta or an event."""
        return offline_material.release(
            project_id, material_ref, holder_ref=holder_ref, custodian_subject_ref=custodian_subject_ref,
            release_id=release_id, actor_ref=actor_ref)

    @web.method()
    def rotate_offline_material(  # pylint: disable=R0913
        self, project_id: int, material_ref: str, *, expected_generation: int, refresh_token, caller_ref: str,
    ) -> dict:
        """Keep a rotated refresh token as the next generation: ``{"ok": True, "generation"}`` or ``{"ok": False,
        "reason_code"}``."""
        return offline_material.rotate(
            project_id, material_ref, expected_generation=expected_generation, refresh_token=refresh_token,
            caller_ref=caller_ref)

    @web.method()
    def retire_offline_material(
        self, project_id: int, material_ref: str, *, reason: str, caller_ref: str, actor_user_id=None,
    ) -> dict:
        """Make a material unreleasable from now and delete its store copy: ``{"ok": True, "retired"}`` or
        ``{"ok": False, "reason_code"}``. ``reason``: one of ``credential_offline_material.RETIRED_REASONS``."""
        return offline_material.retire(
            project_id, material_ref, reason=reason, caller_ref=caller_ref, actor_user_id=actor_user_id)
