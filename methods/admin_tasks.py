"""Admin tasks of credential governance (R-2.0.8, #6757, C-1009).

Registered by ``module.py``; results never contain secret material, a store locator or a path.
"""
from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401


class Method:
    """Admin task bodies"""

    @web.method()
    def create_credential_governance_tables(self, *args, **kwargs):
        """Admin task: create the credential governance tables in each project schema (R-2.0.8, #6757, C-1009).

        Creates ``credential_reference``, ``credential_use_grant`` and ``credential_store_ledger`` where they
        are missing. New projects get them from ``create_all`` and a startup guard covers the rest, so this is
        the operator's way to report (dry run) and re-run. Idempotent; schemas that have all three are left alone.

        Second step, ``personal_index`` (#7119): in projects whose tables predate personal credential references,
        swaps the single live-reference unique index for two partial ones (one live non-personal reference per
        configuration; one personal reference per owner of a configuration) and adds ``written_by`` (the startup
        guard adds that column too). Until it has run in a project, creating a personal reference there is refused
        (``MIGRATION_REQUIRED``). Each project waits at most 5 s for its table; one that is busy fails alone and the
        step is repeated. It is reported under ``personal_index`` (``migrated`` = would swap, on a dry run).

        Param format (required):
            "project_id=<all|N>[;dry_run]"

        Examples:
            "project_id=all;dry_run"  - report which projects lack the tables (``migrated`` = would create)
            "project_id=all"          - create them everywhere they are missing
            "project_id=3"            - project 3 only
        """
        from ..utils.credential_schema import (  # pylint: disable=C0415
            apply_credential_tables, apply_personal_index, parse_project_param, project_ids_missing_credential_tables,
            project_ids_missing_personal_index, target_project_ids,
        )

        project_id_filter, dry_run, error = parse_project_param(kwargs.get("param", "") or "")
        if error:
            log.error("create_credential_governance_tables: %s", error)
            return {"migrated": 0, "error": error}
        try:
            project_ids = target_project_ids(self, project_id_filter)
            missing = set(project_ids_missing_credential_tables())
        except Exception:  # pylint: disable=W0703
            log.exception("create_credential_governance_tables: failed to list projects")
            return {"migrated": 0, "error": "failed to list projects"}
        migrated, failed = apply_credential_tables([pid for pid in project_ids if pid in missing], dry_run=dry_run)
        try:   # projects that just got their tables have the new indexes already
            pending = project_ids_missing_personal_index([pid for pid in project_ids if pid not in missing])
        except Exception:  # pylint: disable=W0703
            log.exception("create_credential_governance_tables: failed to read the indexes")
            return {"migrated": len(migrated), "failed": len(failed), "failed_projects": failed, "dry_run": dry_run,
                    "error": "failed to read the indexes"}
        index_migrated, index_failed = apply_personal_index(pending, dry_run=dry_run)
        log.info(
            "%screate_credential_governance_tables: migrated=%s failed=%s personal_index migrated=%s failed=%s",
            "[DRY RUN] " if dry_run else "", len(migrated), len(failed), len(index_migrated), len(index_failed),
        )
        return {"migrated": len(migrated), "failed": len(failed), "failed_projects": failed, "dry_run": dry_run,
                "personal_index": {"migrated": len(index_migrated), "failed": len(index_failed),
                                   "failed_projects": index_failed}}

    @web.method()
    def manage_credential_reference(self, *args, **kwargs):
        """Admin task: register a stored secret for governed use and move it through its lifecycle (R-2.0.8, #6757, C-1009).

        Works with credential governance off, so references can be prepared before it is switched on. Each
        change is audited in the same transaction. The secret is copied server-side from the configuration it
        governs into the store; it is never a parameter. The configuration's own copy stays until the release
        path moves to the store, so do not onboard a production credential into corporate Vault before that.
        The creator of a reference cannot approve it.

        Param format (required):
            "project_id=N;action=<a>;configuration_uuid=U;store_kind=<k>;ownership_class=<o>" (create)
            "project_id=N;action=<a>;ref=R[;approval_ref=...;policy_revision=...][;dry_run]" (others)

        Actions: create (pending), import (copy the material, one generation per import), probe (compare the
        stored material with the configuration), approve (needs approval_ref and policy_revision; another
        operator than the creator), activate, suspend, resume, retire (deletes the stored material).
        Store kinds: database, corporate_vault. Ownership classes: project_shared, service, technical, personal.

        A personal reference needs owner_user_id (a member of the project; their identity-provider subject is
        resolved on the server) and a project updated by create_credential_governance_tables (personal_index). It
        has no import: its value is written through the write-only credential_material endpoint. Its probe checks
        the store; add check_connection to also test the stored value against its provider.

        Examples:
            "project_id=3;action=create;configuration_uuid=<uuid>;store_kind=database;ownership_class=project_shared"
            "project_id=3;action=approve;ref=<uuid>;approval_ref=CHG-12;policy_revision=2026-10-1"
        """
        from ..utils.credential_onboarding import manage_reference  # pylint: disable=C0415

        result = manage_reference(kwargs.get("param", "") or "", kwargs.get("_executing_user_id") or 0)
        log.info("manage_credential_reference: %s", result)
        return result

    @web.method()
    def manage_credential_grant(self, *args, **kwargs):
        """Admin task: let an agent binding use a credential reference for one user (R-2.0.8, #6757, C-1009).

        A grant names the binding, the toolkit of the binding's agent version, the reference and the user
        (``idp:<tenant>:<object>``). It starts pending and becomes active when another operator than its
        creator approves it. Works with governance off.

        Param format (required):
            "project_id=N;action=<a>;binding_ref=B;toolkit_id=T;ref=R;subject_ref=idp:<tenant>:<object>
             [;valid_until=<ISO-8601 with offset>][;approval_ref=...;policy_revision=...][;dry_run]"

        Actions: create, approve (needs approval_ref and policy_revision), suspend, resume, revoke.
        valid_until applies to create only.

        Examples:
            "project_id=3;action=create;binding_ref=<uuid>;toolkit_id=41;ref=<uuid>;subject_ref=idp:t1:u1"
            "project_id=3;action=approve;binding_ref=<uuid>;toolkit_id=41;ref=<uuid>;subject_ref=idp:t1:u1;approval_ref=CHG-13;policy_revision=2026-10-1"
        """
        from ..utils.credential_grants import manage_grant  # pylint: disable=C0415

        result = manage_grant(kwargs.get("param", "") or "", kwargs.get("_executing_user_id") or 0)
        log.info("manage_credential_grant: %s", result)
        return result

    @web.method()
    def reconcile_credential_store(self, *args, **kwargs):
        """Admin task: settle store writes and deletes that were interrupted (R-2.0.8, #6757, C-1009).

        For each ledger row left in intent or written longer than older_than_s ago: a staged generation that
        reached the store is committed, one that did not is released, and the material of a retired or missing
        reference is deleted. The material of a live reference is never deleted. Run it after a restart or a
        store outage, and when an import reports IMPORT_IN_FLIGHT (use older_than_s=0 to include rows just
        written). No periodic job runs it yet.

        Param format (required):
            "project_id=<all|N>[;older_than_s=300][;dry_run]"

        Examples:
            "project_id=all;dry_run"  - count the rows that would be settled (``candidates``)
            "project_id=3;older_than_s=0"
        """
        from ..utils.credential_reconcile import reconcile_store  # pylint: disable=C0415

        result = reconcile_store(self, kwargs.get("param", "") or "", kwargs.get("_executing_user_id") or 0)
        log.info("reconcile_credential_store: %s", result)
        return result

    @web.method()
    def credential_store_smoke(self, *args, **kwargs):
        """Admin task: check the corporate Vault policy shape the credential store relies on (R-2.0.8, #6757, C-1009).

        Reads the shared canary, then confirms that listing the credential path, reading another tenant's
        path and writing without check-and-set are all refused. Nothing is written. Needs the corporate Vault
        settings of the platform.

        Param format (required):
            "store_kind=corporate_vault[;dry_run]"
        """
        from ..utils.credential_reconcile import run_store_smoke  # pylint: disable=C0415

        result = run_store_smoke(kwargs.get("param", "") or "", kwargs.get("_executing_user_id") or 0)
        log.info("credential_store_smoke: %s", result)
        return result
