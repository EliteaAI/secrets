#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Module """
from threading import Thread

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401
from tools import auth, this  # pylint: disable=E0401

# Credential governance (#6757, C-1009): admin task name -> Method attribute, all in the R-2.0.8 group
CREDENTIAL_ADMIN_TASKS = (
    "create_credential_governance_tables",
    "manage_credential_reference",
    "manage_credential_grant",
    "reconcile_credential_store",
    "credential_store_smoke",
)


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        self._register_openapi()

    def _register_openapi(self):
        """Register API endpoints with OpenAPI registry."""
        try:
            from tools import openapi_registry  # pylint: disable=E0401,C0415
            from .api import v2 as api_v2
            openapi_registry.register_plugin(
                plugin_name="secrets",
                version=self.descriptor.metadata.get("version", "1.0.0"),
                description="Secrets management — create, read, update, delete, and hide project secrets.",
                tags=[
                    {
                        "name": "secrets",
                        "description": "Secrets management for projects.",
                    },
                ],
                api_module=api_v2,
            )
        except Exception as e:  # pylint: disable=W0703
            log.warning("Failed to register OpenAPI for secrets plugin: %s", e)

    def init(self):
        """ Init module """
        log.info("Initializing module Secrets")
        # Imported so create_all sees the credential governance tables
        from .models import credential_governance  # pylint: disable=C0415,W0611
        #
        self.descriptor.init_methods()
        self.descriptor.init_api()
        self.descriptor.init_rpcs()
        self.descriptor.init_blueprint()

        auth.register_permissions({
            "permissions": ["configuration.secrets"],
            "recommended_roles": {
                "administration": {"admin": True, "viewer": False, "editor": False},
                "default": {"admin": True, "viewer": False, "editor": False},
            }
        })

        # Credential governance (#6757, C-1009). Registered whatever the governance flag says, so roles can
        # be assigned before it is switched on. Only credentials.use is evaluated by the admission layer;
        # reveal exists for a later governed reveal and is recommended to nobody, and no route reads it.
        # view, manage, probe and approve are what the operator REST API (#7119) checks, in administration mode.
        from .utils import credential_api  # pylint: disable=C0415
        for permission, roles in (
                (credential_api.VIEW, credential_api.VIEW_ROLES),
                (credential_api.MANAGE, credential_api.OPERATE_ROLES),
                (credential_api.PROBE, credential_api.OPERATE_ROLES),
                (credential_api.APPROVE, credential_api.OPERATE_ROLES),
                (credential_api.SET_OWN_VALUE, credential_api.OWN_VALUE_ROLES),
                ("credentials.use", {
                    "administration": {"admin": True, "viewer": False, "editor": False},
                    "default": {"admin": True, "viewer": True, "editor": True}}),
                ("credentials.reveal", {  # recommended to nobody (explicitly: the role model defaults system/super_admin to True)
                    "administration": {"admin": False, "viewer": False, "editor": False, "system": False, "super_admin": False},
                    "default": {"admin": False, "viewer": False, "editor": False, "system": False, "super_admin": False}}),
        ):
            auth.register_permissions({"permissions": [permission], "recommended_roles": roles})

        self.descriptor.init_slots()

    def ready(self):
        """ Module is ready """
        self._register_admin_tasks()
        self._ensure_credential_schema()

    @staticmethod
    def _wrap_admin_task(method_cls, method_name, module_instance):
        """Plain function wrapper that keeps the docstring: the admin UI unwraps pylon's partial of a
        @web.method() down to the module instance and would lose it."""
        original = getattr(method_cls, method_name)

        def wrapper(*args, **kwargs):
            return original(module_instance, *args, **kwargs)

        wrapper.__doc__ = original.__doc__
        wrapper.__name__ = method_name
        return wrapper

    def _register_admin_tasks(self):
        try:
            from .methods.admin_tasks import Method  # pylint: disable=C0415
            self._admin_tasks = {}
            for name in CREDENTIAL_ADMIN_TASKS:
                task = self._wrap_admin_task(Method, name, self)
                this.for_module("admin").module.register_admin_task(name, task, group="R-2.0.8")
                self._admin_tasks[name] = task
        except Exception as e:  # pylint: disable=W0703
            log.exception("Failed to register credential admin tasks: %s", e)

    def _unregister_admin_tasks(self):
        try:
            for name, task in getattr(self, "_admin_tasks", {}).items():
                this.for_module("admin").module.unregister_admin_task(name, task)
        except Exception as e:  # pylint: disable=W0703
            log.exception("Failed to unregister credential admin tasks: %s", e)

    def _ensure_credential_schema(self):
        """Startup safety net: create the credential governance tables in any project schema that predates
        them (#6757). Runs off-thread; guarded by a catalog check so steady-state boots issue no DDL.
        New projects are already covered by create_all."""
        def _run():
            try:
                from .utils.credential_schema import (  # pylint: disable=C0415
                    apply_credential_tables, apply_grant_subject_user_id, apply_written_by,
                    project_ids_missing_credential_tables, project_ids_missing_grant_subject_user_id,
                    project_ids_missing_written_by,
                )
                pending = project_ids_missing_credential_tables()
                if pending:
                    log.info("credential governance schema: auto-migrating %s project(s)", len(pending))
                    migrated, failed = apply_credential_tables(pending)
                    log.info(
                        "credential governance schema: auto-migration done (migrated=%s failed=%s)",
                        len(migrated), len(failed),
                    )
                # the model reads written_by (#7119); adding the column is additive, the index swap is the task's
                unwritten = project_ids_missing_written_by()
                if unwritten:
                    migrated, failed = apply_written_by(unwritten)
                    log.info("credential governance schema: written_by added (migrated=%s failed=%s)",
                             len(migrated), len(failed))
                # the model reads credential_use_grant.subject_user_id too (grant_subject_user_id step)
                ungranted = project_ids_missing_grant_subject_user_id()
                if ungranted:
                    migrated, failed = apply_grant_subject_user_id(ungranted)
                    log.info("credential governance schema: subject_user_id added (migrated=%s failed=%s)",
                             len(migrated), len(failed))
            except Exception:  # pylint: disable=W0703
                log.exception("credential governance schema: auto-migration failed")

        Thread(target=_run, daemon=True).start()

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module Secrets")
        self._unregister_admin_tasks()
