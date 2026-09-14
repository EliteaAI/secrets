from urllib.parse import unquote

from typing import Optional, Tuple
from flask import request

from pylon.core.tools import log

from tools import api_tools, VaultClient, auth, config as c, register_openapi, this

from ...pd.secrets import SecretDetail

_PATH_PARAMS = [
    {"name": "project_id", "in": "path", "schema": {"type": "string"},
     "description": "Calling project identifier. Used for permission checks and audit only;"
                    " the secret is always read from the caller's own personal project."},
    {"name": "secret", "in": "path", "schema": {"type": "string"},
     "description": "Secret name (URL-encoded if it contains special chars)."},
]


def _resolve_caller_id(project_id: int) -> Optional[int]:
    """ Identify the user the request acts on behalf of """
    received_session = request.headers.get("X-USERSESSION", None)
    #
    if received_session and received_session != '-':
        # Acting-as-user is only honored for callers that proved themselves with X-SECRET
        vault_client = VaultClient.from_project(project_id)
        all_secrets = vault_client.get_all_secrets()
        if "secrets_header_value" not in all_secrets or \
                request.headers.get("X-SECRET", None) != all_secrets["secrets_header_value"]:
            return None
        #
        session_context = auth.get_referenced_auth_context(received_session)
        if not session_context:
            return None
        return session_context.get("user_id")
    #
    return auth.current_user().get("id")


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Get Private Project Secret",
        description="Get a secret from the calling user's own personal project."
                    " Only secrets the owner explicitly marked as externally accessible are returned.",
        parameters=_PATH_PARAMS,
        available_to_users=True,
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.unsecret"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int, secret: str) -> Tuple[dict, int]:  # pylint: disable=R0201,C0111
        secret = unquote(secret)
        #
        user_id = _resolve_caller_id(project_id)
        if user_id is None:
            log.info(
                'Private secret denied: project=%s secret=%s outcome=unidentified_caller',
                project_id, secret,
            )
            return {"error": "unidentified_caller"}, 401
        #
        personal_project_id = self.module.context.rpc_manager.call.projects_get_personal_project_id(
            user_id=user_id,
        )
        if personal_project_id is None:
            log.info(
                'Private secret denied: user=%s project=%s secret=%s outcome=no_personal_project',
                user_id, project_id, secret,
            )
            return {"error": "no_personal_project"}, 404
        #
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        # Unlike the regular secret endpoints, a valid X-SECRET does not lift this guard:
        # platform-injected secrets must stay unreachable from a shared-project code node.
        if secret in default_keys and elitea_core_config.get("ignore_default_secret_api", False):
            log.info(
                'Private secret denied: user=%s project=%s secret=%s outcome=default_secret',
                user_id, project_id, secret,
            )
            return {"error": "default_secret"}, 400
        #
        vault_client = VaultClient.from_project(personal_project_id)
        #
        # Checked before existence so the endpoint can't be used to enumerate a user's secrets
        if not vault_client.get_external_access().get(secret, False):
            log.info(
                'Private secret denied: user=%s project=%s secret=%s outcome=not_shared',
                user_id, project_id, secret,
            )
            return {"error": "not_shared"}, 403
        #
        result = SecretDetail(name=secret)
        result.allow_external_access = True
        #
        secrets = vault_client.get_secrets()
        if secret in secrets:
            result.value = secrets[secret]
        else:
            hidden_secrets = vault_client.get_project_hidden_secrets()
            if secret not in hidden_secrets:
                log.info(
                    'Private secret denied: user=%s project=%s secret=%s outcome=not_found',
                    user_id, project_id, secret,
                )
                return {"error": "not_found"}, 404
            result.value = hidden_secrets[secret]
            result.is_hidden = True
        #
        log.info(
            'Private secret granted: user=%s project=%s secret=%s has_value=%s',
            user_id, project_id, secret, bool(result.value),
        )
        result.value = result.value or ""
        return result.dict(), 200


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @auth.decorators.check_api(["configuration.secrets.secret.view"])
    def get(self, project_id: int, secret: str) -> Tuple[dict, int]:  # pylint: disable=R0201,C0111
        return {"error": "no_personal_project"}, 401


class API(api_tools.APIBase):
    url_params = api_tools.with_modes([
        '<string:project_id>/<string:secret>',
    ])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
