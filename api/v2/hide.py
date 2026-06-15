from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth, config as c, register_openapi, this
from ..v0.hide import AdminAPI


class ProjectAPI(api_tools.APIModeHandler):
    @register_openapi(
        name="Hide Secret",
        description="Move a project secret from regular secrets to hidden secrets.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "string"},
             "description": "Project identifier."},
            {"name": "secret", "in": "path", "schema": {"type": "string"},
             "description": "Secret name to hide."},
        ],
        available_to_users=True,
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.hide"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def post(self, project_id: int, secret: str) -> Tuple[dict, int]:
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        #
        vault_client = VaultClient.from_project(project_id)
        #
        all_secrets = vault_client.get_all_secrets()
        #
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)
        #
        if ignore_default_secret_api and secret in default_keys:
            return {'message': 'Default secrets API disabled'}, 400
        #
        secrets = vault_client.get_secrets()
        hidden_secrets = vault_client.get_project_hidden_secrets()
        try:
            hidden_secrets[secret] = secrets.pop(secret)
        except KeyError:
            return {"message": "Project secret was not found"}, 400

        vault_client.set_secrets(secrets)
        vault_client.set_hidden_secrets(hidden_secrets)
        return {"message": "Project secret was moved to hidden secrets"}, 200


class API(api_tools.APIBase):
    url_params = api_tools.with_modes([
        '<string:project_id>/<string:secret>',
    ])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
