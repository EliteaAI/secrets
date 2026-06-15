from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth, this


class ProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api(["configuration.secrets.secret.edit"])
    def post(self, project_id: int, secret: str) -> Tuple[dict, int]:
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        #
        # Check project_id for validity
        project = self.module.context.rpc_manager.call.project_get_or_404(project_id)
        vault_client = VaultClient.from_project(project_id)
        #
        all_secrets = vault_client.get_all_secrets()
        #
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)
        #
        if ignore_default_secret_api and secret in default_keys:
            return {'message': 'Default secrets API disabled'}, 400
        # Set secret
        secrets = vault_client.get_secrets()
        hidden_secrets = vault_client.get_project_hidden_secrets()
        try:
            hidden_secrets[secret] = secrets[secret]
        except KeyError:
            return {"message": "Project secret was not found"}, 404
        secrets.pop(secret, None)
        vault_client.set_secrets(secrets)
        vault_client.set_hidden_secrets(hidden_secrets)
        return {"message": "Project secret was moved to hidden secrets"}, 200


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api(["configuration.secrets.secret.edit"])
    def post(self, project_id: int, secret: str) -> Tuple[dict, int]:
        return {"message": "There are no hidden secrets in administration mode"}, 401


class API(api_tools.APIBase):
    url_params = [
        '<string:project_id>/<string:secret>',
        '<string:mode>/<string:project_id>/<string:secret>',
    ]

    mode_handlers = {
        'default': ProjectAPI,
        'administration': AdminAPI,
    }
# from pylon.core.tools import log
# log.info('API HIDE s')
