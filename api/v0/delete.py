from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth, this


class ProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api(["configuration.secrets.secret.delete"])
    def post(self, project_id: int) -> Tuple[dict, int]:
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        #
        project = self.module.context.rpc_manager.call.project_get_or_404(project_id)
        vault_client = VaultClient.from_project(project)
        #
        all_secrets = vault_client.get_all_secrets()
        #
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)
        #
        data = request.json
        secrets = vault_client.get_secrets()
        for secret in data.get('secrets', []):
            if ignore_default_secret_api and secret in default_keys:
                continue
            #
            try:
                del secrets[secret]
            except KeyError:
                ...
        vault_client.set_secrets(secrets)
        return {"message": "deleted"}, 204


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api(["configuration.secrets.secret.delete"])
    def post(self, **kwargs) -> Tuple[dict, int]:
        data = request.json
        vault_client = VaultClient()
        secrets = vault_client.get_secrets()
        for secret in data.get('secrets', []):
            try:
                del secrets[secret]
            except KeyError:
                ...
        vault_client.set_secrets(secrets)
        return {"message": "deleted"}, 204


class API(api_tools.APIBase):
    url_params = [
        '<string:project_id>',
        '<string:mode>/<string:project_id>',
    ]

    mode_handlers = {
        'default': ProjectAPI,
        'administration': AdminAPI,
    }

# from pylon.core.tools import log
# log.info('API DELETE s')
