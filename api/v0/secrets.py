from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth, this


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @auth.decorators.check_api(["configuration.secrets.secret.view"])
    def get(self, project_id: int) -> Tuple[list, int]:  # pylint: disable=R0201,C0111
        # Check project_id for validity
        project = self.module.context.rpc_manager.call.project_get_or_404(project_id)
        vault_client = VaultClient.from_project(project)
        # Get secrets
        secrets_dict = vault_client.get_secrets()
        #
        all_secrets = vault_client.get_all_secrets()
        #
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)
        #
        resp = []
        for key in secrets_dict.keys():
            if ignore_default_secret_api and key in default_keys:
                continue
            #
            resp.append({"name": key, "secret": "******"})
        # for k, v in vault_client.get_project_hidden_secrets().items(): # todo: remove
        #     resp.append({"name": f'!_HIDDEN_{k}', "secret": v}) # todo: remove
        return resp, 200

    @auth.decorators.check_api(["configuration.secrets.secret.create"])
    def post(self, project_id: int) -> Tuple[dict, int]:  # pylint: disable=C0111
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        #
        # Check project_id for validity
        project = self.module.context.rpc_manager.call.project_get_or_404(project_id)
        vault_client = VaultClient.from_project(project)
        #
        all_secrets = vault_client.get_all_secrets()
        #
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)
        #
        for key in default_keys:
            if ignore_default_secret_api and key in request.json["secrets"]:
                return {'message': 'Default secrets API disabled'}, 400
        # Set secrets
        vault_client.set_secrets(request.json["secrets"])
        return {"message": f"Project secrets were saved"}, 200


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @auth.decorators.check_api(["configuration.secrets.secret.view"])
    def get(self, project_id: int) -> Tuple[list, int]:  # pylint: disable=R0201,C0111
        # Get secrets
        vault_client = VaultClient()
        secrets_dict = vault_client.get_secrets()
        resp = []
        for key in secrets_dict.keys():
            resp.append({"name": key, "secret": "******"})
        return resp, 200

    @auth.decorators.check_api(["configuration.secrets.secret.create"])
    def post(self, project_id: int) -> Tuple[dict, int]:  # pylint: disable=C0111
        # Set secrets
        vault_client = VaultClient()
        vault_client.set_secrets(request.json["secrets"])
        return {"message": f"Project secrets were saved"}, 200


class API(api_tools.APIBase):
    url_params = [
        '<string:project_id>',
        '<string:mode>/<string:project_id>',
    ]

    mode_handlers = {
        'default': ProjectAPI,
        'administration': AdminAPI,
    }
