from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth


class ProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api(["configuration.secrets.secret.delete"])
    def post(self, project_id: int) -> Tuple[dict, int]:
        project = self.module.context.rpc_manager.call.project_get_or_404(project_id)
        vault_client = VaultClient.from_project(project)
        data = request.json
        secrets = vault_client.get_secrets()
        for secret in data.get('secrets', []):
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
