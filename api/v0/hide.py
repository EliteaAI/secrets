from typing import Tuple

from tools import api_tools, VaultClient, auth


class ProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api(["configuration.secrets.secret.edit"])
    def post(self, project_id: int, secret: str) -> Tuple[dict, int]:
        # Check project_id for validity
        project = self.module.context.rpc_manager.call.project_get_or_404(project_id)
        # Set secret
        vault_client = VaultClient.from_project(project_id)
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
