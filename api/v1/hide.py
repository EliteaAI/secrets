from typing import Tuple

from tools import api_tools, VaultClient, auth, config as c
from ..v0.hide import AdminAPI


class ProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.hide"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def post(self, project_id: int, secret: str) -> Tuple[dict, int]:
        vault_client = VaultClient.from_project(project_id)
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
