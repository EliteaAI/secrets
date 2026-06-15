from typing import Tuple, List
from flask import request

from tools import api_tools, VaultClient, auth, config as c, this

from pydantic.v1 import ValidationError
from ...pd.secrets import SecretList, SecretCreate
from ..v0.secrets import AdminAPI


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.list"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int) -> Tuple[list, int]:  # pylint: disable=R0201,C0111
        vault_client = VaultClient.from_project(project_id)
        secrets_dict = vault_client.get_secrets()
        #
        all_secrets = vault_client.get_all_secrets()
        #
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)
        #
        result = []
        #
        for i in secrets_dict.keys():
            if ignore_default_secret_api and i in default_keys:
                continue
            #
            result.append(SecretList(name=i).dict())
        #
        return result, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.create"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def post(self, project_id: int) -> Tuple[dict | list, int]:  # pylint: disable=C0111
        try:
            parsed = SecretCreate.parse_obj(dict(request.json))
        except ValidationError as e:
            return e.errors(), 400

        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        #
        vault_client = VaultClient.from_project(project_id)
        all_secrets = vault_client.get_all_secrets()
        #
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)

        if ignore_default_secret_api and parsed.name in default_keys:
            return {'error': 'Default secrets API disabled'}, 400

        secrets = vault_client.get_secrets()

        if parsed.name in secrets:
            return {'error': f'Secret "{parsed.name}" already exists'}, 400

        secrets[parsed.name] = parsed.value
        vault_client.set_secrets(secrets)
        return SecretList(name=parsed.name).dict(), 201


class API(api_tools.APIBase):
    url_params = api_tools.with_modes([
        '<string:project_id>',
    ])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
