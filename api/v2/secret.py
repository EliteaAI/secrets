from urllib.parse import unquote

from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth, config as c, register_openapi, this

from pydantic.v1 import ValidationError
from ...pd.secrets import SecretDetail, SecretUpdate, SecretList

_PATH_PARAMS = [
    {"name": "project_id", "in": "path", "schema": {"type": "string"},
     "description": "Project identifier."},
    {"name": "secret", "in": "path", "schema": {"type": "string"},
     "description": "Secret name (URL-encoded if it contains special chars)."},
]


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Get Secret",
        description="Get a secret value by name.",
        parameters=_PATH_PARAMS,
        available_to_users=True,
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.unsecret"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int, secret: str) -> Tuple[dict | None, int]:  # pylint: disable=R0201,C0111
        secret = unquote(secret)
        #
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
            return None, 400
        #
        if ignore_default_secret_api:
            result = SecretDetail(name=secret)
            result.value = ""
            return result.dict(), 200
        #
        secrets = vault_client.get_secrets()
        result = SecretDetail(name=secret)
        if secret in secrets:
            result.value = secrets[secret]
        else:
            hidden_secrets = vault_client.get_project_hidden_secrets()
            if secret not in hidden_secrets:
                return None, 404
            result.value = hidden_secrets[secret]
            result.is_hidden = True
        result.value = result.value or ""
        return result.dict(), 200

    @register_openapi(
        name="Update Secret",
        description="Update an existing secret's name and/or value.",
        parameters=_PATH_PARAMS,
        request_body=SecretUpdate,
        available_to_users=True,
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.edit"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def put(self, project_id: int, secret: str) -> Tuple[dict | list, int]:  # pylint: disable=C0111
        secret = unquote(secret)
        #
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
        raw = dict(request.json)
        raw['name'] = secret
        try:
            parsed = SecretUpdate.parse_obj(raw)
        except ValidationError as e:
            return e.errors(), 400

        secrets = vault_client.get_secrets()
        try:
            del secrets[secret]
        except KeyError:
            return {"message": f"Secret {secret} was not found"}, 400
        secrets[parsed.name] = parsed.value
        vault_client.set_secrets(secrets)
        return SecretList(name=parsed.name).dict(), 200

    @register_openapi(
        name="Delete Secret",
        description="Delete a secret by name.",
        parameters=_PATH_PARAMS,
        available_to_users=True,
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.delete"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def delete(self, project_id: int, secret: str) -> Tuple[None, int]:  # pylint: disable=C0111
        secret = unquote(secret)
        #
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
            return None, 400
        #
        secrets = vault_client.get_secrets()
        if secret in secrets:
            del secrets[secret]
        vault_client.set_secrets(secrets)
        return None, 204


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self, project_id: int, secret: str) -> Tuple[dict, int]:  # pylint: disable=R0201,C0111
        vault_client = VaultClient()
        # Get secret
        secrets = vault_client.get_secrets()
        # _secret = secrets.get(secret) or vault_client.get_project_hidden_secrets().get(secret)
        _secret = secrets.get(secret)
        return {"secret": _secret}, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.create"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def post(self, project_id: int, secret: str) -> Tuple[dict, int]:  # pylint: disable=C0111
        data = request.json
        # Set secret
        vault_client = VaultClient()
        secrets = vault_client.get_secrets()
        secrets[secret] = data["secret"]
        vault_client.set_secrets(secrets)
        return {"message": "Project secret was saved"}, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, project_id: int, secret: str) -> Tuple[dict, int]:  # pylint: disable=C0111
        data = request.json
        # Set secret
        vault_client = VaultClient()
        secrets = vault_client.get_secrets()
        try:
            del secrets[data['secret']['old_name']]
        except KeyError:
            return {"message": "Project secret was not found"}, 404
        secrets[secret] = data["secret"]['value']
        vault_client.set_secrets(secrets)
        return {"message": "Project secret was updated"}, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.delete"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def delete(self, project_id: int, secret: str) -> Tuple[dict, int]:  # pylint: disable=C0111
        vault_client = VaultClient()
        secrets = vault_client.get_secrets()
        if secret in secrets:
            del secrets[secret]
        vault_client.set_secrets(secrets)
        return {"message": "deleted"}, 204


class API(api_tools.APIBase):
    url_params = api_tools.with_modes([
        '<string:project_id>/<string:secret>'
    ])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
