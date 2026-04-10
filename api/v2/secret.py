from urllib.parse import unquote

from typing import Tuple
from flask import request

from tools import api_tools, VaultClient, auth, config as c

from pydantic.v1 import ValidationError
from ...pd.secrets import SecretDetail, SecretUpdate, SecretList
from ..v0.secret import AdminAPI


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.unsecret"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int, secret: str) -> Tuple[dict | None, int]:  # pylint: disable=R0201,C0111
        secret = unquote(secret)
        vault_client = VaultClient.from_project(project_id)
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

    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.edit"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def put(self, project_id: int, secret: str) -> Tuple[dict | list, int]:  # pylint: disable=C0111
        secret = unquote(secret)
        raw = dict(request.json)
        raw['name'] = secret
        try:
            parsed = SecretUpdate.parse_obj(raw)
        except ValidationError as e:
            return e.errors(), 400

        vault_client = VaultClient.from_project(project_id)
        secrets = vault_client.get_secrets()
        try:
            del secrets[secret]
        except KeyError:
            return {"message": f"Secret {secret} was not found"}, 400
        secrets[parsed.name] = parsed.value
        vault_client.set_secrets(secrets)
        return SecretList(name=parsed.name).dict(), 200

    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.delete"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def delete(self, project_id: int, secret: str) -> Tuple[None, int]:  # pylint: disable=C0111
        secret = unquote(secret)
        vault_client = VaultClient.from_project(project_id)
        secrets = vault_client.get_secrets()
        if secret in secrets:
            del secrets[secret]
        vault_client.set_secrets(secrets)
        return None, 204


class API(api_tools.APIBase):
    url_params = api_tools.with_modes([
        '<string:project_id>/<string:secret>'
    ])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
