from typing import Tuple, List
from flask import request

from tools import api_tools, VaultClient, auth, config as c, this, register_openapi

from pydantic.v1 import ValidationError
from ...pd.secrets import SecretList, SecretCreate


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="List Secrets",
        description="List all secret names for a project (values are not returned).",
        mcp_tool=True,
        mcp_description="Use this tool when you need to see what project secrets exist, build secret-reference dropdowns, or determine whether a secret key is present before reading or updating it. Do not use this tool when you need the actual secret value — use Get Secret for that. Do not use this endpoint to create or modify secrets. This is the safest read endpoint in the secrets API because it exposes names and metadata only, not values.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "string"},
             "description": "Project identifier."},
        ],
        available_to_users=True,
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.secrets.secret.list"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": True},
            c.DEFAULT_MODE: {"admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int) -> Tuple[list, int]:  # pylint: disable=R0201,C0111
        # Get project secrets
        vault_client = VaultClient.from_project(project_id)
        secrets_dict = vault_client.get_secrets()
        all_secrets = vault_client.get_all_secrets()

        # Get default secret keys from elitea_core config
        elitea_core_config = this.for_module("elitea_core").descriptor.config
        default_keys = set(elitea_core_config.get("default_secret_keys", []))
        has_correct_secret_header = "secrets_header_value" in all_secrets and request.headers.get("X-SECRET", None) == all_secrets["secrets_header_value"]
        ignore_default_secret_api = not has_correct_secret_header and elitea_core_config.get("ignore_default_secret_api", False)

        external_access = vault_client.get_external_access()

        # Build response with is_default flag for each secret
        response = []
        for secret_name in secrets_dict.keys():
            if ignore_default_secret_api and secret_name in default_keys:
                continue
            #
            secret_data = SecretList(name=secret_name).dict()
            secret_data['is_default'] = secret_name in default_keys
            secret_data['allow_external_access'] = bool(external_access.get(secret_name, False))
            response.append(secret_data)

        return response, 200

    @register_openapi(
        name="Create Secret",
        description="Create a new project secret.",
        mcp_tool=True,
        mcp_description="Use this tool when you need to add a brand-new project secret, such as an API token, password, or integration credential that does not yet exist in the project. Do not use this tool to change an existing secret value — use Update Secret. Do not use it to inspect secret contents or list available keys. This is the correct endpoint for introducing new secret keys into the project's secret store so they can later be referenced via {{secret.NAME}}.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "string"},
             "description": "Project identifier."},
        ],
        request_body=SecretCreate,
        available_to_users=True,
    )
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
        if parsed.allow_external_access:
            vault_client.update_external_access(add={parsed.name: True})
        return SecretList(name=parsed.name).dict(), 201


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
    url_params = api_tools.with_modes([
        '<string:project_id>',
    ])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
