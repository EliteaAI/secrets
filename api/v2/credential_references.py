"""Credential references of a project: list and create (#7119, C-1009). Metadata only, never the store locator."""
from tools import api_tools, auth, config as c, register_openapi

from ...models.credential_governance import OWNERSHIP_CLASSES, REFERENCE_STATES, STORE_KINDS
from ...utils import credential_api as api, credential_queries as queries


_PROJECT = {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."}


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="List Credential References (Admin)",
        description="List the credential references of a project with their state, owner and approval.",
        parameters=[_PROJECT, *api.list_parameters(
            queries.REFERENCE_SORTS,
            ("state", "string", REFERENCE_STATES), ("ownership_class", "string", OWNERSHIP_CLASSES),
            ("store_kind", "string", STORE_KINDS), ("owner_user_id", "integer", None))],
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.VIEW], "recommended_roles": api.VIEW_ROLES})
    def get(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(api.list_references, project_id)

    @register_openapi(
        name="Create Credential Reference (Admin)",
        description="Register a credential of the project for governed use. The reference starts pending; its "
                    "secret is imported afterwards, on the server.",
        parameters=[_PROJECT],
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.MANAGE], "recommended_roles": api.OPERATE_ROLES})
    def post(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(api.create_reference, project_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>'])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
