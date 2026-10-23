"""Credential references of a project: list and create (#7119, C-1009). Metadata only, never the store locator."""
from tools import api_tools, auth, config as c, register_openapi

from ...models.credential_governance import OWNERSHIP_CLASSES, REFERENCE_STATES, STORE_KINDS
from ...utils import credential_api as api, credential_queries as queries


_PROJECT = {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."}


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="List My Personal Credential References",
        description="The personal credential references of the project whose owner is the caller (`mine=true` is "
                    "required), for the owner's own Credentials page. Metadata only: state, generation and the "
                    "configuration; no operators, approvals or store details.",
        parameters=[_PROJECT, {"name": "mine", "in": "query", "required": True, "schema": {"type": "boolean"}},
                    *api.list_parameters(queries.REFERENCE_SORTS, ("state", "string", REFERENCE_STATES))],
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.SET_OWN_VALUE], "recommended_roles": api.OWN_VALUE_ROLES})
    def get(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.list_own_references, project_id)


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="List Credential References (Admin)",
        description="List the credential references of a project with their state, owner and approval. "
                    "Search matches the provider or the configuration title.",
        parameters=[_PROJECT, *api.list_parameters(
            queries.REFERENCE_SORTS,
            ("state", "string", REFERENCE_STATES), ("ownership_class", "string", OWNERSHIP_CLASSES),
            ("store_kind", "string", STORE_KINDS), ("owner_user_id", "integer", None))],
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.VIEW], "recommended_roles": api.VIEW_ROLES})
    def get(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.list_references, project_id)

    @register_openapi(
        name="Create Credential Reference (Admin)",
        description="Register a credential of the project for governed use. The reference starts pending; its "
                    "secret is imported afterwards, on the server. A personal reference (ownership_class personal, "
                    "with owner_user_id, a member of the project) stands beside the shared one and takes its value "
                    "through the write-only value endpoint. Once its owner has one, the owner's runs use it and no "
                    "other: while it is pending, validated or suspended they are refused, and they do not fall "
                    "back to the shared credential.",
        parameters=[_PROJECT],
        request_body=api.ReferenceCreate,
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.MANAGE], "recommended_roles": api.OPERATE_ROLES})
    def post(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.create_reference, project_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>'])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
