"""Credential use grants of a project: list and create (#7119, C-1009). Users are named by id."""
from tools import api_tools, auth, config as c, register_openapi

from ...models.credential_governance import GRANT_STATES
from ...utils import credential_api as api, credential_queries as queries


_PROJECT = {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."}


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="List Credential Grants (Admin)",
        description="List the credential use grants of a project, optionally for one user. Search matches "
                    "the subject or the approval reference.",
        parameters=[_PROJECT, *api.list_parameters(
            queries.GRANT_SORTS,
            ("state", "string", GRANT_STATES), ("agent_binding_ref", "string", None),
            ("credential_ref", "string", None), ("toolkit_id", "integer", None), ("subject_user_id", "integer", None))],
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.VIEW], "recommended_roles": api.VIEW_ROLES})
    def get(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.list_grants, project_id)

    @register_openapi(
        name="Create Credential Grant (Admin)",
        description="Let an agent binding use a credential reference, for one toolkit and one user. The grant "
                    "starts pending and needs approval by another operator.",
        parameters=[_PROJECT],
        request_body=api.GrantCreate,
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.MANAGE], "recommended_roles": api.OPERATE_ROLES})
    def post(self, project_id: int, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.create_grant, project_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>'])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
