"""One credential reference of a project (#7119, C-1009). Metadata only."""
from tools import api_tools, auth, config as c, register_openapi

from ...utils import credential_api as api



class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Get Credential Reference (Admin)",
        description="One credential reference with its number of live grants and whether a store write is in flight.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."},
            {"name": "ref_id", "in": "path", "schema": {"type": "string", "format": "uuid"},
             "description": "Credential reference identifier."},
        ],
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.VIEW], "recommended_roles": api.VIEW_ROLES})
    def get(self, project_id: int, ref_id, **kwargs):  # pylint: disable=C0111
        return api.respond(api.get_reference, project_id, ref_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>/<uuid:ref_id>'])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
