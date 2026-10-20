"""Lifecycle actions on a credential use grant (#7119, C-1009): the admin task's actions over REST."""
from tools import api_tools, auth, config as c, register_openapi

from ...utils import credential_api as api



class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Act on Credential Grant (Admin)",
        description="Approve, suspend, resume or revoke a credential use grant. Approve needs credentials.approve "
                    "(another operator than the creator), the rest credentials.manage.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."},
            {"name": "grant_id", "in": "path", "schema": {"type": "string", "format": "uuid"},
             "description": "Credential use grant identifier."},
        ],
        request_body=api.GrantAction,
        mcp_tool=False,
        available_to_users=False,
    )
    # Any of the two opens the endpoint; the action then needs the one permission it names
    @auth.decorators.check_api({"permissions": [api.MANAGE, api.APPROVE], "recommended_roles": api.OPERATE_ROLES})
    def post(self, project_id: int, grant_id, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.grant_action, project_id, grant_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>/<uuid:grant_id>'])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
