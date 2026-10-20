"""Lifecycle actions on a credential reference (#7119, C-1009): the admin task's actions over REST."""
from tools import api_tools, auth, config as c, register_openapi

from ...utils import credential_api as api



class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Act on Credential Reference (Admin)",
        description="Import, probe, approve, activate, suspend, resume or retire a credential reference. "
                    "Each action needs its own permission: probe credentials.probe, approve credentials.approve, "
                    "the rest credentials.manage. The creator of a reference cannot approve it.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."},
            {"name": "ref_id", "in": "path", "schema": {"type": "string", "format": "uuid"},
             "description": "Credential reference identifier."},
        ],
        request_body=api.ReferenceAction,
        mcp_tool=False,
        available_to_users=False,
    )
    # Any of the three opens the endpoint; the action then needs the one permission it names
    @auth.decorators.check_api({"permissions": [api.MANAGE, api.PROBE, api.APPROVE],
                                "recommended_roles": api.OPERATE_ROLES})
    def post(self, project_id: int, ref_id, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.reference_action, project_id, ref_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>/<uuid:ref_id>'])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
