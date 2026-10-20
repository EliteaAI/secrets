"""The value of a personal credential reference: write-only (#7119, C-1009).

There is a ``PUT`` and nothing else: no ``GET``, so the value cannot be read back through the API. The body is bounded
before it is parsed, the values become ``SecretStr`` when it is, and the reply is the new generation and state only. The
tracing plugin does not capture the body of this path (``/api/v2/secrets/credential_material/``).
"""
from tools import api_tools, auth, config as c, register_openapi

from ...utils import credential_api as api


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Write Personal Credential Value (Admin)",
        description="Write the value of a personal credential reference, replacing any earlier value as a new "
                    "generation. Write-only: the value is never returned, logged or audited. The names must be secret "
                    "fields of the configuration's type, at most 32 fields, and the body at most 16 KiB. The reference "
                    "goes back to pending: the new value has to be probed and approved again.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."},
            {"name": "ref_id", "in": "path", "schema": {"type": "string", "format": "uuid"},
             "description": "Credential reference identifier."},
        ],
        request_body=api.MaterialBody,
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.MANAGE], "recommended_roles": api.OPERATE_ROLES})
    def put(self, project_id: int, ref_id, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.put_material, project_id, ref_id)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>/<uuid:ref_id>'])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
