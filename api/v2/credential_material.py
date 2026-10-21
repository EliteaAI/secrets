"""The value of a personal credential reference: write-only (#7119, C-1009).

A personal value is set by its owner and by no one else (administrators included): the administration route is open to
``credentials.manage`` or ``credentials.set_own_value`` and answers ``OWNER_ONLY`` (403) to anyone but the owner; the
default-mode route is the one the main UI calls for the owner. There is a ``PUT`` and nothing else: no ``GET``, so the value cannot be read back through the API. The body is bounded
before it is parsed, the values become ``SecretStr`` when it is, and the reply is the new generation and state only. The
tracing plugin does not capture the body of this path (``/api/v2/secrets/credential_material/``).
"""
from tools import api_tools, auth, config as c, register_openapi

from ...utils import credential_api as api


_PARAMETERS = [
    {"name": "project_id", "in": "path", "schema": {"type": "integer"}, "description": "Project identifier."},
    {"name": "ref_id", "in": "path", "schema": {"type": "string", "format": "uuid"},
     "description": "Credential reference identifier."},
]
_OWNER_ONLY = ("Only the owner of the personal credential can set its value (403 OWNER_ONLY for anyone else, "
               "administrators included); the owner needs the credentials.set_own_value permission, not "
               "credentials.manage. ")


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Write Personal Credential Value (Admin)",
        description=_OWNER_ONLY + "Write the value of a personal credential reference, replacing any earlier value as a new "
                    "generation (a pending, validated or suspended reference takes one). Write-only: the value is "
                    "never returned, logged or audited. The names must be the secret fields of the configuration's "
                    "type: at least one, and no other (a type with alternative ways to authenticate takes the ones "
                    "the credential uses); at most 32 fields of at most 8 KiB each, and a body of at most 32 KiB. The "
                    "reference goes back to pending: the new value has to be probed and approved again, by someone "
                    "other than its creator and the one who wrote it.",
        parameters=_PARAMETERS,
        request_body=api.MaterialBody,
        mcp_tool=False,
        available_to_users=False,
    )
    # Either opens the endpoint; the handler then asks for the owner (a personal reference) or for manage (any other)
    @auth.decorators.check_api({"permissions": [api.MANAGE, api.SET_OWN_VALUE],
                                "recommended_roles": api.OPERATE_ROLES})
    def put(self, project_id: int, ref_id, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.put_material, project_id, ref_id)


class ProjectAPI(api_tools.APIModeHandler):  # pylint: disable=C0111
    @register_openapi(
        name="Write My Personal Credential Value",
        description=_OWNER_ONLY + "Same body and replies as the administration route: the fields of the credential's "
                    "type (at least one, no others; at most 32 of at most 8 KiB each, a body of at most 32 KiB) and the "
                    "generation last seen. Write-only: the value is never returned, logged or audited. The reference "
                    "goes back to pending: an operator probes and approves the new value.",
        parameters=_PARAMETERS,
        request_body=api.MaterialBody,
        mcp_tool=False,
        available_to_users=False,
    )
    @auth.decorators.check_api({"permissions": [api.SET_OWN_VALUE], "recommended_roles": api.OWN_VALUE_ROLES})
    def put(self, project_id: int, ref_id, **kwargs):  # pylint: disable=C0111
        return api.respond(self.module, api.put_material, project_id, ref_id, False)


class API(api_tools.APIBase):  # pylint: disable=R0903,C0111
    url_params = api_tools.with_modes(['<int:project_id>/<uuid:ref_id>'])

    mode_handlers = {
        c.DEFAULT_MODE: ProjectAPI,
        c.ADMINISTRATION_MODE: AdminAPI,
    }
