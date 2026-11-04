""" Method """

from pylon.core.tools import web  # pylint: disable=E0611,E0401


class Method:  # pylint: disable=E1101,R0903
    """ Method Resource """

    @web.method()
    def file_credential_requests(self, session, project_id, items, actor_user_id):
        """ Same process (elitea_core's batch request, #7269): file a member's personal references and use grants in
        ``session`` (the batch's, whose commit is a flush). ``[{key, id}]``, or ``CredentialTaskError`` (``code``,
        ``key``) with the batch to roll back. """
        from ..utils.credential_requests import file_requests  # pylint: disable=C0415
        #
        return file_requests(session, project_id, items, actor_user_id)

    @web.method()
    def revoke_binding_grants(self, session, project_id, binding_id, actor_user_id, reason="BINDING_RETIRED"):
        """ Same process (elitea_core's binding retirement and revival, #7228): revoke the binding's live grants in
        ``session`` (the caller's transaction), each audited. The count, or ``CredentialTaskError`` with the caller to
        roll back. """
        from ..utils.credential_grants import revoke_binding_grants  # pylint: disable=C0415
        #
        return revoke_binding_grants(session, project_id, binding_id, actor_user_id, reason)
