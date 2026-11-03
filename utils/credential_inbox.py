"""The project inbox's escalation for credential references and use grants (#7269, C-1009).

The same rule as elitea_core's ``utils/governance_inbox.py`` (which also reads the project's admins): a waiting row
whose four-eyes rule leaves no project admin to approve it (a reference: its creator and whoever wrote its value; a grant:
its creator) "needs a platform operator". A reference waits while it is pending or validated and not approved yet; a
grant while it is ``pending_approval``. Nothing is stored.
"""
from sqlalchemy import and_, false, or_

from ..models.credential_governance import CredentialReference as _REF, CredentialUseGrant as _GRANT

REFERENCE_WAITING = ("pending", "validated")


def escalated(admins, *excluded) -> bool:
    """No project admin may approve a row whose four-eyes rule excludes ``excluded``."""
    return not set(admins) - {user_id for user_id in excluded if user_id}


def _clause(admins, waiting, *columns):
    admins = sorted(admins)
    if len(admins) > len(columns):
        return false()
    return and_(waiting, *[or_(*[column == admin for column in columns]) for admin in admins])


def reference_waiting(state, approved_by) -> bool:
    return state in REFERENCE_WAITING and approved_by is None


def reference_clause(admins):
    return _clause(admins, and_(_REF.state.in_(REFERENCE_WAITING), _REF.approved_by.is_(None)),
                   _REF.created_by, _REF.written_by)


def grant_clause(admins):
    return _clause(admins, _GRANT.state == "pending_approval", _GRANT.created_by)
