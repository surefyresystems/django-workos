from typing import Optional

from workos_login.models import LoginRule
from workos_login.utils import get_client


def get_portal_link(rule: LoginRule, return_url: Optional[str] = None, success_url: Optional[str] = None) -> str:
    """
    Generate a WorkOS Admin Portal link for a customer to self-configure their SAML connection.

    WorkOS Admin Portal links expire 5 minutes after generation, so this must be called
    immediately before redirecting the user - never cache or email the result.
    """
    portal_link = get_client(rule).admin_portal.generate_link(
        organization=rule.organization_id,
        intent="sso",
        return_url=return_url,
        success_url=success_url,
    )
    return portal_link.link


def get_connection_status(rule: LoginRule):
    """
    Fetch the live SAML connection for a LoginRule directly from WorkOS.

    Mirrors LoginRule.clean()'s "connection_id or organization_id, not both" constraint.
    Returns None if the rule has neither set yet (no connection configured).
    """
    client = get_client(rule)

    if rule.connection_id:
        return client.sso.get_connection(rule.connection_id)

    if rule.organization_id:
        connections = client.sso.list_connections(organization_id=rule.organization_id)
        if connections.data:
            return connections.data[0]

    return None
