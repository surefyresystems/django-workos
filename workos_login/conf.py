from typing import Optional

from django.conf import settings


class Settings:
    """
    Shadow Django's settings with defaults
    """
    @property
    def WORKOS_CLIENT_ID(self) -> str:
        return getattr(settings, "WORKOS_CLIENT_ID", None)

    @property
    def WORKOS_API_KEY(self) -> str:
        return getattr(settings, "WORKOS_API_KEY", None)

    @property
    def WORKOS_EMAIL_LOOKUP(self) -> bool:
        """Lookup based on email address - the application must enforce lowercase unique emails if this is True"""
        return getattr(settings, "WORKOS_EMAIL_LOOKUP", False)

    @property
    def WORKOS_USERNAME_LOOKUP(self) -> bool:
        """Lookup based on username"""
        return getattr(settings, "WORKOS_USERNAME_LOOKUP", True)

    @property
    def WORKOS_METHOD_EMAIL(self) -> str:
        return "username"

    @property
    def WORKOS_METHOD_SSO(self) -> str:
        return "sso"

    @property
    def WORKOS_METHOD_GOOGLE_OAUTH(self) -> str:
        return "GoogleOAuth"

    @property
    def WORKOS_METHOD_MICROSOFT_OAUTH(self) -> str:
        return "MicrosoftOAuth"

    @property
    def WORKOS_METHOD_MFA(self) -> str:
        return "mfa"

    @property
    def WORKOS_METHOD_EMAIL_MFA(self) -> str:
        return "email_mfa"

    @property
    def WORKOS_METHOD_MAGIC(self) -> str:
        return "magic"

    @property
    def WORKOS_SSO_REDIRECT_URI(self) -> Optional[str]:
        return getattr(settings, "WORKOS_SSO_REDIRECT_URI", None)

    @property
    def WORKOS_MAGIC_REDIRECT_URI(self) -> Optional[str]:
        return getattr(settings, "WORKOS_MAGIC_REDIRECT_URI", None)

    @property
    def MFA_TOTP_TYPE(self) -> str:
        return "totp"

    @property
    def MFA_SMS_TYPE(self) -> str:
        return "sms"

    @property
    def WORKOS_SMS_MFA_TEMPLATE(self) -> str:
        return getattr(settings, "WORKOS_SMS_MFA_TEMPLATE", "Your authentication code is {{code}}")

    @property
    def WORKOS_SEND_CUSTOM_EMAIL(self) -> bool:
        return getattr(settings, 'WORKOS_SEND_CUSTOM_EMAIL', False)

    @property
    def WORKOS_EXTRA_STATE(self) -> dict:
        return getattr(settings, 'WORKOS_EXTRA_STATE', {})

    @property
    def WORKOS_AUTO_UPDATE(self) -> bool:
        return getattr(settings, 'WORKOS_AUTO_UPDATE', True)

    @property
    def WORKOS_JIT_USERNAME(self) -> bool:
        # Available methods are 'email', 'idp_id', 'id'
        return getattr(settings, 'WORKOS_JIT_USERNAME', 'email')

    @property
    def WORKOS_ACTIVE_USER_FILTER(self) -> dict:
        return getattr(settings, 'WORKOS_ACTIVE_USER_FILTER', {"is_active": True})


conf = Settings()
