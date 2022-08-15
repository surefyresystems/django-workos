from typing import Optional

from django.conf import settings
from collections.abc import Callable
from django.db import models
from django.urls import reverse


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
    def WORKOS_METHOD_EMAIL(self):
        return "username"

    @property
    def WORKOS_METHOD_SSO(self):
        return "sso"

    @property
    def WORKOS_METHOD_GOOGLE_OAUTH(self):
        return "GoogleOAuth"

    @property
    def WORKOS_METHOD_MICROSOFT_OAUTH(self):
        return "MicrosoftOAuth"

    @property
    def WORKOS_METHOD_MFA(self):
        return "mfa"

    @property
    def WORKOS_METHOD_MAGIC(self):
        return "magic"

    @property
    def WORKOS_SSO_REDIRECT_URI(self):
        return reverse("sso_callback")

    @property
    def WORKOS_MAGIC_REDIRECT_URI(self):
        return reverse("magic_callback")

    @property
    def MFA_TOTP_TYPE(self):
        return "totp"

    @property
    def MFA_SMS_TYPE(self):
        return "sms"

    @property
    def WORKOS_SMS_MFA_TEMPLATE(self):
        return getattr(settings, "WORKOS_SMS_MFA_TEMPLATE", "Your authentication code is {{code}}")

    @property
    def WORKOS_SEND_CUSTOM_EMAIL(self):
        return getattr(settings, 'WORKOS_SEND_CUSTOM_EMAIL', False)


conf = Settings()
