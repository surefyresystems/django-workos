from enum import Enum
from typing import Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django import forms
from django.utils.translation import gettext_lazy as _
from workos.utils.connection_types import ConnectionType

from workos_login.conf import conf
import re

# Create your models here.
from workos_login.exceptions import UnknownUsernameFormat
from workos_login.utils import find_user, render_attribute, get_users


class EmailRegexField(models.TextField):

    def formfield(self, **kwargs):
        return super().formfield(widget=forms.TextInput)


class WorkosQuerySet(models.QuerySet):
    def find_rule_for_username(self, username_or_email: str) -> Optional["LoginRule"]:
        """Find a rule for a matching username"""
        for rule in self.all():
            if rule.rule_applies_to_username(username_or_email):
                return rule
        return None

    def find_rule_for_user(self, user: models.Model) -> Optional["LoginRule"]:
        """
        Find the applied rule for this user
        :param user: The user to test
        :return: The rule that applies - it will only return 1 rule at most.
        """
        for rule in self.all():
            if rule.rule_applies_to_user(user):
                return rule
        return None

    def find_rule_for_jit(self, email: str, connection_id: Optional[str], organization_id: Optional[str]) -> Optional["LoginRule"]:
        """Find a rule for a matching an email address
        This could return a rule that matches an email address even if JIT is not enabled and the user does not exist.
        This is used for IdP initiated logins to try and find a matching rule before associated to user or
        creating user (if JIT is enabled).
        """
        for rule in self.all():
            connection_match = (rule.organization_id == organization_id or rule.connection_id == connection_id)
            if rule.jit_creation_type == JitMethods.IDP and connection_match:
                return rule
            # For ATTRIBUTES_MATCH connection_match is not checked since it could be google or microsoft login.
            if rule.jit_creation_type == JitMethods.ATTRIBUTES_MATCH and rule.test_email(email):
                return rule

        return None


class LoginMethods(models.TextChoices):
    MFA = conf.WORKOS_METHOD_MFA, "MFA"
    EMAIL_MFA = conf.WORKOS_METHOD_EMAIL_MFA, "Email MFA"
    MAGIC_LINK = conf.WORKOS_METHOD_MAGIC, "Passwordless Email"
    GOOGLE_SSO = conf.WORKOS_METHOD_GOOGLE_OAUTH, "Google SSO"
    MICROSOFT_SSO = conf.WORKOS_METHOD_MICROSOFT_OAUTH, "Microsoft SSO"
    SAML_SSO = conf.WORKOS_METHOD_SSO, "SAML SSO"
    USERNAME = conf.WORKOS_METHOD_EMAIL, "Username/Password"

    @property
    def is_sso(self):
        return self == self.GOOGLE_SSO or self == self.MICROSOFT_SSO or self == self.SAML_SSO

    @property
    def frontend_method(self):
        return "sso" if self.is_sso else self

    @property
    def needs_con_or_org_id(self):
        return self == self.SAML_SSO

    @property
    def provider(self):
        if self == self.GOOGLE_SSO:
            return ConnectionType.GoogleOAuth
        if self == self.MICROSOFT_SSO:
            return ConnectionType.MicrosoftOAuth
        return None


class JitMethods(models.TextChoices):
    ATTRIBUTES_MATCH = "attributes", "Matching Attributes"
    IDP = "idp", "Matching Attributes or IdP login"

class LoginRule(models.Model):
    name = models.CharField(max_length=255, help_text=_("Name for this config"), unique=True)
    lookup_attributes = models.JSONField(blank=True, null=True)
    totp_organization_name = models.CharField(max_length=255, blank=True, help_text=_("The name of organization which "
                                                                                    "shows in authenticator apps."))
    method = models.CharField(choices=LoginMethods.choices, max_length=15)

    jit_creation_type = models.CharField(choices=JitMethods.choices, verbose_name=_("Just in time account creation type"),
                                         max_length=10, blank=True, help_text=_("If enabled a user account will be automatically created "
                                                   "if one does not exist."))
    priority = models.IntegerField(default=100, help_text=_("Priority of this rule. Lower numbers are checked first"),
                                   unique=True)
    email_regex = EmailRegexField(blank=True, help_text=_(r"Regex to test on email. Ex. ^.+@(domain|domain2)\.com$"),
                                  verbose_name="Email Regular Expression Pattern")
    connection_id = models.CharField(max_length=255, blank=True, help_text=_("WorkOS connection ID"))
    organization_id = models.CharField(max_length=255, blank=True, help_text=_("WorkOS organization ID"))

    # Need a way to set attributes like is_external to True when setting up JIT
    jit_groups = models.ManyToManyField("auth.Group", blank=True,
                                        help_text=_("Groups a user should be added to if user is being created."))

    saved_attributes = models.JSONField(blank=True, default=dict,
                                        help_text=_("Attributes to set on user instance when creating user. This is a Django template string that supports lookups like "
                                                    "{{profile.raw_attributes['some-extended-attribute']}}. <a target='_blank' href='https://workos.com/docs/reference/sso/profile'>Profile</a> is defined by WorkOS"))
    objects = WorkosQuerySet.as_manager()

    class Meta:
        ordering = ["priority"]

    def __str__(self):
        return self.name

    @property
    def sso(self) -> bool:
        return LoginMethods(self.method).is_sso

    @property
    def mfa(self) -> bool:
        return self.method == LoginMethods.MFA

    @property
    def magic_link(self) -> bool:
        return self.method == LoginMethods.MAGIC_LINK or self.method == LoginMethods.EMAIL_MFA

    @property
    def username(self) -> bool:
        return self.method == LoginMethods.USERNAME

    @property
    def requires_password(self) -> bool:
        return self.mfa or self.username or self.method == LoginMethods.EMAIL_MFA

    def clean(self):
        errors = {}

        if self.totp_organization_name and not self.mfa:
            errors["totp_organization_name"] = _("Organization name only valid for MFA")

        if self.mfa and not self.totp_organization_name:
            errors["totp_organization_name"] = _("Must set organization name if using MFA. This will appear on "
                                                 "authenticator apps")

        if self.organization_id and not self.sso:
            errors["organization_id"] = _("Organization ID is only used for SSO")

        if self.connection_id and not self.sso:
            errors["connection_id"] = _("Connection ID is only used for SSO")

        if self.connection_id and self.organization_id:
            raise ValidationError(_("You cannot set both an organization ID and connection ID"))

        if LoginMethods(self.method).needs_con_or_org_id and not (self.organization_id or self.connection_id):
            errors["connection_id"] = _("For SSO you must provide either connection ID or organization ID")
            errors["organization_id"] = _("For SSO you must provide either connection ID or organization ID")

        if not self.jit_creation_type and not self.lookup_attributes and not self.email_regex:
            errors["lookup_attributes"] = errors["email_regex"] = _("This rule does not apply to any users. "
                                                                    "Set lookup attributes or an email pattern.")

        if self.jit_creation_type and not self.sso:
            errors["jit_creation_type"] = _("You can only set account creation if using SSO")


        if self.saved_attributes and not self.sso:
            errors["saved_attributes"] = _("Custom attributes only apply to SSO login.")

        if errors:
            raise ValidationError(errors)

    def test_email(self, email: str) -> bool:
        if self.email_regex and re.search(self.email_regex, email, flags=re.IGNORECASE):
            return True
        return False

    def rule_applies_to_username(self, username_or_email: str) -> bool:
        """
        Given a username try to find the rule that applies
        :param username_or_email: A username or email to lookup
        :return: True if the rule applies False otherwise
        """
        # Check if a user exists
        user = find_user(username_or_email)
        if user:
            return self.rule_applies_to_user(user)

        if not self.jit_creation_type:
            return False

        if self.test_email(username_or_email):
            return True

        return False

    def rule_applies_to_user(self, user: models.Model):
        exists = False
        if self.lookup_attributes:
            # Check two special keys first "has_mfa" checks
            attrs = self.lookup_attributes
            has_mfa = attrs.pop("has_mfa", False)
            if has_mfa:
                exists = UserLogin.objects.filter(user=user).exclude(mfa_factor="").exists()

            has_sso = attrs.pop("has_sso", False)
            if has_sso and not exists:
                exists = UserLogin.objects.filter(user=user).exclude(sso_id="").exists()

            if not exists and attrs:
                exists = get_users().filter(**attrs).filter(pk=user.pk).exists()

        if not exists:
            # The user attributes do not match, check if email domain matches
            return self.test_email(user.email)

        return exists

    def format_username(self, profile: dict) -> str:
        if "username" in self.saved_attributes:
            return render_attribute(self.saved_attributes["username"], profile)

        if conf.WORKOS_JIT_USERNAME == "email":
            return profile["email"]
        if conf.WORKOS_JIT_USERNAME == "idp_id":
            return profile["idp_id"]
        if conf.WORKOS_JIT_USERNAME == "id":
            return profile["id"]
        raise UnknownUsernameFormat

class UserLogin(models.Model):
    """One-to-one link to a user that sets the ids needed for sso and mfa"""
    mfa_factor = models.CharField(max_length=255, blank=True)
    MFA_TYPE_CHOICES = (
        (conf.MFA_SMS_TYPE, "SMS"),
        (conf.MFA_TOTP_TYPE, "Authenticator App")
    )
    mfa_type = models.CharField(choices=MFA_TYPE_CHOICES, max_length=10, blank=True)
    sso_id = models.CharField(max_length=255, blank=True)
    idp_id = models.CharField(max_length=255, blank=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    # Rule associated with UserLogin - used for SSO particularly for being able to update saved_attributes
    rule = models.ForeignKey(LoginRule, blank=True, null=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.user)

    @property
    def mfa_enabled(self):
        return bool(self.mfa_type) and bool(self.mfa_factor)

    @property
    def is_sms(self):
        return self.mfa_type == conf.MFA_SMS_TYPE

    @property
    def is_totp(self):
        return self.mfa_type == conf.MFA_TOTP_TYPE

