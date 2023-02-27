from django.contrib.auth.forms import AuthenticationForm, UsernameField, PasswordResetForm, SetPasswordForm
from django import forms
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _
from workos.exceptions import BadRequestException, ServerException

from workos_login.conf import conf
from django.core.exceptions import ValidationError
import workos

from workos_login.models import LoginRule
from workos_login.utils import find_user, verify_challenge, totp_verify_code, user_has_mfa_enabled


class BootstrapMixin:

    def __init__(self, *args, **kwargs):
        kwargs["label_suffix"] = ""
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs["class"] = "form-control"

    def _post_clean(self):
        for name, field in self.fields.items():
            class_list = ["form-control"]
            if(field.get_bound_field(self, name).errors):
                class_list.append("is-invalid")
            field.widget.attrs["class"] = " ".join(class_list)


class LoginForm(BootstrapMixin, AuthenticationForm):

    username = UsernameField(label=_("Username"), widget=forms.TextInput(attrs={"autofocus": True}))
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        required=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    def __init__(self, *args, **kwargs):
        self.rule_cache = None
        super(LoginForm, self).__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["class"] = "form-control"
        if conf.WORKOS_EMAIL_LOOKUP:
            self.fields["username"].label = _("Username or Email")


    def get_rule(self):
        return self.rule_cache

    def clean(self):
        rule = LoginRule.objects.find_rule_for_username(self.cleaned_data["username"])
        if not rule:
            # No rule for user - cannot login
            # there should always be at least one rule
            raise self.get_invalid_login_error()
        self.rule_cache = rule

        try:
            user = find_user(self.cleaned_data.get("username"))
        except ObjectDoesNotExist:
            user = None

        if rule.requires_password or (user and user_has_mfa_enabled(user)):
            # Even if the rule doesn't require a password but the user has mfa enabled, that will take precedence.
            # MFA is always checked before magic email and will be respected to require MFA.
            if not self.cleaned_data.get("password"):
                raise self.get_invalid_login_error()
            return super().clean()

        self.user_cache = user

        if rule.magic_link:
            if not user:
                raise self.get_invalid_login_error()
            self.confirm_login_allowed(user)
        if rule.sso:
            # Make sure that there is either an active user or that there is a JIT
            if not rule.sso:
                raise self.get_invalid_login_error()
            if not rule.jit_creation_type:
                if not user:
                    raise self.get_invalid_login_error()
                self.confirm_login_allowed(user)

        return self.cleaned_data


class MFAVerificationForm(BootstrapMixin, forms.Form):
    """
    Used to verify an already enrolled MFA user.
    """
    code = forms.CharField(required=True, widget=forms.TextInput(attrs={"autofocus": True}))
    challenge_id = forms.CharField(widget=forms.HiddenInput(), required=True)

    def clean(self):
        challenge_id = self.cleaned_data["challenge_id"]
        challenge_code = self.cleaned_data["code"]
        if not verify_challenge(challenge_id, challenge_code):
            self.add_error("code", ValidationError(_("Verification failed - please try again"), code="invalid_code"))

        return self.cleaned_data


class MFAEnrollFormSMS(BootstrapMixin, forms.Form):
    """Used to set a new enrollment"""
    phone_number = forms.CharField(required=True, help_text="Enter the phone number you would like to use "
                                                            "to receive your text message authentication codes")

    def __init__(self, *args, **kwargs):
        self.response_id = None
        super(MFAEnrollFormSMS, self).__init__(*args, **kwargs)
        
    def clean_phone_number(self):
        try:
            response = workos.client.mfa.enroll_factor(type=conf.MFA_SMS_TYPE, phone_number=self.cleaned_data["phone_number"])
        except BadRequestException as e:
            try:
                message = e.message
            except AttributeError:
                message = "Error, please try again"
            raise ValidationError(message)
        except ServerException:
            message = _("Unknown error, please try again")
            raise ValidationError(message)
        
        self.response_id = response["id"]
        
    def complete_enrollment(self, user):
        return self.response_id


class MFAEnrollFormTOTP(BootstrapMixin, forms.Form):
    """Used to set a new enrollment"""
    factor_id = forms.CharField(required=True, widget=forms.HiddenInput())
    code = forms.CharField(required=True, widget=forms.TextInput(attrs={"autofocus": True}))

    def clean(self):
        if not totp_verify_code(self.cleaned_data["factor_id"], self.cleaned_data["code"]):
            self.add_error("code", ValidationError(_("Verification failed - please try again")))

    def complete_enrollment(self, user):
        return self.cleaned_data["factor_id"]


class WorkosPasswordResetForm(BootstrapMixin, PasswordResetForm):
    pass


class WorkosSetPasswordForm(BootstrapMixin, SetPasswordForm):
    pass
