from typing import Optional

from django.contrib import messages
from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import LoginView
from django.http import JsonResponse, Http404, HttpRequest
from django.shortcuts import redirect, resolve_url
from django.conf import settings
from django.urls import reverse
from django.views.decorators.http import require_GET
from django.contrib.auth import login as auth_login, get_user_model
from django.core import signing
from django.utils.translation import gettext_lazy as _

import workos

# Create your views here.
from django.views.generic import FormView, RedirectView, TemplateView

from workos_login.forms import LoginForm, MFAVerificationForm, MFAEnrollFormSMS, MFAEnrollFormTOTP
from workos_login.models import LoginRule, UserLogin, LoginMethods
from workos_login.conf import conf
from workos_login.signals import workos_user_created, workos_send_magic_link
from workos_login.utils import find_user, user_has_mfa_enabled, get_user_login_model, mfa_enroll, jit_create_user

SESSION_AUTHENTICATED_USER_ID = "workos_auth_user_id"  # Stores the authenticated user id (used by MFA)
SESSION_USER_ID = "workos_user_id"  # Store the user ID in SSO state.
STATE_USERNAME = "workos_username"  # Username entered - used to verify the SSO is the same name.
SESSION_RULE_ID = "workos_rule_id"  # The LoginRule ID used

# Store the safe next URL. Safeness is checked when inserting into session (or signed state object)
SESSION_NEXT = "workos_next"
SESSION_MFA_FACTOR_ID = "workos_mfa_factor_id"  # Used during MFA enrollment to store the factor ID
SESSION_TOTP_QR_CODE = "workos_totp_qr_code"  # QR Code used for enrollment
SESSION_TOTP_SECRET = "workos_totp_secret"  # Secret that matches the above QR code


def clear_session_vars(request: HttpRequest) -> None:
    if SESSION_USER_ID in request.session:
        del request.session[SESSION_USER_ID]

    if SESSION_AUTHENTICATED_USER_ID in request.session:
        del request.session[SESSION_AUTHENTICATED_USER_ID]

    if SESSION_RULE_ID in request.session:
        del request.session[SESSION_RULE_ID]

    if SESSION_NEXT in request.session:
        del request.session[SESSION_NEXT]

    if SESSION_MFA_FACTOR_ID in request.session:
        del request.session[SESSION_MFA_FACTOR_ID]

    if SESSION_TOTP_QR_CODE in request.session:
        del request.session[SESSION_TOTP_QR_CODE]

    if SESSION_TOTP_SECRET in request.session:
        del request.session[SESSION_TOTP_SECRET]


class UserNotFound(Exception):
    pass


def get_session_user(request: HttpRequest):
    user_id = request.session[SESSION_AUTHENTICATED_USER_ID]
    if(user_id):
        return get_user_model().objects.get(pk=user_id)
    return None


def get_session_rule(request: HttpRequest) -> Optional[LoginRule]:
    rule_id = request.session[SESSION_RULE_ID]
    if(rule_id):
        return LoginRule.objects.get(pk=rule_id)
    return None


def login_session_user(request: HttpRequest):
    user = get_session_user(request)

    if not user:
        raise UserNotFound

    auth_login(request, user)
    clear_session_vars(request)
    return user


@require_GET
def get_login_method(request: HttpRequest):
    username = request.GET.get("username")
    rule_id = None
    login_method = LoginMethods.USERNAME
    if not username:
        return JsonResponse({"message": "Username is required"}, status=400)

    rule = LoginRule.objects.find_rule_for_username(username)
    if(rule):
        login_method = LoginMethods(rule.method).frontend_method

    return JsonResponse({"method": login_method}, status=200)


class BaseCallbackView(RedirectView):
    query_string = False
    permanent = False
    allow_idp_initiated = False

    def create_error(self, msg: str) -> str:
        messages.error(self.request, msg)
        return reverse("login")

    def update_user_login(self, user_login: UserLogin, workos_profile: dict) -> None:
        """
        Can be used to update the user login profile
        :param user_login: the UserLogin object for this user
        :param workos_profile: the workos profile
        """
        pass

    def find_user_login(self, workos_profile: dict) -> Optional[UserLogin]:
        return None

    def get_redirect_url(self, *args, **kwargs):
        code = self.request.GET.get("code")
        state = self.request.GET.get("state")
        user = None
        username = None
        if (state):
            state = signing.loads(state)

        profile = workos.client.sso.get_profile_and_token(code).to_dict()["profile"]

        user_login = self.find_user_login(profile)

        # Default to base redirect login
        next_url = settings.LOGIN_REDIRECT_URL

        if user_login:
            # User has logged in before, and we know the user account
            user = user_login.user
            rule = None
            if(state):
                next_url = state[SESSION_NEXT]
        elif (state):
            rule_id = state[SESSION_RULE_ID]
            user_id = state[SESSION_USER_ID]
            next_url = state[SESSION_NEXT]
            username = state[STATE_USERNAME]
            if(user_id):
                user = get_user_model().objects.get(pk=user_id)
            rule = LoginRule.objects.get(pk=rule_id)
        elif self.allow_idp_initiated:
            # IDP Initiated
            user = find_user(profile["email"])
            rule = LoginRule.objects.find_rule_for_username(profile["email"])
            if rule is None:
                return self.create_error(_("No login was found, please contact your administrator"))
            if rule.organization_id != profile["organization_id"] and rule.connection_id != profile["connection_id"]:
                return self.create_error(_("Unknown SSO connection or organization"))
        else:
            return self.create_error(_("Unable to login. Please contact your administrator."))

        if user is None:
            if rule.jit_creation is False:
                return self.create_error(_("Your user account has not been provisioned. Please contact your administrator to create an account."))

            if username != profile["email"]:
                return self.create_error(_("Account email does not match your request. Please try again"))
            user = jit_create_user(profile, rule)
            workos_user_created.send(sender=UserLogin, user=user, profile=profile, rule=rule)

        # We have a user, make sure they are active
        if not user.is_active:
            return self.create_error(_("Your user account is not active. Please contact your administrator."))

        if not user_login:
            user_login = get_user_login_model(user)

        self.update_user_login(user_login, profile)
        # Login user and save sso attributes
        # Check if the user is active and has permissions
        auth_login(self.request, user)
        clear_session_vars(self.request)

        return next_url


class MagicCallbackView(BaseCallbackView):
    pass


class SSOCallbackView(BaseCallbackView):
    allow_idp_initiated = True

    def find_user_login(self, workos_profile: dict) -> Optional[UserLogin]:
        try:
            user_login = UserLogin.objects.get(sso_id=workos_profile["id"])
        except UserLogin.DoesNotExist:
            user_login = None
        return user_login

    def update_user_login(self, user_login: UserLogin, workos_profile: dict) -> None:
        user_login.mfa_type = ""  # Don't have MFA enabled if using SSO - rely on SSO to do this
        user_login.sso_id = workos_profile["id"]
        user_login.idp_id = workos_profile["idp_id"]
        user_login.save()


class WorkosLoginView(LoginView):
    form_class = LoginForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["login_home"] = resolve_url(settings.LOGIN_REDIRECT_URL)
        return ctx

    def get(self, request, *args, **kwargs):
        # Starting a new login - clear session
        clear_session_vars(request)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.get_user()
        rule = form.get_rule()
        method = rule.method

        state = signing.dumps({
            SESSION_RULE_ID: rule.pk,
            SESSION_USER_ID: user.pk if user else 0,
            STATE_USERNAME: form.cleaned_data["username"],
            SESSION_NEXT: self.get_success_url()
        }, compress=True)

        self.request.session[SESSION_RULE_ID] = rule.pk
        self.request.session[SESSION_NEXT] = self.get_success_url()
        # Check MFA before email to see if the user enabled MFA even without
        # having it as part of a rule
        if method == LoginMethods.MFA or user_has_mfa_enabled(user):
            self.request.session[SESSION_AUTHENTICATED_USER_ID] = user.pk
            if user_has_mfa_enabled(user):
                return redirect('mfa_verify')
            else:
                return redirect('mfa_enroll')
        elif method == LoginMethods.USERNAME:
            # This will log in the user - clear the workos session vars
            clear_session_vars(self.request)
            return super(WorkosLoginView, self).form_valid(form)
        elif method == LoginMethods.MAGIC_LINK:
            email = user.email
            session = workos.client.passwordless.create_session({
                'email': email,
                'redirect_uri': self.request.build_absolute_uri(conf.WORKOS_MAGIC_REDIRECT_URI),
                'state': state,
                'type': 'MagicLink'})
            workos_send_magic_link.send(sender=LoginRule, user=user, link=session["link"], rule=rule)
            if not conf.WORKOS_SEND_CUSTOM_EMAIL:
                workos.client.passwordless.send_session(session['id'])
            return redirect('magic_link_confirmation')
        elif method == LoginMethods.SAML_SSO:
            authorization_url = workos.client.sso.get_authorization_url(
                connection=rule.connection_id if rule.connection_id else None,
                organization=rule.organization_id if rule.organization_id else None,
                redirect_uri=self.request.build_absolute_uri(conf.WORKOS_SSO_REDIRECT_URI),
                state=state,
            )
            return redirect(authorization_url)
        elif method in {LoginMethods.MICROSOFT_SSO, LoginMethods.GOOGLE_SSO}:
            authorization_url = workos.client.sso.get_authorization_url(
                redirect_uri=self.request.build_absolute_uri(conf.WORKOS_SSO_REDIRECT_URI),
                provider=LoginMethods(method).provider,
                state=state,
            )
            return redirect(authorization_url)

        # Unknown method
        raise Http404


class MFAPermissionMixin(UserPassesTestMixin):
    def test_func(self):
        if self.request.user.is_authenticated:
            return True

        if self.request.session.get(SESSION_AUTHENTICATED_USER_ID, False):
            return True

        return False


class LoginSuccessUrlMixin:
    def get_success_url(self):
        if SESSION_NEXT in self.request.session:
            return self.request.session[SESSION_NEXT]

        return settings.LOGIN_REDIRECT_URL


class MFAVerificationView(MFAPermissionMixin, LoginSuccessUrlMixin, FormView):
    form_class = MFAVerificationForm
    template_name = 'registration/mfa_verify.html'

    def get_factor_id(self):

        if SESSION_MFA_FACTOR_ID in self.request.session:
            return self.request.session[SESSION_MFA_FACTOR_ID]

        user_login = get_user_login_model(get_session_user(self.request))
        if not user_login:
            raise Http404

        factor_id = user_login.mfa_factor
        if not factor_id:
            # No factor that we can authenticate
            raise Http404

        return factor_id

    def __init__(self, *args, **kwargs):
        self.workos_response = None
        super(MFAVerificationView, self).__init__(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        # Only on first GET do we get a challenge factor - if posting it will already be in the form data
        message = conf.WORKOS_SMS_MFA_TEMPLATE
        if callable(message):
            message = message(get_session_user(self.request))
        self.workos_response = workos.client.mfa.challenge_factor(authentication_factor_id=self.get_factor_id(), sms_template=message)
        return super(MFAVerificationView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(MFAVerificationView, self).get_context_data(**kwargs)
        user_login = get_user_login_model(get_session_user(self.request))
        ctx["sms"] = user_login.is_sms
        ctx["totp"] = user_login.is_totp
        return ctx

    def get_initial(self):
        # Add the challenge ID if we don't have it yet
        initial = super(MFAVerificationView, self).get_initial()
        if self.workos_response:
            initial["challenge_id"] = self.workos_response["id"]
        return initial

    def form_valid(self, form):
        if not self.request.user.is_authenticated:
            # They could be enrolling/verifying while logged in - only log in if needed
            login_session_user(self.request)

        if SESSION_MFA_FACTOR_ID in self.request.session:
            # We are enrolling so we want to save the factor ID by sending signal to app
            # Update factor id
            mfa_enroll(self.request.user, self.request.session[SESSION_MFA_FACTOR_ID], mfa_type="sms")
            del self.request.session[SESSION_MFA_FACTOR_ID]
            # user is already signed in for this case - no need for login

        return super(MFAVerificationView, self).form_valid(form)


class MFAStartEnrollView(MFAPermissionMixin, TemplateView):
    template_name = "registration/mfa_enroll_start.html"


class MFAEnrollBaseView(MFAPermissionMixin, FormView):
    template_name = 'registration/mfa_enroll.html'

    def get_success_url(self):
        return reverse('mfa_verify')

    def form_valid(self, form):
        self.request.session[SESSION_MFA_FACTOR_ID] = form.complete_enrollment(self.request.user)
        return super(MFAEnrollBaseView, self).form_valid(form)


class MFAEnrollSMSView(MFAEnrollBaseView):
    form_class = MFAEnrollFormSMS

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["is_sms"] = True
        return ctx


class MFAEnrollTOTPView(LoginSuccessUrlMixin, FormView):
    template_name = 'registration/mfa_enroll.html'
    form_class = MFAEnrollFormTOTP

    def __init__(self, *args, **kwargs):
        super(MFAEnrollTOTPView, self).__init__(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        user = get_session_user(request)
        rule = get_session_rule(request)
        if not user or not rule:
            messages.error(request, _("Unauthorized - try again"))
            return redirect("login")
        if SESSION_TOTP_QR_CODE not in self.request.session:
            workos_response = workos.client.mfa.enroll_factor(type=conf.MFA_TOTP_TYPE,
                                                                   totp_issuer=rule.totp_organization_name,
                                                                   totp_user=user.email)
            self.request.session[SESSION_TOTP_QR_CODE] = workos_response["totp"]["qr_code"]
            self.request.session[SESSION_TOTP_SECRET] = workos_response["totp"]["secret"]
            self.request.session[SESSION_MFA_FACTOR_ID] = workos_response["id"]
        return super(MFAEnrollTOTPView, self).get(request, *args, **kwargs)

    def form_valid(self, form):
        mfa_enroll(get_session_user(self.request), form.cleaned_data["factor_id"], mfa_type="totp")
        login_session_user(self.request)
        return super(MFAEnrollTOTPView, self).form_valid(form)

    def get_initial(self):
        initial = super(MFAEnrollTOTPView, self).get_initial()
        initial["factor_id"] = self.request.session[SESSION_MFA_FACTOR_ID]
        return initial

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["is_totp"] = True
        return ctx
