from typing import Optional

from django.contrib import messages
from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import LoginView
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.http import JsonResponse, Http404, HttpRequest
from django.shortcuts import redirect, resolve_url
from django.conf import settings
from django.urls import reverse
from django.views.decorators.http import require_GET
from django.contrib.auth import login as auth_login
from django.utils.translation import gettext_lazy as _

import workos

# Create your views here.
from django.views.generic import FormView, RedirectView, TemplateView

from workos_login.forms import LoginForm, MFAVerificationForm, MFAEnrollFormSMS, MFAEnrollFormTOTP
from workos_login.models import LoginRule, UserLogin, LoginMethods
from workos_login.conf import conf
from workos_login.signals import workos_user_created, workos_send_magic_link
from workos_login.utils import user_has_mfa_enabled, get_user_login_model, mfa_enroll, jit_create_user, \
    pack_state, unpack_state, update_user_profile, find_user_by_email, get_users, has_user_login_model, find_user

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
        return get_users().get(pk=user_id)
    return None


def get_session_rule(request: HttpRequest) -> Optional[LoginRule]:
    rule_id = request.session[SESSION_RULE_ID]
    if rule_id:
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
    username = request.GET.get("username", default="").strip()
    rule_id = None
    login_method = LoginMethods.USERNAME
    if not username:
        return JsonResponse({"message": "Username is required"}, status=400)

    rule = LoginRule.objects.find_rule_for_username(username)
    if rule:
        method = LoginMethods(rule.method)
        login_method = method.frontend_method
        if not method.is_sso:
            # If method is not SSO check if MFA is enabled, if so that is the method we will use.
            # Since the user has enabled MFA for themselves.
            try:
                user = find_user(username)
                if user_has_mfa_enabled(user):
                    login_method = LoginMethods.MFA
            except ObjectDoesNotExist:
                pass


    return JsonResponse({"method": login_method}, status=200)


class BaseCallbackView(RedirectView):
    query_string = False
    permanent = False
    allow_idp_initiated = False

    def create_error(self, msg: str | list[str]) -> str:
        if isinstance(msg, list):
            for m in msg:
                messages.error(self.request, m)
        else:
            messages.error(self.request, msg)

        return reverse("login")

    def update_user_login(self, user_login: UserLogin, workos_profile: dict) -> None:
        """
        Can be used to update the user login profile
        :param user_login: the UserLogin object for this user
        :param workos_profile: the workos profile
        """
        # Save the workos id
        user_login.sso_id = workos_profile["id"]
        user_login.save()

    def find_user_login(self, workos_profile: dict) -> Optional[UserLogin]:
        try:
            user_login = UserLogin.objects.get(sso_id=workos_profile["id"])
        except UserLogin.DoesNotExist:
            user_login = None
        return user_login

    def get_redirect_url(self, *args, **kwargs):
        code = self.request.GET.get("code")
        state = self.request.GET.get("state")
        error = self.request.GET.get("error")
        error_description = self.request.GET.get("error_description")
        if error:
            return self.create_error([_("There was an logging in please try again."), _("%(error_code)s: %(error_message)s") % {"error_code": str(error), "error_message": str(error_description)}])
        user = None
        username = None
        if state:
            state = unpack_state(state)

        profile = workos.client.sso.get_profile_and_token(code).to_dict()["profile"]

        user_login = self.find_user_login(profile)

        # Default to base redirect login
        next_url = settings.LOGIN_REDIRECT_URL

        if user_login:
            # User has logged in before, and we know the user account
            user = user_login.user
            rule = user_login.rule

            if state:
                next_url = state[SESSION_NEXT]
                if user.pk != state[SESSION_USER_ID]:
                    return self.create_error(_("Your username does not match the account you selected."))
        elif state:
            # Login based on a rule, but this is the first time a user is loging in
            # via SSO (since there is no user_login yet) or it is JIT creation.
            rule_id = state[SESSION_RULE_ID]
            user_id = state[SESSION_USER_ID]
            next_url = state[SESSION_NEXT]
            username = state[STATE_USERNAME]
            rule = LoginRule.objects.get(pk=rule_id)
            if user_id:
                user = get_users().get(pk=user_id)

                if has_user_login_model(user):
                    # Magic link can change the sso_id if the email changes in the user model.
                    # So this case is allowed without erroring out and the related UserLogin model
                    # will get updated lower down.
                    # This is not allowed for SSO since it likely means they selected the wrong account
                    # in the case they have multiple user accounts with the iDP.
                    if not rule.magic_link:
                        return self.create_error(_("Selected account does not match the user account"))
                elif not user.email or user.email.lower() != profile["email"].lower():
                    # We have a user on file and this is the first time they are logging in via SSO (since there is no user login).
                    # But the email does not match. For the first association the email address must match
                    # to ensure the user is logging into the account they are supposed to.
                    return self.create_error(_("Your email address does not match your user account on file. Please try again"))

        elif self.allow_idp_initiated:
            # First time IDP Initiated
            # If they have logged in before we would have a user_login created already
            # Since this is a first time login we have not created a formatted username yet.
            # Instead, do a lookup based on email to try to find a matching account already in the system.
            user = find_user_by_email(profile["email"])
            if user:
                rule = LoginRule.objects.find_rule_for_user(user)
            else:
                # No user found, but maybe a JIT rule exists for this email address
                rule = LoginRule.objects.find_rule_for_jit(profile["email"],
                                                           connection_id=profile.get("connection_id"),
                                                           organization_id=profile.get("organization_id"))
            if rule is None:
                return self.create_error(_("No login was found, please contact your administrator"))
            if rule.organization_id != profile["organization_id"] and rule.connection_id != profile["connection_id"]:
                return self.create_error(_("Unknown SSO connection or organization"))
        else:
            return self.create_error(_("Unable to login. Please contact your administrator."))

        if user is None:
            if not rule.jit_creation_type:
                return self.create_error(_("Your user account has not been provisioned. Please contact your administrator to create an account."))

            # Since there is no user this must have been an email match, make sure
            # the email they used is for the correct rule (ensuring they didn't select a wrong account)
            expected_rule = LoginRule.objects.find_rule_for_jit(profile["email"],
                                                                connection_id=profile.get("connection_id"),
                                                                organization_id=profile.get("organization_id"))

            if rule != expected_rule:
                return self.create_error(_("Account username does not match your request. Please try again"))

            # If there is a username but no user it is because we are doing an SP JIT login
            # that matched an email regex rule. Make sure that the email associated with the
            # SSO account matches the username the user entered (which would be their email).
            if username and username != profile["email"]:
                return self.create_error(_("The account selected does not match username entered. Please try again"))

            try:
                user = jit_create_user(rule, profile)
            except IntegrityError:
                return self.create_error(_("Unable to create user account, you may already have an account created."))
            workos_user_created.send(sender=UserLogin, user=user, profile=profile, rule=rule)
        else:
            try:
                update_user_profile(user, rule, profile)
            except IntegrityError:
                self.create_error(_("Unable to update user profile, please contact your administrator."))

        # We have a user, make sure they are active
        if not user.is_active:
            return self.create_error(_("Your user account is not active. Please contact your administrator."))

        if not user_login:
            # First time through or could not match user_login based on workosID (this happens if using magic email and user email address changed).
            # Get the user login and set the rule that is being used.
            user_login = get_user_login_model(user)
            user_login.rule = rule
            user_login.save()

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

    def __init__(self, *args, **kwargs):
        self.cookies_disabled = False
        super().__init__(*args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["login_home"] = resolve_url(settings.LOGIN_REDIRECT_URL)
        return ctx

    def get(self, request, *args, **kwargs):
        # Starting a new login - clear session
        clear_session_vars(request)
        request.session.set_test_cookie()
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        # First check if cookie are enabled
        if not self.request.session.test_cookie_worked():
            messages.error(self.request, _("Cookies are required for proper functionality. Please enable cookies and try again."))
            self.cookies_disabled = True
            return self.form_invalid(form)

        user = form.get_user()
        rule = form.get_rule()
        method = rule.method
        state = pack_state({
            SESSION_RULE_ID: rule.pk,
            SESSION_USER_ID: user.pk if user else 0,
            STATE_USERNAME: form.cleaned_data["username"],
            SESSION_NEXT: self.get_success_url()
        })

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
        elif method == LoginMethods.MAGIC_LINK or method == LoginMethods.EMAIL_MFA:
            email = user.email
            uri = conf.WORKOS_MAGIC_REDIRECT_URI if conf.WORKOS_MAGIC_REDIRECT_URI else self.request.build_absolute_uri(reverse("magic_callback"))
            session = workos.client.passwordless.create_session({
                'email': email,
                'redirect_uri': uri,
                'state': state,
                'type': 'MagicLink'})
            workos_send_magic_link.send(sender=LoginRule, user=user, link=session["link"], rule=rule)
            if not conf.WORKOS_SEND_CUSTOM_EMAIL:
                workos.client.passwordless.send_session(session['id'])
            return redirect('magic_link_confirmation')
        elif method == LoginMethods.SAML_SSO:
            uri = conf.WORKOS_SSO_REDIRECT_URI if conf.WORKOS_SSO_REDIRECT_URI else self.request.build_absolute_uri(reverse("sso_callback"))
            authorization_url = workos.client.sso.get_authorization_url(
                connection=rule.connection_id if rule.connection_id else None,
                organization=rule.organization_id if rule.organization_id else None,
                redirect_uri=uri,
                state=state,
            )
            return redirect(authorization_url)
        elif method in {LoginMethods.MICROSOFT_SSO, LoginMethods.GOOGLE_SSO}:
            uri = conf.WORKOS_SSO_REDIRECT_URI if conf.WORKOS_SSO_REDIRECT_URI else self.request.build_absolute_uri(reverse("sso_callback"))
            authorization_url = workos.client.sso.get_authorization_url(
                redirect_uri=uri,
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

# Allow for an API post (open to all) to post a username/email to get the flow started.
