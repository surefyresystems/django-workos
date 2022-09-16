from django.contrib.auth.decorators import login_required
from django.urls import path
from django.views.generic import TemplateView

from .forms import WorkosPasswordResetForm, WorkosSetPasswordForm
from .views import WorkosLoginView, get_login_method, MFAVerificationView, MFAEnrollSMSView, \
    MFAEnrollTOTPView, MagicCallbackView, SSOCallbackView, MFAStartEnrollView
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('verify/', MFAVerificationView.as_view(), name="mfa_verify"),
    path('enroll/', MFAStartEnrollView.as_view(), name="mfa_enroll"),
    path('enroll-sms/', MFAEnrollSMSView.as_view(), name="mfa_enroll_sms"),
    path('enroll-totp/', MFAEnrollTOTPView.as_view(), name="mfa_enroll_totp"),
    path('complete/', TemplateView.as_view(template_name="registration/magic_link_complete.html"),
         name="magic_link_confirmation"),
    path('login-method/', get_login_method, name="login_method"),
    path('callback/sso/', SSOCallbackView.as_view(), name="sso_callback"),
    path('callback/magic/', MagicCallbackView.as_view(), name="magic_callback"),
    path("login/", WorkosLoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path(
        "password_change/", auth_views.PasswordChangeView.as_view(), name="password_change"
    ),
    path(
        "password_change/done/",
        auth_views.PasswordChangeDoneView.as_view(),
        name="password_change_done",
    ),
    path("password_reset/", auth_views.PasswordResetView.as_view(
        form_class=WorkosPasswordResetForm
    ), name="password_reset"),
    path(
        "password_reset/done/",
        auth_views.PasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(form_class=WorkosSetPasswordForm),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]
