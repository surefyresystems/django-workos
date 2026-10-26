from dataclasses import dataclass
from functools import partial
from datetime import timedelta
from unittest.mock import patch, MagicMock, Mock
from django.contrib.auth import get_user_model, get_user
from django.contrib.messages import get_messages
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TestCase, RequestFactory, override_settings
from django.urls import reverse
from django.core import mail
from django.utils import timezone

from workos_login.admin import LoginRuleAdmin, CreateSAMLConnectionForm
from workos_login.connections import create_saml_connection
from workos_login.models import LoginRule, LoginMethods, UserLogin, LogoutMethods
from workos_login.exceptions import EmailVerificationError
import workos
from workos import AuthenticationError, BadRequestError, ServerError
from django.contrib import admin as django_admin
from django import forms as django_forms

from workos_login.utils import (
    jit_create_user,
    send_email_verification_code,
    verify_email_code,
    SESSION_EMAIL_VERIFICATION_KEY,
    SESSION_EMAIL_VERIFICATION_USER_KEY,
    SESSION_EMAIL_VERIFICATION_TIMESTAMP
)
from workos_login.forms import EmailVerificationForm



@dataclass
class MockProfile:
    profile: dict
    def to_dict(self):
        return self.profile

def get_profile_and_token(code, **profile_attrs):
    """Assume code is the email"""
    return MockProfile({
        "profile": {
           "id": code,
           "email": code,
           "first_name": code,
           "last_name": code,
           "idp_id": code,
           "raw_attributes": {},
            "organization_id": None,
            "connection_id": None,
            **profile_attrs
        }
    })

def get_and_clear_messages(resp, client):
    messages = [x.message for x in get_messages(resp.wsgi_request)]
    try:
        del client.cookies['messages']
    except KeyError:
        pass
    return messages

#sso_mock = patch('workos.client.sso.get_profile_and_token', wraps=get_profile_and_token)
#sso_mock.side_effect = get_profile_and_token

class LoginRuleTest(TestCase):
    def setUp(self) -> None:
        pass

    def test_priority(self):
        get_user_model().objects.create_user(
            first_name="Test",
            last_name="MFA",
            email="test@mfa.com",
            username="test"
        )
        priority_one = LoginRule.objects.create(
            name="Pri 1",
            method=LoginMethods.SAML_SSO,
            connection_id="1",
            priority=1,
            email_regex="test@sso.com"
        )

        priority_two = LoginRule.objects.create(
            name="Pri 2",
            method=LoginMethods.MFA,
            priority=2,
            email_regex="@mfa.com"
        )

        priority_three = LoginRule.objects.create(
            name="Pri 3",
            method=LoginMethods.USERNAME,
            priority=3,
            email_regex="@mfa.com"
        )

        rule = LoginRule.objects.find_rule_for_username("test")
        self.assertEqual(rule, priority_two)

    @patch('workos.sso.SSO.get_profile_and_token', wraps=partial(get_profile_and_token, organization_id="sso_org", idp_id="1234"), org_id="org_id")
    def test_idp_lookup(self, mock_get_profile):
        """
        Test that idp will find a user correctly using SSO callback
        """
        user = get_user_model().objects.create_user(
            username="stale_username",
            email="test@example.com"
        )
        resp = self.client.get(reverse('sso_callback'), data={"code": "test@example.com"})
        message = get_and_clear_messages(resp, self.client)[0]
        self.assertEqual(message, "Unknown SSO connection or organization")
        self.assertFalse(get_user(self.client).is_authenticated)

        # Add a user login with SSO
        LoginRule.objects.create(
            name="Saml sso",
            method=LoginMethods.SAML_SSO,
            priority=2,
            organization_id="sso_org",
            email_regex="@example.com"
        )
        self.assertFalse(UserLogin.objects.all().exists())
        resp = self.client.get(reverse('sso_callback'), data={"code": "test@example.com"})
        self.assertEqual(get_and_clear_messages(resp, self.client), [])
        self.assertTrue(UserLogin.objects.all().exists())
        self.assertEqual(get_user(self.client), user)
        self.client.logout()
        self.assertFalse(get_user(self.client).is_authenticated)

        # Now try changing the email and ensure the login still works since the ID has not changed
        resp = self.client.get(reverse('sso_callback'), data={"code": "invalidemail@invalid.com"})
        self.assertEqual(get_user(self.client), user)
        self.assertTrue(get_user(self.client).is_authenticated)

    def test_jit_creation(self):
        sso_rule = LoginRule.objects.create(
            name="JIT Creation",
            method=LoginMethods.SAML_SSO,
            jit_creation_type="idp",
            priority=3,
            saved_attributes={
                "username": "{{profile.first_name}}{{profile.last_name}}"
            }
        )
        profile = {
            "first_name": "Santana",
            "last_name": "Clause",
            "email": "sclause@northpole.net",
            "id": "123",
            "idp_id": "333"
        }
        user = jit_create_user(sso_rule, profile)
        self.assertEqual(user.is_active, True)
        self.assertEqual(user.username, "SantanaClause")


class EmailVerificationTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = get_user_model().objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test'
        )
        self.client.force_login(self.user)

    def _create_request_with_session(self):
        """Helper to create a request with session middleware"""
        request = self.factory.get('/')
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()
        request.user = self.user
        return request

    @override_settings(WORKOS_SEND_CUSTOM_EMAIL=False)
    def test_send_email_success(self):
        """Test that email is sent successfully"""
        request = self._create_request_with_session()

        result = send_email_verification_code(request, self.user)

        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.user.email])

    def test_code_stored_in_session(self):
        """Test that verification code is stored in session"""
        request = self._create_request_with_session()

        send_email_verification_code(request, self.user)

        self.assertIn(SESSION_EMAIL_VERIFICATION_KEY, request.session)
        self.assertIn(SESSION_EMAIL_VERIFICATION_USER_KEY, request.session)
        self.assertIn(SESSION_EMAIL_VERIFICATION_TIMESTAMP, request.session)
        self.assertEqual(request.session[SESSION_EMAIL_VERIFICATION_USER_KEY], self.user.id)

    @override_settings(WORKOS_SEND_CUSTOM_EMAIL=False)
    def test_email_contains_code(self):
        """Test that email contains the verification code"""
        request = self._create_request_with_session()

        send_email_verification_code(request, self.user)

        code = request.session[SESSION_EMAIL_VERIFICATION_KEY]
        email_body = mail.outbox[0].body
        self.assertIn(code, email_body)

    @override_settings(WORKOS_SEND_CUSTOM_EMAIL=False)
    def test_email_has_html_alternative(self):
        """Test that email has HTML alternative"""
        request = self._create_request_with_session()

        send_email_verification_code(request, self.user)

        self.assertEqual(len(mail.outbox[0].alternatives), 1)
        html_content, content_type = mail.outbox[0].alternatives[0]
        self.assertEqual(content_type, "text/html")

    def test_verify_correct_code(self):
        """Test that correct code passes verification"""
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = self.user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()

        result = verify_email_code(request, "123456")

        self.assertTrue(result)

    def test_verify_incorrect_code(self):
        """Test that incorrect code fails verification"""
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = self.user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()

        self.assertRaises(EmailVerificationError, verify_email_code, request, "654321")

    def test_verify_clears_session_on_success(self):
        """Test that session data is cleared after successful verification"""
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = self.user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()

        verify_email_code(request, "123456")

        self.assertNotIn(SESSION_EMAIL_VERIFICATION_KEY, request.session)
        self.assertNotIn(SESSION_EMAIL_VERIFICATION_USER_KEY, request.session)
        self.assertNotIn(SESSION_EMAIL_VERIFICATION_TIMESTAMP, request.session)

    def test_verify_no_code_in_session(self):
        """Test that verification fails when no code in session"""
        request = self._create_request_with_session()

        self.assertRaises(EmailVerificationError, verify_email_code, request, "123456")

    def test_verify_wrong_user(self):
        """Test that verification fails for different user"""
        other_user = get_user_model().objects.create_user(username='other', email='other@example.com')
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = other_user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()
        request.user = self.user

        self.assertRaises(EmailVerificationError, verify_email_code, request, "123456")

    def test_form_valid_code(self):
        """Test form validation with correct code"""
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = self.user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()

        form = EmailVerificationForm(data={'verification_code': '123456'}, request=request)

        self.assertTrue(form.is_valid())

    def test_form_invalid_code(self):
        """Test form validation with incorrect code"""
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = self.user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()

        form = EmailVerificationForm(data={'verification_code': '654321'}, request=request)

        self.assertFalse(form.is_valid())
        self.assertIn('verification_code', form.errors)

    @override_settings(WORKOS_SEND_CUSTOM_EMAIL=False)
    def test_resend_view_sends_email(self):
        """Test that resend view sends a new email"""
        response = self.client.get(reverse('resend_email_verification'))

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.user.email])

    def test_resend_view_redirects(self):
        """Test that resend view redirects to verification page"""
        response = self.client.get(reverse('resend_email_verification'))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('email_verification'))

    def test_resend_view_success_message(self):
        """Test that resend view shows success message"""
        response = self.client.get(reverse('resend_email_verification'), follow=True)

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertIn("verification code has been sent", str(messages[0]))

    def test_resend_view_updates_session_code(self):
        """Test that resend generates a new code"""
        self.client.get(reverse('resend_email_verification'))
        first_code = self.client.session[SESSION_EMAIL_VERIFICATION_KEY]

        self.client.get(reverse('resend_email_verification'))
        second_code = self.client.session[SESSION_EMAIL_VERIFICATION_KEY]

        self.assertNotEqual(first_code, second_code)

    def test_full_verification_flow(self):
        """Test complete email verification flow"""
        self.client.get(reverse('resend_email_verification'))

        session = self.client.session
        code = session[SESSION_EMAIL_VERIFICATION_KEY]

        response = self.client.post(
            reverse('email_verification'),
            {'verification_code': code},
            follow=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_EMAIL_VERIFICATION_KEY, self.client.session)

    @override_settings(WORKOS_VERIFICATION_EMAIL_EXPIRATION_MINUTES=15)
    def test_expired_code_integration_flow(self):
        """Test complete flow with expired code"""
        self.client.get(reverse('resend_email_verification'))

        code = self.client.session[SESSION_EMAIL_VERIFICATION_KEY]

        session = self.client.session
        expired_time = timezone.now() - timedelta(minutes=20)
        session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = expired_time.isoformat()
        session.save()

        response = self.client.post(
            reverse('email_verification'),
            {'verification_code': code},
            follow=True
        )

        form = response.context['form']
        self.assertFalse(form.is_valid())

    def test_cleared_session_code(self):
        """Test verification fails after session clear"""
        self.client.get(reverse('resend_email_verification'))
        code = self.client.session[SESSION_EMAIL_VERIFICATION_KEY]

        self.client.session.flush()

        response = self.client.post(
            reverse('email_verification'),
            {'verification_code': code},
            follow=True
        )

        form = response.context['form']
        self.assertFalse(form.is_valid())


class WorkosLogoutViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="logout_user",
            email="logout_user@example.com",
        )
        self.client.force_login(self.user)

    def test_logout_no_rule_uses_default_behavior(self):
        """If no LoginRule is associated with the user, default logout should occur."""
        with patch(
            "workos_login.models.LoginRule.objects.find_rule_for_user",
            return_value=None,
        ):
            response = self.client.post(reverse("logout"))

        self.assertFalse(get_user(self.client).is_authenticated)
        self.assertEqual(response.status_code, 302)

    def test_logout_rule_without_single_logout_uses_default_behavior(self):
        """If the rule does not have single_logout enabled, default logout should occur."""
        rule = MagicMock(sso_logout_method=None, custom_logout_url=None)
        with patch(
            "workos_login.models.LoginRule.objects.find_rule_for_user",
            return_value=rule,
        ):
            response = self.client.post(reverse("logout"))

        self.assertFalse(get_user(self.client).is_authenticated)
        self.assertEqual(response.status_code, 302)

    def test_logout_with_single_logout_and_custom_url_redirects(self):
        """If single_logout is enabled and a custom_logout_url is set, redirect there."""
        custom_url = "https://example.com/custom-logout"
        rule = MagicMock(sso_logout_method=LogoutMethods.CUSTOM_URL, custom_logout_url=custom_url)
        with patch(
            "workos_login.models.LoginRule.objects.find_rule_for_user",
            return_value=rule,
        ):
            response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, custom_url)

    def test_logout_with_single_logout_but_no_custom_url_uses_default_behavior(self):
        """If single_logout is enabled but no custom_logout_url is set, default logout should occur."""
        rule = MagicMock(sso_logout_method=LogoutMethods.CUSTOM_URL, custom_logout_url=None)
        with patch(
            "workos_login.models.LoginRule.objects.find_rule_for_user",
            return_value=rule,
        ):
            response = self.client.post(reverse("logout"))

        self.assertFalse(get_user(self.client).is_authenticated)
        self.assertEqual(response.status_code, 302)

    def test_logout_anonymous_user_no_rule(self):
        """Logging out as an anonymous user with no matching rule should not error."""
        self.client.logout()
        self.assertTrue(get_user(self.client).is_anonymous)
        with patch(
                "workos_login.models.LoginRule.objects.find_rule_for_user",
                return_value=None,
        ):
            response = self.client.post(reverse("logout"))

        self.assertFalse(get_user(self.client).is_authenticated)
        self.assertEqual(response.status_code, 302)

    def test_logout_anonymous_user_with_custom_url_redirects(self):
        """Logging out as an anonymous user should still respect a matching rule's custom_logout_url."""
        self.client.logout()
        custom_url = "https://example.com/custom-logout"
        rule = MagicMock(sso_logout_method=LogoutMethods.CUSTOM_URL, custom_logout_url=custom_url)
        self.assertTrue(get_user(self.client).is_anonymous)
        with patch(
                "workos_login.models.LoginRule.objects.find_rule_for_user",
                return_value=rule,
        ):
            response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, custom_url)


class SelfServiceConnectionsTest(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user(
            username="staff_user",
            email="staff@example.com",
            is_staff=True,
        )
        self.rule = LoginRule.objects.create(
            name="SSO Rule",
            method=LoginMethods.SAML_SSO,
            organization_id="org_123",
            priority=5,
            email_regex="test@ssoconn.com",
        )

    def test_status_denied_without_managed_rule(self):
        """Default WORKOS_GET_MANAGED_RULE returns None, so access is denied even for staff."""
        self.client.force_login(self.staff)
        response = self.client.get(reverse("workos_connection_status"))
        self.assertEqual(response.status_code, 403)

    def test_status_denied_for_non_staff(self):
        """Default WORKOS_CONNECTION_MANAGER_TEST is staff-only."""
        user = get_user_model().objects.create_user(username="regular", email="regular@example.com")
        self.client.force_login(user)
        with override_settings(WORKOS_GET_MANAGED_RULE=lambda request: self.rule):
            response = self.client.get(reverse("workos_connection_status"))
        self.assertEqual(response.status_code, 403)

    def test_status_shows_live_connection_by_organization(self):
        """A rule with only organization_id set looks up the connection via list_connections."""
        self.client.force_login(self.staff)
        connection = Mock(state="active", connection_type="OktaSAML", name="Acme Co", updated_at="2026-09-01")
        with override_settings(WORKOS_GET_MANAGED_RULE=lambda request: self.rule):
            with patch("workos_login.connections.get_client") as mock_get_client:
                mock_get_client.return_value.sso.list_connections.return_value = MagicMock(data=[connection])
                response = self.client.get(reverse("workos_connection_status"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "active")
        mock_get_client.return_value.sso.list_connections.assert_called_once_with(organization_id="org_123")

    def test_status_shows_live_connection_by_connection_id(self):
        """A rule with only connection_id set looks up the connection via get_connection."""
        rule = LoginRule.objects.create(
            name="Direct Connection Rule",
            method=LoginMethods.SAML_SSO,
            connection_id="conn_123",
            priority=6,
            email_regex="test2@ssoconn.com",
        )
        self.client.force_login(self.staff)
        connection = Mock(state="active", connection_type="AzureSAML", name="Acme Co", updated_at="2026-09-01")
        with override_settings(WORKOS_GET_MANAGED_RULE=lambda request: rule):
            with patch("workos_login.connections.get_client") as mock_get_client:
                mock_get_client.return_value.sso.get_connection.return_value = connection
                response = self.client.get(reverse("workos_connection_status"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "active")
        mock_get_client.return_value.sso.get_connection.assert_called_once_with("conn_123")

    def test_status_empty_state_when_no_connection_configured(self):
        """A rule with neither connection_id nor organization_id set shows the empty state."""
        rule = LoginRule.objects.create(
            name="Unconfigured Rule",
            method=LoginMethods.SAML_SSO,
            priority=7,
            email_regex="test3@ssoconn.com",
        )
        self.client.force_login(self.staff)
        with override_settings(WORKOS_GET_MANAGED_RULE=lambda request: rule):
            response = self.client.get(reverse("workos_connection_status"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "haven't configured")

    def test_setup_redirects_to_fresh_portal_link_using_environment_aware_client(self):
        """The redirect view must use get_client(rule), not the bare SDK client."""
        self.client.force_login(self.staff)
        with override_settings(WORKOS_GET_MANAGED_RULE=lambda request: self.rule):
            with patch("workos_login.connections.get_client") as mock_get_client:
                mock_get_client.return_value.admin_portal.generate_link.return_value = MagicMock(
                    link="https://id.workos.com/portal/abc"
                )
                response = self.client.get(reverse("workos_connection_setup"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://id.workos.com/portal/abc")
        mock_get_client.assert_called_once_with(self.rule)
        mock_get_client.return_value.admin_portal.generate_link.assert_called_once_with(
            organization="org_123", intent="sso", return_url=None, success_url=None,
        )


class LoginRuleAdminConnectionStatusTest(TestCase):
    def setUp(self):
        self.admin = LoginRuleAdmin(LoginRule, django_admin.site)

    def test_connection_status_unavailable_without_ids(self):
        rule = LoginRule.objects.create(
            name="Unconfigured Admin Rule",
            method=LoginMethods.USERNAME,
            priority=60,
            email_regex="admin1@ssoconn.com",
        )
        result = str(self.admin.connection_status(rule))
        self.assertIn("Only available", result)

    def test_connection_status_shows_no_connection_configured(self):
        rule = LoginRule.objects.create(
            name="Admin Rule No Connection",
            method=LoginMethods.SAML_SSO,
            organization_id="org_admin_1",
            priority=61,
            email_regex="admin2@ssoconn.com",
        )
        with patch("workos_login.admin.get_connection_status", return_value=None):
            result = str(self.admin.connection_status(rule))
        self.assertIn("No connection configured yet", result)

    def test_connection_status_shows_live_state(self):
        rule = LoginRule.objects.create(
            name="Admin Rule Live",
            method=LoginMethods.SAML_SSO,
            organization_id="org_admin_2",
            priority=62,
            email_regex="admin3@ssoconn.com",
        )
        connection = Mock(state="active", connection_type="OktaSAML", name="Acme Co")
        with patch("workos_login.admin.get_connection_status", return_value=connection):
            result = str(self.admin.connection_status(rule))
        self.assertIn("active", result)
        self.assertIn("OktaSAML", result)

    def test_connection_status_does_not_500_on_authentication_error(self):
        """A credentials problem (not just a bad request) must not crash the change page."""
        rule = LoginRule.objects.create(
            name="Admin Rule Auth Error",
            method=LoginMethods.SAML_SSO,
            organization_id="org_admin_3",
            priority=63,
            email_regex="admin4@ssoconn.com",
        )
        with patch("workos_login.admin.get_connection_status", side_effect=AuthenticationError("bad key")):
            result = str(self.admin.connection_status(rule))
        self.assertIn("Unable to fetch connection status", result)

    def test_portal_link_does_not_500_on_authentication_error(self):
        rule = LoginRule.objects.create(
            name="Admin Rule Portal Auth Error",
            method=LoginMethods.SAML_SSO,
            organization_id="org_admin_4",
            priority=64,
            email_regex="admin5@ssoconn.com",
        )
        with patch("workos_login.admin.get_portal_link", side_effect=AuthenticationError("bad key")):
            result = str(self.admin.portal_link(rule))
        self.assertIn("Unable to generate a portal link", result)

    def test_create_connection_link_does_not_500_on_authentication_error(self):
        rule = LoginRule.objects.create(
            name="Admin Rule Create Link Auth Error",
            method=LoginMethods.SAML_SSO,
            organization_id="org_admin_5",
            priority=65,
            email_regex="admin6@ssoconn.com",
        )
        with patch("workos_login.admin.get_connection_status", side_effect=AuthenticationError("bad key")):
            result = str(self.admin.create_connection_link(rule))
        self.assertIn("Unable to fetch connection status", result)


class CreateSAMLConnectionFormTest(TestCase):
    def test_neither_path_provided_is_invalid(self):
        form = CreateSAMLConnectionForm(data={})
        self.assertFalse(form.is_valid())

    def test_both_paths_provided_is_invalid(self):
        form = CreateSAMLConnectionForm(data={
            "idp_metadata_url": "https://idp.example.com/metadata",
            "idp_entity_id": "https://idp.example.com/entity",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_signing_cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
        })
        self.assertFalse(form.is_valid())

    def test_metadata_url_only_is_valid(self):
        form = CreateSAMLConnectionForm(data={"idp_metadata_url": "https://idp.example.com/metadata"})
        self.assertTrue(form.is_valid())

    def test_full_manual_trio_is_valid(self):
        form = CreateSAMLConnectionForm(data={
            "idp_entity_id": "https://idp.example.com/entity",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_signing_cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
        })
        self.assertTrue(form.is_valid())

    def test_partial_manual_trio_is_invalid(self):
        form = CreateSAMLConnectionForm(data={
            "idp_entity_id": "https://idp.example.com/entity",
            "idp_sso_url": "https://idp.example.com/sso",
        })
        self.assertFalse(form.is_valid())


class CreateSAMLConnectionTest(TestCase):
    def setUp(self):
        self.rule = LoginRule.objects.create(
            name="Create Conn Rule",
            method=LoginMethods.SAML_SSO,
            organization_id="org_create_1",
            priority=70,
            email_regex="create1@ssoconn.com",
        )

    def test_metadata_url_path(self):
        with patch("workos_login.connections.get_client") as mock_get_client:
            create_saml_connection(self.rule, idp_metadata_url="https://idp.example.com/metadata")

        _, kwargs = mock_get_client.return_value.sso.create_connection.call_args
        self.assertEqual(kwargs["organization_id"], "org_create_1")
        self.assertEqual(kwargs["protocol_options"].saml_options.idp_metadata_url, "https://idp.example.com/metadata")
        self.assertIsNone(kwargs["protocol_options"].saml_options.idp_signing_certs)

    def test_manual_fields_path_wraps_cert_in_list(self):
        with patch("workos_login.connections.get_client") as mock_get_client:
            create_saml_connection(
                self.rule,
                idp_entity_id="https://idp.example.com/entity",
                idp_sso_url="https://idp.example.com/sso",
                idp_signing_cert="CERT_PEM_TEXT",
            )

        _, kwargs = mock_get_client.return_value.sso.create_connection.call_args
        saml_options = kwargs["protocol_options"].saml_options
        self.assertIsNone(saml_options.idp_metadata_url)
        self.assertEqual(saml_options.idp_entity_id, "https://idp.example.com/entity")
        self.assertEqual(saml_options.idp_sso_url, "https://idp.example.com/sso")
        self.assertEqual(saml_options.idp_signing_certs, ["CERT_PEM_TEXT"])


class LoginRuleAdminCreateConnectionFlagTest(TestCase):
    def setUp(self):
        self.superuser = get_user_model().objects.create_superuser(
            username="flag_super", email="flag@example.com", password="pw12345",
        )
        self.rule = LoginRule.objects.create(
            name="Flag Rule",
            method=LoginMethods.SAML_SSO,
            organization_id="org_flag_1",
            priority=90,
            email_regex="flag1@ssoconn.com",
        )
        self.admin = LoginRuleAdmin(LoginRule, django_admin.site)

    def _fields(self):
        request = RequestFactory().get("/")
        fieldsets = self.admin.get_fieldsets(request, self.rule)
        return [f for _name, options in fieldsets for f in options["fields"]]

    def test_flag_defaults_to_disabled(self):
        from workos_login.conf import conf
        self.assertFalse(conf.WORKOS_ENABLE_CREATE_CONNECTION)

    def test_view_returns_404_when_disabled(self):
        self.client.force_login(self.superuser)
        url = reverse("admin:workos_login_loginrule_create_connection", args=[self.rule.pk])
        with patch("workos_login.admin.get_connection_status") as mock_status:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        mock_status.assert_not_called()

    def test_link_hidden_from_fieldsets_when_disabled(self):
        self.assertNotIn("create_connection_link", self._fields())

    @override_settings(WORKOS_ENABLE_CREATE_CONNECTION=True)
    def test_link_shown_in_fieldsets_when_enabled(self):
        self.assertIn("create_connection_link", self._fields())


@override_settings(WORKOS_ENABLE_CREATE_CONNECTION=True)
class LoginRuleAdminCreateConnectionViewTest(TestCase):
    def setUp(self):
        self.superuser = get_user_model().objects.create_superuser(
            username="super_user", email="super@example.com", password="pw12345",
        )
        self.limited_staff = get_user_model().objects.create_user(
            username="limited_staff", email="limited@example.com", is_staff=True,
        )
        self.rule = LoginRule.objects.create(
            name="View Test Rule",
            method=LoginMethods.SAML_SSO,
            organization_id="org_view_1",
            priority=80,
            email_regex="view1@ssoconn.com",
        )

    def _url(self, rule=None):
        return reverse("admin:workos_login_loginrule_create_connection", args=[(rule or self.rule).pk])

    def _change_url(self, rule=None):
        return reverse("admin:workos_login_loginrule_change", args=[(rule or self.rule).pk])

    def test_denied_without_change_permission(self):
        self.client.force_login(self.limited_staff)
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 403)

    def test_blocked_when_organization_id_unset(self):
        rule = LoginRule.objects.create(
            name="No Org Rule", method=LoginMethods.SAML_SSO, connection_id="conn_x",
            priority=81, email_regex="view2@ssoconn.com",
        )
        self.client.force_login(self.superuser)
        response = self.client.get(self._url(rule))
        self.assertRedirects(response, self._change_url(rule), fetch_redirect_response=False)

    def test_blocked_when_connection_already_exists(self):
        self.client.force_login(self.superuser)
        with patch("workos_login.admin.get_connection_status", return_value=Mock()):
            response = self.client.get(self._url())
        self.assertRedirects(response, self._change_url(), fetch_redirect_response=False)

    def test_does_not_500_when_status_check_raises_authentication_error(self):
        """A credentials problem while checking for an existing connection must not crash the view."""
        self.client.force_login(self.superuser)
        with patch("workos_login.admin.get_connection_status", side_effect=AuthenticationError("bad key")):
            response = self.client.get(self._url())
        self.assertRedirects(response, self._change_url(), fetch_redirect_response=False)

    def test_uses_configured_form_class(self):
        class CustomForm(CreateSAMLConnectionForm):
            custom_marker = django_forms.CharField(required=False, label="Custom Marker Field")

        self.client.force_login(self.superuser)
        with patch.object(LoginRuleAdmin, "create_connection_form_class", CustomForm):
            with patch("workos_login.admin.get_connection_status", return_value=None):
                response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Custom Marker Field")

    def test_get_happy_path_renders_form(self):
        self.client.force_login(self.superuser)
        with patch("workos_login.admin.get_connection_status", return_value=None):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create Connection")

    def test_post_happy_path_creates_connection_and_redirects(self):
        self.client.force_login(self.superuser)
        created = Mock(state="active")
        with patch("workos_login.admin.get_connection_status", return_value=None):
            with patch("workos_login.admin.create_saml_connection", return_value=created) as mock_create:
                response = self.client.post(self._url(), data={
                    "idp_metadata_url": "https://idp.example.com/metadata",
                    "connection_type": "GenericSAML",
                })

        self.assertRedirects(response, self._change_url(), fetch_redirect_response=False)
        mock_create.assert_called_once_with(
            self.rule,
            name="",
            connection_type="GenericSAML",
            idp_metadata_url="https://idp.example.com/metadata",
            idp_entity_id="",
            idp_sso_url="",
            idp_signing_cert="",
        )

    def test_post_invalid_form_does_not_call_create(self):
        self.client.force_login(self.superuser)
        with patch("workos_login.admin.get_connection_status", return_value=None):
            with patch("workos_login.admin.create_saml_connection") as mock_create:
                response = self.client.post(self._url(), data={})

        self.assertEqual(response.status_code, 200)
        mock_create.assert_not_called()

    def test_post_bad_request_error_rerenders_form_with_error(self):
        self.client.force_login(self.superuser)
        with patch("workos_login.admin.get_connection_status", return_value=None):
            with patch("workos_login.admin.create_saml_connection", side_effect=BadRequestError("bad metadata")):
                response = self.client.post(self._url(), data={
                    "idp_metadata_url": "https://idp.example.com/metadata",
                })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "bad metadata")

    def test_post_server_error_shows_message_and_redirects(self):
        self.client.force_login(self.superuser)
        with patch("workos_login.admin.get_connection_status", return_value=None):
            with patch("workos_login.admin.create_saml_connection", side_effect=ServerError("boom")):
                response = self.client.post(self._url(), data={
                    "idp_metadata_url": "https://idp.example.com/metadata",
                })

        self.assertRedirects(response, self._change_url(), fetch_redirect_response=False)
