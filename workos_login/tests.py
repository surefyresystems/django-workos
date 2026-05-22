from dataclasses import dataclass
from functools import partial
from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth import get_user_model, get_user
from django.contrib.messages import get_messages
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TestCase, RequestFactory, override_settings
from django.urls import reverse
from django.core import mail
from django.utils import timezone

from workos_login.models import LoginRule, LoginMethods, UserLogin
import workos

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
    def dict(self):
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

    def test_email_contains_code(self):
        """Test that email contains the verification code"""
        request = self._create_request_with_session()

        send_email_verification_code(request, self.user)

        code = request.session[SESSION_EMAIL_VERIFICATION_KEY]
        email_body = mail.outbox[0].body
        self.assertIn(code, email_body)

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

        result = verify_email_code(request, "654321")

        self.assertFalse(result)

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

        result = verify_email_code(request, "123456")

        self.assertFalse(result)

    def test_verify_wrong_user(self):
        """Test that verification fails for different user"""
        other_user = get_user_model().objects.create_user(username='other', email='other@example.com')
        request = self._create_request_with_session()
        request.session[SESSION_EMAIL_VERIFICATION_KEY] = "123456"
        request.session[SESSION_EMAIL_VERIFICATION_USER_KEY] = other_user.id
        request.session[SESSION_EMAIL_VERIFICATION_TIMESTAMP] = timezone.now().isoformat()
        request.user = self.user

        result = verify_email_code(request, "123456")

        self.assertFalse(result)

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
