from dataclasses import dataclass
from functools import partial
from unittest.mock import patch

from django.contrib.auth import get_user_model, get_user
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse

from workos_login.models import LoginRule, LoginMethods, UserLogin
import workos

from workos_login.utils import jit_create_user

workos.api_key = "mock"
workos.client_id = "mock"


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

    @patch('workos.client.sso.get_profile_and_token', wraps=partial(get_profile_and_token, organization_id="sso_org", id="1234"), org_id="org_id")
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
            jit_creation=True,
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
