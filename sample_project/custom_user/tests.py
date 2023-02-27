from django.test import TestCase

from .models import OfficeLocation
from workos_login.exceptions import RelationDoesNotExist
from workos_login.models import LoginRule, LoginMethods, JitMethods
from workos_login.utils import jit_create_user


# Create your tests here.
class SampleTests(TestCase):

    def setUp(self):
        self.sso_rule = LoginRule.objects.create(
            name="JIT Creation",
            method=LoginMethods.SAML_SSO,
            jit_creation_type=JitMethods.ATTRIBUTES_MATCH,
            priority=3,
        )
    def test_user_creation(self):
        profile = {
            "first_name": "Santana",
            "last_name": "Clause",
            "email": "sclause@northpole.net",
            "id": "123",
            "idp_id": "333",
            "raw_attributes": {
                "location": {
                    "locId": "123abc",
                    "address": "fake addr"
                }
            }
        }

        saved_attrs = {
            "~user_location": {
                "location_id": "{{profile.raw_attributes.location.locId}}"
            },
            "user_location": {
                "location_id": "{{profile.raw_attributes.location.locId}}",
                "address": "{{profile.raw_attributes.location.address}}"
            }
        }
        self.sso_rule.saved_attributes = saved_attrs

        user = jit_create_user(self.sso_rule, profile)
        self.assertEqual(user.first_name, "Santana")
        self.assertEqual(user.user_location.address, "fake addr")
        self.assertEqual(user.user_location.location_id, "123abc")


    def test_user_creation_location_required(self):
        """
        Make sure if the location is required but does not exist user does not get created.
        """
        profile = {
            "first_name": "Santana",
            "last_name": "Clause",
            "email": "sclause@northpole.net",
            "id": "123",
            "idp_id": "333",
            "raw_attributes": {
                "location": {
                    "locId": "123abc",
                    "address": "fake addr"
                }
            }
        }

        saved_attrs = {
            "!user_location": {
                "location_id": "{{profile.raw_attributes.location.locId}}"
            },
            "user_location": {
                "location_id": "{{profile.raw_attributes.location.locId}}",
                "address": "{{profile.raw_attributes.location.address}}"
            }
        }
        self.sso_rule.saved_attributes = saved_attrs

        with self.assertRaises(RelationDoesNotExist):
            user = jit_create_user(self.sso_rule, profile)

        # Now create the location, but don't set the address - it will get filled out by update
        ol = OfficeLocation.objects.create(location_id="123abc", address="real addr")
        user = jit_create_user(self.sso_rule, profile)
        self.assertEqual(user.first_name, "Santana")
        self.assertEqual(user.user_location.address, "fake addr")
        self.assertEqual(user.user_location.location_id, "123abc")
        self.assertEqual(user.user_location, ol)
