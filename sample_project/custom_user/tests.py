from django.test import TestCase

from .models import OfficeLocation, User, Address
from workos_login.exceptions import RelationDoesNotExist
from workos_login.models import LoginRule, LoginMethods, JitMethods
from workos_login.utils import jit_create_user, update_user_profile


# Create your tests here.
class SampleTests(TestCase):

    def setUp(self):
        User.objects.all().delete() # Delete the sample users
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
                    "address": "fake addr",
                    "city": "Fake City"
                }
            }
        }

        saved_attrs = {
            "~user_location": {
                "location_id": "{{profile.raw_attributes.location.locId}}"
            },
            "user_location": {
                "location_id": "{{profile.raw_attributes.location.locId}}",
                "addresses": [
                    {
                        "address1": "{{profile.raw_attributes.location.address}}",
                        "city": "{{profile.raw_attributes.location.city}}"
                    }
                ]
            }
        }
        self.sso_rule.saved_attributes = saved_attrs

        user = jit_create_user(self.sso_rule, profile)
        user = User.objects.get(pk=user.pk)
        self.assertEqual(user.first_name, "Santana")
        self.assertEqual(user.user_location.addresses.first().address1, "fake addr")
        self.assertEqual(user.user_location.addresses.first().city, "Fake City")
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
                "addresses": [
                    {
                        "address1": "{{profile.raw_attributes.location.address}}",
                        "state": "CA"
                    }
                ],
                "meeting_rooms": [
                    {
                        "name": "room1"
                    },
                    {
                        "name": "room2"
                    }
                ]
            }
        }
        self.sso_rule.saved_attributes = saved_attrs

        with self.assertRaises(RelationDoesNotExist):
            user = jit_create_user(self.sso_rule, profile)

        # Now create the location, but don't set the address - it will get filled out by update
        ol = OfficeLocation.objects.create(location_id="123abc")
        user = jit_create_user(self.sso_rule, profile)
        user = User.objects.get(pk=user.pk)
        self.assertEqual(user.first_name, "Santana")
        self.assertEqual(user.user_location.addresses.first().address1, "fake addr")
        self.assertEqual(user.user_location.addresses.first().state, "CA")
        self.assertEqual(user.user_location.location_id, "123abc")
        self.assertEqual(user.user_location, ol)
        self.assertEqual(set(user.user_location.meeting_rooms.values_list("name", flat=True)), {"room1", "room2"})
        self.assertEqual(User.objects.count(), 1)

        profile = {
            "first_name": "Second",
            "last_name": "Clause",
            "email": "secondclause@northpole.net",
            "id": "432",
            "idp_id": "444",
            "raw_attributes": {
                "location": {
                    "locId": "123abc",
                    "address": "fake addr"
                }
            }
        }
        user = jit_create_user(self.sso_rule, profile)
        user = User.objects.get(pk=user.pk)

        self.assertEqual(user.first_name, "Second")
        self.assertEqual(user.user_location.addresses.first().address1, "fake addr")
        self.assertEqual(user.user_location.addresses.first().state, "CA")
        self.assertEqual(user.user_location.location_id, "123abc")
        self.assertEqual(user.user_location, ol)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(Address.objects.count(), 1, "Since address did not change there should only be one")

        update_user_profile(user, self.sso_rule, profile)
        user = User.objects.get(pk=user.pk)

        self.assertEqual(user.first_name, "Second")
        self.assertEqual(user.user_location.addresses.first().address1, "fake addr")
        self.assertEqual(user.user_location.addresses.first().state, "CA")
        self.assertEqual(user.user_location.location_id, "123abc")
        self.assertEqual(user.user_location, ol)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(Address.objects.count(), 1, "Since address did not change there should only be one")


        profile = {
            "first_name": "Second",
            "last_name": "Clause",
            "email": "secondclause@northpole.net",
            "id": "432",
            "idp_id": "444",
            "raw_attributes": {
                "location": {
                    "locId": "123abc",
                    "address": "New Addr"
                }
            }
        }

        update_user_profile(user, self.sso_rule, profile)
        user = User.objects.get(pk=user.pk)

        self.assertEqual(user.first_name, "Second")
        self.assertEqual(user.user_location.addresses.first().address1, "fake addr")
        self.assertEqual(user.user_location.addresses.first().state, "CA")
        self.assertEqual(user.user_location.location_id, "123abc")
        self.assertEqual(user.user_location, ol)
        self.assertEqual(OfficeLocation.objects.count(), 1)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(Address.objects.count(), 2, "Since address did change it will create a new one")
