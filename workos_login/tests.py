from django.test import TestCase

from workos_login.models import LoginRule


class LoginRuleTest(TestCase):
    def setUp(self) -> None:
        pass

    def test_priority(self):
        priority_one = LoginRule.objects.create(
            name="Pri 1",
            mfa=False,
            connection_id="1",
            priority=1,
            email_regex="test@sso.com"
        )

        priority_two = LoginRule.objects.create(
            name="Pri 2",
            mfa=True,
            priority=2,
            email_regex="@mfa.com"
        )

        priority_three = LoginRule.objects.create(
            name="Pri 3",
            mfa=False,
            priority=3,
            email_regex="@mfa.com"
        )

        rule = LoginRule.objects.find_rule_for_username("user1@mfa.com")
        self.assertEqual(rule, priority_two)
