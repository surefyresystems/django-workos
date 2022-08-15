from django import template

from workos_login.models import LoginRule

register = template.Library()


@register.simple_tag
def rule_applies_class(rule, user):
    if rule == LoginRule.objects.find_rule_for_username(user.username):
        return "table-success"
    elif rule.rule_applies_to_user(user):
        return "table-warning"
    return ""


@register.filter
def login_rule(user):
    return LoginRule.objects.find_rule_for_username(user.username)
