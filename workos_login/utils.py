from typing import Optional

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.functions import Lower
from workos.exceptions import BadRequestException

from workos_login.conf import conf
from django.db import models
import workos


def find_user(username_or_email: str) -> Optional[models.Model]:
    user = None
    if(conf.WORKOS_EMAIL_LOOKUP):
        try:
            user = get_user_model().objects.annotate(email_lower=Lower('email')).get(email_lower=username_or_email.lower())
        except ObjectDoesNotExist:
            pass
    if(not user and conf.WORKOS_USERNAME_LOOKUP):
        try:
            user = get_user_model().objects.get(username=username_or_email)
        except ObjectDoesNotExist:
            pass
    return user


def user_has_mfa_enabled(user: models.Model) -> bool:
    from workos_login.models import UserLogin
    try:
        user_login = UserLogin.objects.get(user=user)
        return user_login.mfa_enabled and user_login.mfa_factor
    except UserLogin.DoesNotExist:
        return False


def get_user_login_model(user: models.Model) -> models.Model:
    from workos_login.models import UserLogin
    try:
        return UserLogin.objects.get(user=user)
    except UserLogin.DoesNotExist:
        return UserLogin.objects.create(user=user)


def totp_verify_code(factor_id: str, code: str) -> bool:
    challenge_id = workos.client.mfa.challenge_factor(authentication_factor_id=factor_id).get("id")
    return verify_challenge(challenge_id, code)


def verify_challenge(challenge_id: str, code: str) -> bool:
    """
    Given a challenge ID verify that it is correct
    :param challenge_id: challenge id to verify
    :param code: user entered code
    :return: True if valid, False otherwise
    """
    try:
        response = workos.client.mfa.verify_challenge(authentication_challenge_id=challenge_id, code=code)
    except BadRequestException as e:
        return False

    if not response.get("valid", False):
        return False
    return True


def mfa_enroll(user: models.Model, factor_id: str, mfa_type: str) -> None:
    """
    Call this once MFA has been successfully enrolled and at least one verification has passed
    :param user: user to enroll
    :param mfa_type: type of MFA ("sms" or "totp")
    :param factor_id: factor_id to use
    """
    user_login = get_user_login_model(user)
    user_login.mfa_type = mfa_type
    user_login.mfa_factor = factor_id
    user_login.save()


def jit_create_user(profile: dict, rule: models.Model) -> models.Model:
    """
    Given a profile from workos and a rule create a user
    """
    related_attributes = {k: v for k, v in rule.jit_attributes.items() if isinstance(v, dict)}
    user_attributes = {k: v for k, v in rule.jit_attributes.items() if k not in related_attributes}
    print(related_attributes)
    print(user_attributes)

    user = get_user_model().objects.create_user(username=profile["email"], email=profile["email"],
                                                first_name=profile["first_name"], last_name=profile["last_name"],
                                                is_active=False, **user_attributes)
    user.set_unusable_password()
    # Only mark them active once we know the user has been created successfully.
    user.is_active = True
    user.save()

    for group in rule.jit_groups.all():
        user.groups.add(group)

    for attr, values in related_attributes.items():
        item_to_update = getattr(user, attr)
        for k, v in values.items():
            setattr(item_to_update, k, v)
        item_to_update.save()

    return user
