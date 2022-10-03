import json
from typing import Optional

from django.contrib.auth import get_user_model
from django.core import signing
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from workos.exceptions import BadRequestException

from workos_login.conf import conf
from django.db import models
import workos


def find_user_by_email(email: str) -> Optional[models.Model]:
    """
    Given an email address find a user account that matches (case insensitive).
    If there are duplicates, none are returned.

    :param email: Email address
    :return: A user object or None (if duplicates or none found)
    """
    try:
        return get_user_model().objects.get(email__iexact=email)
    except (ObjectDoesNotExist, MultipleObjectsReturned):
        return None


def find_user(username_or_email: str) -> Optional[models.Model]:
    """
    Find a user given the username/email they entered in the form.
    If username is an exact match return that.
    If username is not found, and email lookup is enabled - look for the email (case insensitive).
    :param username_or_email: The username entered in the login form
    :return: User if found else None
    """
    user = None
    if conf.WORKOS_USERNAME_LOOKUP:
        try:
            user = get_user_model().objects.get(username=username_or_email)
        except ObjectDoesNotExist:
            pass
    if not user and conf.WORKOS_EMAIL_LOOKUP:
        user = find_user_by_email(username_or_email)
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
    username = rule.format_username(email=profile["email"], idp_id=profile["idp_id"], workos_id=profile["id"])
    user = get_user_model().objects.create_user(username=username, email=profile["email"],
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


def update_user_profile(user: models.Model, profile: dict, rule: models.Model) -> bool:
    """
    Called on SSO login to update user attributes if anything changed on the SSO side
    :param user: user that is logging in
    :param profile: profile returned from workos that contains first, last, email
    :param rule: the rule used for the login. This should be a form of SSO since only SSO logins have attributes that
                 can update user attributes.
    :return: True if user updated, false if user did not need update
    """
    needs_update = False
    if user.first_name != profile["first_name"]:
        user.first_name = profile["first_name"]
        needs_update = True

    if user.last_name != profile["last_name"]:
        user.last_name = profile["last_name"]
        needs_update = True

    if user.email != profile["email"]:
        user.email = profile["email"]
        needs_update = True

    if needs_update:
        user.save()

    return needs_update


def pack_state(state_dict: dict) -> str:
    """
    Pack state object into a string that will be used during handshake.
    State must be unpacked with unpack_state.
    This will sign the state so secrets cannot be seen and it will merge in
    any user defined state variables (which will not be signed).
    """
    state = signing.dumps(state_dict, compress=True)
    return json.dumps({"_": state, **conf.WORKOS_EXTRA_STATE})


def unpack_state(state_str: str) -> dict:
    """
    Unpack state that was packed with pack_state.
    Drop any extra state and only return what was originally packed.
    """
    state = json.loads(state_str)
    return signing.loads(state["_"])
