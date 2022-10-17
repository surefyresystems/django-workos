import json
from typing import Optional, Any

from django.contrib.auth import get_user_model
from django.core import signing
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned, FieldDoesNotExist
from django.template import Template, Context
from workos.exceptions import BadRequestException

from workos_login.conf import conf
from django.db import models, transaction
import workos

from workos_login.exceptions import RelationDoesNotExist


def get_users():
    return get_user_model().objects.filter(**conf.WORKOS_ACTIVE_USER_FILTER)


def find_user_by_email(email: str) -> Optional[models.Model]:
    """
    Given an email address find a user account that matches (case insensitive).
    If there are duplicates, none are returned.

    :param email: Email address
    :return: A user object or None (if duplicates or none found)
    """
    try:
        return get_users().get(email__iexact=email)
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
            user = get_users().get(username=username_or_email)
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
    """
    Get or create a user login model
    """
    from workos_login.models import UserLogin
    try:
        return UserLogin.objects.get(user=user)
    except UserLogin.DoesNotExist:
        return UserLogin.objects.create(user=user)


def has_user_login_model(user: models.Model) -> bool:
    """
    Check to see if a user login model exists.
    :param user: The user object
    :return: True if user model exists, false otherwise.
    """
    from workos_login.models import UserLogin
    return UserLogin.objects.filter(user=user).exists()


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


def render_attribute(value: Any, profile: dict) -> Any:
    """
    Helper to render an attribute that will convert strings to templates that are provided with `profile`.
    If value is a dictionary it will nest down and render the leaf values.
    :param value: the attribute value to render
    :param profile: the profile dict passed from WorkOS
    :return: Rendered value to save
    """
    if isinstance(value, dict):
        for k, v in value.items():
            value[k] = render_attribute(v, profile)
    if isinstance(value, str):
        t = Template(value)
        c = Context({"profile": profile})
        return t.render(c)
    return value


def _link_attributes(obj: models.Model, attributes: Optional[dict], profile: dict) -> None:
    """
    Given a user object link any attributes that are needed.

    :param obj: A user object to link related objects to
    :param attributes: The saved attributes that will be used to try and link attributes.
    :param profile: Profile as provided by WorkOS
    """
    if not attributes:
        return

    for field_name, value in attributes.items():
        if field_name.startswith(("!", "~")) is False:
            continue
        required = field_name.startswith("!")
        field_name = field_name[1:]
        # This should not error out since "!/~" can only be used for fields that exist and have related lookups.
        field = obj._meta.get_field(field_name)
        try:
            related_instance = field.related_model.objects.get(**render_attribute(value, profile))
        except ObjectDoesNotExist:
            related_instance = None

        if required and related_instance is None:
            raise RelationDoesNotExist()

        setattr(obj, field_name, related_instance)

def _update_attributes(obj: models.Model, attributes: Optional[dict], profile: dict, template_only: bool=False) -> None:
    """
    Update an object passed in with any attributes defined. The attributes can be a template to access profile data.
    :param obj: The object to update
    :param attributes: A dictionary of attributes to update. Ex. {"username": "{{profile.first_name}}{{profile.last_name}}"}
    :param profile: The WorkOS provided profile https://workos.com/docs/reference/sso/profile
    :param template_only: If True, only update fields that rely on template and do not update static attributes.
    :return None:
    """
    if not attributes:
        return

    for field_name, value in attributes.items():
        if field_name.startswith(("!", "~")):
            continue
        try:
            field = obj._meta.get_field(field_name)
        except FieldDoesNotExist:
            # Even though this isn't a proper field it might be some custom attribute or settable property.
            # Still set the attribute if it exists on the object.
            if hasattr(obj, field_name) and (template_only is False or value != render_attribute(value, profile)):
                setattr(obj, field_name, render_attribute(value, profile))
            continue

        if field.is_relation is False:
            # If template only, do not update if the value equals the rendered value which implies it is not a template field.
            if template_only is False or value != render_attribute(value, profile):
                setattr(obj, field_name, render_attribute(value, profile))

        elif field.many_to_one or field.one_to_one:
            if value is None:
                if template_only is False:
                    setattr(obj, field_name, None)
            else:
                # Might need to create object
                related_obj = getattr(obj, field_name)
                if related_obj is None:
                    # Need to create object with the top level attributes
                    related_obj_attrs = {k: v for k,v in value.items() if not isinstance(v, dict)}
                    related_obj = field.related_model.objects.create(**related_obj_attrs)
                    setattr(obj, field_name, related_obj)

                _update_attributes(getattr(obj, field_name), value, profile)

    obj.save()


def jit_create_user(rule: models.Model, profile: dict) -> models.Model:
    """
    Given a profile from workos and a rule create a user
    """
    # Make sure if user (or related object fails) transaction rolls back
    with transaction.atomic():
        username = rule.format_username(profile)
        user = get_user_model().objects.create_user(username=username, email=profile["email"],
                                                    first_name=profile["first_name"], last_name=profile["last_name"],
                                                    is_active=False)
        user.set_unusable_password()
        _link_attributes(user, rule.saved_attributes, profile)
        _update_attributes(user, rule.saved_attributes, profile)
        # Only mark them active once we know the user has been created successfully unless explicitly set in rule.
        if "is_active" not in rule.saved_attributes:
            user.is_active = True
        user.save()

        for group in rule.jit_groups.all():
            user.groups.add(group)

    return user


def update_user_profile(user: models.Model, rule: Optional[models.Model], profile: dict) -> None:
    """
    Called on SSO login to update user attributes if anything changed on the SSO side
    :param user: user that is logging in
    :param profile: profile returned from workos that contains first, last, email
    :param rule: the rule used for the login. This should be a form of SSO since only SSO logins have attributes that
                 can update user attributes.
    """
    if conf.WORKOS_AUTO_UPDATE is True and rule:
        user.first_name = profile["first_name"]
        user.last_name = profile["last_name"]
        user.email = profile["email"]
        _update_attributes(user, rule.saved_attributes, profile, template_only=True)


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
