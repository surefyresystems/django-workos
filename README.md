# Django WorkOS

Django WorkOS builds on top of Django contrib auth to support a variety of login methods.
Django WorKOS adds support for the following login methods:

1. Username/Password authentication provided by `django.contrib.auth`
2. SSO authentication provided by [WorkOS](https://workos.com)
3. MFA authentication provided by `django.contrib.auth` (first factor) and [WorkOS](https://workos.com) (second factor)
4. Passwordless login (magic emails) provided by [WorkOS](https://workos.com)

You can enable one or more of the above methods.
Configuration is done using Login Rules. 

## Installing

```
pip install django-workos
```

## Sample Project
View a [sample project](sample_project/README.md) or view [demo videos](sample_project/README.md#demo-videos) here

## Login Rules

A login rule applies to a set of users to control their login method.
There is no limit to the number of login rules but only one will apply to any given user.
Login rules are checked in priority order - the lowest priority that applies to a given user is the login rule they will use.
By default, a single rule will be installed which is Username/Password which applies to all users.

### Creating a login rule

Here are the available settings for login rules when creating in the admin

| Property Name            | Description                                                                                                                                                                                                                                                                                                                                             |
|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Name                     | A human readable identifier (this can be changed at any time)                                                                                                                                                                                                                                                                                           |
| Method                   | The login method for this rule - all rules only have a single login method.                                                                                                                                                                                                                                                                             |
| Priority                 | If a user has multiple rules that apply the lowest priority wins                                                                                                                                                                                                                                                                                        |
| Email Regular Expression | A regex to match on email address of user. Example to match two domains `^.+@(domain)\.com$`                                                                                                                                                                                                                                                            |
| Lookup Attributes        | A JSON structure to lookup a user based on attributes. Example to apply a rule for user in group ID 1 `{"groups__in": [1]}`. Example to apply a login rule for superusers `{"is_superuser": true}`. There are two special attributes `{"has_mfa": true}` and `{"has_sso": true}` which can be used to include users that have mfa or sso already setup. |
| Connection ID            | The WorkOS connection id for SAML SSO (only used for SAML SSO)                                                                                                                                                                                                                                                                                          |
| Organization ID          | The WorkOS organization id for SAML SSO (only used for SAML SSO). Only need either connection or org ID                                                                                                                                                                                                                                                 |                                                                                                                                  
| Just in time creation    | Should users be able to login if they don't already have an account. If set to Matching Attributes, then any user where email regex that matches will be created. Otherwise you can include all IdP logins regardless if they have matching email/attributes.                                                                                           |
| JIT Groups               | What groups should be assigned to a user account that is created with this rule                                                                                                                                                                                                                                                                         |
| Saved Attributes         | What attributes should be assigned to users created with this rule. This is only used for SSO method. Example `{"is_superuser": true}`                                                                                                                                                                                                                  |
| TOTP Organization Name   | The organization name used for authenticator apps. Only used for MFA. This name will appear in the authenticator app.                                                                                                                                                                                                                                   |


## Quick start

1. Add "workos_login" to your INSTALLED_APPS setting and make sure it is before `admin`:
```
    INSTALLED_APPS = [
        'workos_login',
        'workos_login.admin_site.AdminLoginConfig',
        ...
    ]
```

2. Update admin if you have `'django.contrib.admin'` in your INSTALLED_APPS replace it with `'workos_login.admin_site.AdminLoginConfig'`.
If you are already using a custom site admin, you should have it inherit from `workos_login.admin_site.AdminSharedLogin` which will fix the admin backdoor.

3. Change your login urls from `path('accounts/', include('django.contrib.auth.urls'))`  to `path('accounts/', include('workos_login.urls'))`

4. Run `python manage.py migrate` to create the needed models.

5. Update your logo by creating a file called registration/logo.html and add an `img` tag.
6. Optionally set your bootstrap location by overriding `registration/bootstrap.html` and have a single `link` tag to your bootstrap stylesheet (javascript bootstrap file is not required)
7. If you use django-stronghold or any other framework to require logins make sure allow all `/accounts` URLs.


## Configuration

You can customize this package with some settings that can be added to your `settings.py` file

| Setting Name                  | Default                                | Description                                                                                                                                                                                                                                                              | 
|-------------------------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `WORKOS_CLIENT_ID`            | `None`                                 | Must set your WorkOS client ID either with this setting or as an env variable with the same name                                                                                                                                                                         |
| `WORKOS_API_KEY`              | `None`                                 | Must set your WorkOS API eith with this setting or as an env variable with the same name                                                                                                                                                                                 |
| `WORKOS_EMAIL_LOOKUP`         | `False`                                | Whether or not to allow for login by email address. It is up to the application to enforce unique lower case email addresses if this is setting is enabled                                                                                                               |
| `WORKOS_USERNAME_LOOKUP`      | `True`                                 | Whether or not to allow for login by username. Either this or `WORKOS_EMAIL_LOOKUP` must be set (or both can be set and it will check email first)                                                                                                                       |
| `WORKOS_SMS_MFA_TEMPLATE`     | `Your authentication code is {{code}}` | The MFA template that should be used for sending an SMS message. It must contain `{{code}}` where you want the 6 digit code to go                                                                                                                                        |
| `WORKOS_SEND_CUSTOM_EMAIL`    | `False`                                | Controls whether or not you would like your application to send magic emails or WorkOS platform to send. If set to `False` you need to listen to `workos_send_magic_link` signal. Example can be seen in the [sample project](sample_project/custom_user/models.py#L21). |
| `WORKOS_AUTO_UPDATE`          | `True`                                 | If using SSO should attributes (such as first name, email, custom attributes) be updated on every login? If this is `False` you will need to make sure to change attributes like email in both IdP and Django separately.                                                |
| `WORKOS_JIT_USERNAME`         | `email`                                | What should the username be set to? Options are `email`, `idp_id` or `id` (which is the WorkOS unique ID). For more control see Template Attributes section.                                                                                                             |
| `WORKOS_ACTIVE_USER_FILTER`   | `{'is_active': True}`                  | What is the filter to get active users? You should only need to change this if you have your own user model.                                                                                                                                                             |
| `LOGIN_REDIRECT_URL`          | `/accounts/profile/`                   | This [standard Django setting](https://docs.djangoproject.com/en/dev/ref/settings/#login-redirect-url) is respected to control where the user will end up after login                                                                                                    |

### Updating Templates

If you want to update the login page you can override `registration/login.html` to extend `registration/base_login.html` and override some blocks.

Example for adding some messages before/after the form:

```html
{% extends 'registration/base_login.html' %}
{% block before_form %}
Welcome back! Please add your username below.
{% endblock %}

{% block after_form %}
Don't have a login? <a href="{% url 'your_signup_view_name'%}">Signup Here</a>
{% endblock %}
```

## Logging In
django-workos supports both direct login (SP login) and if using SSO - IdP login.

### Using the login page
When logging in directly to your Django app you will be presented with a login screen that looks like this:

For all forms of login, if a `next` query parameter is provided the user will be redirected to that URL after authenticating.
If `next` is not provided `LOGIN_REDIRECT_URL` setting will be used to determine where to redirect the user.

Once a username is entered django-workos will determine which rule applies for this username.
The next step depends on the rule that applies:
#### Username / Password
If the login rule dictates username and password a password input will be presented.
There will also be a forgot your password link presented to allow users to reset password via email.

#### Magic Email
The user will be redirected to `magic_link_complete.html` template and an email will be sent.
Upon the user clicking the link in the email they will be authenticated.

#### MFA
If MFA applies to user will be prompted for a password and must complete that flow first.
After the user has provided a correct password they will be prompted to enter the second factor authentication code.

#### SSO / OAuth
If using SSO (or MS or Google OAuth) the user will be automatically redirected to the correct login page to follow the
standard SP login flow. 


### SSO IdP Login
If using SSO the user may also login using IdP login.
Make sure you have configured and [read about IdP login from WorkOS](https://workos.com/docs/sso/login-flows/idp-initiated-sso).

#### User lookup
If a user has ever successfully logged in using SSO (whether IdP or SP login), django-workos will save the ID that was used to be able to assist in future lookups.
However, the very first time django-workos will need to either find or create the user inside Django.
For IdP logins this is done by checking email address which is the most widely available way to try and find a user account.
If there is a single user with a case-insensitive email address match it will associate the login with the matched user.

## JIT User Creation
Just In Time (JIT) user creation happens when an SSO login rule matches a username/email but the user has not yet been created.
This can happen either with SP or IdP login methods.
django-workos will create the user and always set the first name, last name, email and username fields.
The username will be formatted based on the setting `WORKOS_JIT_USERNAME`.
You can have more control over the username by using template attributes outlined below.

Additionally, you can set groups or other attributes to be set on the user account using JIT Groups or JIT Attributes fields in the login rule.
JIT Attributes will follow nested related structures.
For instance, it is a common Django pattern to have a user profile 1-to-1 relationship with a user account.
You can see an example of this in the [Sample Project Profile Class](/sample_project/custom_user/models.py).

In the sample project you could have saved attributes that look like:
```json
{
  "is_staff": true, 
  "profile": {
    "organization_name": "Acme Inc."
  }
}
```
This would set the user as both a staff user and update the profile organization name.


### Template attributes
If you want to use extended attributes that are provided by SAML you can do so using template language.
For instance, if organization name was sent as SAML attribute from your IdP you could replace the above example with:
```json
{
  "is_staff": true,
  "profile": {
    "organization_name": "{{profile.raw_attributes.organization_name}}"
  }
}
```
The only context provided is `profile` which is a dictionary of items coming from [WorkOS Profile](https://workos.com/docs/reference/sso/profile).
#### Auto Update
If `WORKOS_AUTO_UPDATE` is set to `True` all template attributes will be re-evaluated at each login and will be updated.
So in the above example if the SAML organization name changes the user profile would get automatically updated.
If `WORKOS_AUTO_UPDATE` is set to `False` then only on JIT creation will the saved attributes be used.

### Linking to existing objects
django-workos provides the ability to link to existing objects during JIT creation.
For instance, if we have a foreign key from a user object to a location model we can link the two with `saved_attributes` like this:
```json
{
  "~location": {
    "locationId": "{{profile.raw_attributes.locationUuid}}"
  },
  "location": {
    "address": "{{profile.raw_attributes.locationAddress}}" 
  }
}
```
Any field that starts with a `~` signifies to try and do a lookup before a creation of a related object.
This roughly translates to:
```python
try:
    location = Location.objects.get(locationId=profile.raw_attributes.locationUuid)
    location.address = profile.raw_attributes.locationAddress
    user.location = location
except ObjectDoesNotExist:
    Location.object.create(
        locationId=profile.raw_attributes.locationUuid,
        address=profile.raw_attributes.locationAddress
    )
```

If you want to not create the user unless the object already exists use `!` instead of `~`.
```json
{
  "!location": {
    "locationId": "{{profile.raw_attributes.locationUuid}}"
  },
  "location": {
    "address": "{{profile.raw_attributes.locationAddress}}"
  }
}
```
In the above cause the JIT user will not be created if the `locationId` does not exist.

#### Username formatting
You can use template attributes to set the username, for example:
```json
{
  "username": "{{profile.first_name}}{{profile.last_name}}",
  "is_staff": true,
  "profile": {
    "organization_name": "{{profile.raw_attributes.organization_name}}"
  }
}
```
Just make sure that whatever username you set will be unique across all your users.

## Signals
django-workos provides two signals your application can listen to:

### workos_user_created
Listening to this signal is completely optional but may be useful if you want to do something when a new user logs in.
This signal is sent when a new user has been created due to a JIT user creation.
If you are not planning on enabling JIT you will not need to listen to this signal.
Example:

```python
from workos_login.signals import workos_user_created
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings

@receiver(workos_user_created)
def jit_user_created_handler(sender, **kwargs):
    """
    Handle a magic email custom send
    """
    new_user = kwargs["user"]
    workos_profile = kwargs["profile"]
    login_rule = kwargs["rule"]
    body = "{first_name} {last_name} has just signed up.".format(first_name=new_user.first_name, last_name=new_user.last_name)
    send_mail("New user created", body, settings.DEFAULT_FROM_EMAIL, [workos_profile["email"]])
```

### workos_send_magic_link
If `WORKOS_SEND_CUSTOM_EMAIL` is set to `True` you must listen to this signal in order to send the email.
Example:

```python
from workos_login.signals import workos_send_magic_link
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings

@receiver(workos_send_magic_link)
def jit_user_created_handler(sender, **kwargs):
    """
    Handle a magic email custom send
    """
    new_user = kwargs["user"]
    magic_link = kwargs["link"]
    login_rule = kwargs["rule"]
    email = new_user.email
    
    body = "Your magic link: {}".format(magic_link)
    send_mail("Your passwordless login link is ready", body, settings.DEFAULT_FROM_EMAIL, [email])
```
