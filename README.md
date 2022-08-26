# Django WorkOS

Django WorkOS builds on top of Django contrib auth to support a variety of login methods.
Django WorKOS adds support for the following login methods:

1. Username/Password authentication provided by `django.contrib.auth`
2. SSO authentication provided by [WorkOS](https://workos.com)
3. MFA authentication provided by `django.contrib.auth` (first factor) and [WorkOS](https://workos.com) (second factor)
4. Passwordless login (magic emails) provided by [WorkOS](https://workos.com)

You can enable one or all of the above methods.
Configuration is done using Login Rules. 

## Sample Project
View a [sample project](sample_project/README.md) or view [demo videos](sample_project/README.md#demo-videos) here

## Login Rules

A login rule applies to a set of users to control their login method.
There is no limit to the number of login rules but only one will apply to any given user.
Login rules are checked in priority order - the lowest priority that applies to a given user is the login rule they will use.
By default, a single rule will be installed which is Username/Password which applies to all users.

### Creating a login rule

Here are the available settings for login rules when creating in the admin

| Property Name            | Description                                                                                                                                                                                        |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Name                     | A human readable identifier (this can be changed at any time)                                                                                                                                      |
| Method                   | The login method for this rule - all rules only have a single login method.                                                                                                                        |
| Priority                 | If a user has multiple rules that apply the lowest priority wins                                                                                                                                   |
| Email Regular Expression | A regex to match on email address of user. Example to match two domains `^.+@(domain                                                                                                               |domain2)\.com$` |
| Lookup Attributes        | A JSON structure to lookup a user based on attributes. Example to apply a rule for user in group ID 1 `{"groups__in": [1]}`. Example to apply a login rule for superusers `{"is_superuser": true}` |
| Connection ID            | The WorkOS connection id for SAML SSO (only used for SAML SSO)                                                                                                                                     |
| Organization ID          | The WorkOS organization id for SAML SSO (only used for SAML SSO). Only need either connection or org ID                                                                                            |                                                                                                                                  
| Just in time creation    | Should users be able to login if they don't already have an account. If enable the account will be created automatically                                                                           |
| JIT Groups               | What groups should be assigned to a user account that is created with this rule                                                                                                                    |
| JIT Attributes           | What attributes should be assigned to users created with this rule. Example `{"is_superuser": true}`                                                                                               |
| TOTP Organization Name   | The organization name used for authenticator apps. Only used for MFA. This name will appear in the authenticator app.                                                                              |


Quick start
-----------

1. Add "workos_login" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'workos_login',
    ]

2. Update admin if you have `'django.contrib.admin'` in your INSTALLED_APPS replace it with `'workos_login.admin_site.AdminLoginConfig'`.
If you are already using a custom site admin, you should have it inherit from `workos_login.admin_site.AdminSharedLogin` which will fix the admin backdoor.

3. Change your login urls from `path('accounts/', include('django.contrib.auth.urls'))`  to `path('accounts/', include('workos_login.urls'))`

4. Run ``python manage.py migrate`` to create the polls models.

5. Update your logo by creating a file called registration/logo.html and add an `img` tag.
6. Optionally set your bootstrap location by overriding `registration/bootstrap.html` and have a single `link` tag to your bootstrap stylesheet (javascript bootstrap file is not required)
7. If you use django-stronghold or any other framework to require logins make sure allow all `/accounts` URLs.

