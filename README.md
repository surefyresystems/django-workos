# Django WorkOS

Django WorkOS builds on top of Django contrib auth to support a variety of login methods.
Django WorKOS adds support for the following login methods:

1. Username/Password authentication provided by `django.contrib.auth`
2. SSO authentication provided by [WorkOS](https://workos.com)
3. MFA authentication provided by `django.contrib.auth` (first factor) and [WorkOS](https://workos.com) (second factor)
4. Passwordless login (magic emails) provided by [WorkOS](https://workos.com)

You can enable one or all of the above methods.
Configuration is done using Login Rules. 

## Login Rules

A login rule applies to a set of users to control their login method.
There is no limit to the number of login rules but only one will apply to any given user.
Login rules are checked in priority order - the lowest priority that applies to a given user is the login rule they will use.
By default, a single rule will be installed which is Username/Password which applies to all users.

### Creating a login rule

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

