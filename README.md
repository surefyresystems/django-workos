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

1. Add "polls" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'polls',
    ]

2. Include the polls URLconf in your project urls.py like this::

    path('polls/', include('polls.urls')),

3. Run ``python manage.py migrate`` to create the polls models.

4. Start the development server and visit http://127.0.0.1:8000/admin/
   to create a poll (you'll need the Admin app enabled).

5. Visit http://127.0.0.1:8000/polls/ to participate in the poll.
