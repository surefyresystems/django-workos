
## Quick Start
1. Update your WorkOS staging environment to allow for callbacks to your `http://localhost:8000/accounts/callback/magic/` and `http://localhost:8000/accounts/callback/sso/`
2. Set your credentials WorkOS credentials. This can be done with environment variables or go to `settings.py` and update lines 60 & 61 to uncomment and set `WORKOS_API_KEY` `WORKOS_CLIENT_ID`
3. Install dependencies (in a virtual environment):
   4. `pip install -e ../.` to install django-workos
   5. `pip install django`
3. Run `python manage.py migrate` to create the models.
4. Start the development server `python manage.py runserver` and visit http://127.0.0.1:8000/
5. Try logging in with the below default users

## Default Users

| Username Name | Email             | Method              | Password      |
|---------------|-------------------|---------------------|---------------|
| admin         | admin@basic.local | Username/password   | django-workos |
| mfa           | mfa@example.com   | Username + MFA      | django-workos |
| magic         | magic@example.com | Passwordless Email  | N/A           |
|               | .*@gmail.com      | Google OAuth SSO    | N/A           |
|               | .*@outlook.com    | Microsoft OAuth SSO | N/A           |

For the Google and Microsoft OAuth SSO Integration it uses just in time account creation.
A user will get automatically created when you sign in.

## Default Rules

| Rule Name     | Method          | Setup                                                                                                                                                                                                                                                                                                                | Notes                                                           | 
|---------------|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| Google SSO    | Google OAuth    | Must have Google OAuth enabled on Work OS acocunt                                                                                                                                                                                                                                                                    | Just in time creation will also set user and profile attributes |
| MFA Required  | MFA             | Any user that is the group "MFA Required" will be forced to setup MFA on first login                                                                                                                                                                                                                                 |                                                                 |
| Microsoft SSO | Microsoft OAuth | Must have Microsoft OAuth enabled on WorkOS account                                                                                                                                                                                                                                                                  |                                                                 |
| Magic Email   | Passwordless    | The [console email backend](https://docs.djangoproject.com/en/4.1/topics/email/#console-backend) is used by default, monitor your CLI that is running django to get link and copy and paste into browser.                                                                                                            |                                                                 |
| Okta SSO      | SAML SSO        | Must have a [demo credentials](https://workos.com/docs/dashboard/demo-credentials) enabled. Once you have that setup enter the connection or org ID in the admin settings for this rule. Just in time is not setup for this rule - create a user account for the test user that the demo credentials create for you. |                                                                 |


## Demo Videos

### Outlook OAuth

Example OAuth login: https://www.loom.com/share/6325a0608da34cd2b394818eea2a60d6

### MFA
Example Enrollment: https://www.loom.com/share/efb399a68348402eb2be31a7cd30c2b1

### Okta SSO
Example Login: https://www.loom.com/share/2372334504d845059b05bc3c86c6ad62
