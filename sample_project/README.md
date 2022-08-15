

## Default Rules

| Rule Name     | Method          | Setup                                                                                                                                                                                                                                                                                                                | Notes                                                           | 
|---------------|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| Google SSO    | Google OAuth    | Must have Google OAuth enabled on Work OS acocunt                                                                                                                                                                                                                                                                    | Just in time creation will also set user and profile attributes |
| MFA Required  | MFA             | Any user that is the group "MFA Required" will be forced to setup MFA on first login                                                                                                                                                                                                                                 |                                                                 |
| Microsoft SSO | Microsoft OAuth | Must have Microsoft OAuth enabled on WorkOS account                                                                                                                                                                                                                                                                  |                                                                 |
| Magic Email   | Passwordless    | The [console email backend](https://docs.djangoproject.com/en/4.1/topics/email/#console-backend) is used by default, monitor your CLI that is running django to get link and copy and paste into browser.                                                                                                            |                                                                 |
| Okta SSO      | SAML SSO        | Must have a [demo credentials](https://workos.com/docs/dashboard/demo-credentials) enabled. Once you have that setup enter the connection or org ID in the admin settings for this rule. Just in time is not setup for this rule - create a user account for the test user that the demo credentials create for you. |                                                                 |


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

