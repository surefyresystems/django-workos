import django.dispatch

# for jit creation workos_user_created will be called after the user is saved.
workos_user_created = django.dispatch.Signal()
workos_send_magic_link = django.dispatch.Signal()
workos_magic_link_successful = django.dispatch.Signal()
workos_sso_successful = django.dispatch.Signal()
workos_mfa_successful = django.dispatch.Signal()
workos_send_email_verification = django.dispatch.Signal()
workos_email_verified = django.dispatch.Signal()
