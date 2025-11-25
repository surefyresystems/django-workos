import django.dispatch

# for jit creation workos_user_created will be called after the user is saved.
workos_user_created = django.dispatch.Signal()
workos_send_magic_link = django.dispatch.Signal()

# Signal sent when a PING user successfully logs in
# Provides: user, profile, rule, request
workos_ping_login = django.dispatch.Signal()
