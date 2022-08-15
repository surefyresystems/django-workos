from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import admin, messages
from django.contrib.admin.apps import AdminConfig
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.utils.translation import gettext_lazy as _


class AdminSharedLogin(admin.AdminSite):

    @method_decorator(never_cache)
    def login(self, request, extra_context=None):
        if request.method == "GET" and self.has_permission(request):
            # Already logged-in, redirect to admin index
            index_path = reverse("admin:index", current_app=self.name)
            return redirect(index_path)

        if request.user.is_authenticated:
            # User is authenticated but does not have access to admin
            messages.warning(request, _("You are trying to access a portion of the site you do not have access to."))

        if (
                REDIRECT_FIELD_NAME not in request.GET
                and REDIRECT_FIELD_NAME not in request.POST
        ):
            next_url = reverse("admin:index", current_app=self.name)
        else:
            next_url = request.GET.get(REDIRECT_FIELD_NAME, request.POST.get(REDIRECT_FIELD_NAME))

        from django.contrib.auth.views import redirect_to_login
        return redirect_to_login(next_url)


class AdminLoginConfig(AdminConfig):
    default_site = 'workos_login.admin_site.AdminSharedLogin'
