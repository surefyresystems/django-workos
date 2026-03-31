from django.utils.html import format_html
from workos.exceptions import BadRequestException
from django.utils.translation import gettext_lazy as _
import copy
from workos_login.models import LoginRule, UserLogin

from django.contrib import admin
from workos import client as workos_client
from workos_login.utils import has_sandbox_credentials


class LoginRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "priority", "method")
    filter_horizontal = ("jit_groups",)
    readonly_fields = ('portal_link',)
    fieldsets = (
        (None, {
            'fields': ('name', 'method', 'priority')
        }),
        ('Users this rule applies to', {
            'fields': ('email_regex', 'lookup_attributes',)
        }),
        ('SSO Options', {
            'fields': ('connection_id', 'organization_id', 'saved_attributes', 'jit_creation_type', 'jit_groups', 'portal_link', 'auto_update')
        }),
        ('MFA Options', {
            'fields': ('totp_organization_name',)
        }),
    )

    def get_fieldsets(self, *args, **kwargs):
        fieldset = super().get_fieldsets(*args, **kwargs)
        # If there are no sandbox credentials - leave the default of production only
        if has_sandbox_credentials():
            ret = copy.deepcopy(fieldset)
            ret[0][1]["fields"] += ("environment",)
            return ret
        return fieldset

    @admin.display(
        description='Portal Link',
    )
    def portal_link(self, obj):
        if obj and obj.organization_id:
            try:
                portal_link = workos_client.portal.generate_link(
                    organization=obj.organization_id, intent="sso",
                )
                return format_html("<a href='{}'>Link to WorkOS Portal</a>", portal_link["link"])
            except BadRequestException:
                return _("You cannot have a portal link unless you set an Admin Portal Redirect Link")
        return _("Only available for SSO with organization ID set.")


class UserLoginAdmin(admin.ModelAdmin):
    list_display = ("user", "user_email", "rule")
    list_filter = ("rule",)
    readonly_fields = fields = ("mfa_factor", "mfa_type", "sso_id", "idp_id", "user", "rule", "created_at", "last_modified")
    search_fields = ("user__username", "user__first_name", "user__last_name", "user__email")

    @admin.display(description='Email', ordering='user__email')
    def user_email(self, obj):
        return obj.user.email if obj.user else None


admin.site.register(LoginRule, LoginRuleAdmin)
admin.site.register(UserLogin, UserLoginAdmin)
