from django.utils.html import format_html
from workos.exceptions import BadRequestException
from django.utils.translation import gettext_lazy as _

from workos_login.models import LoginRule, UserLogin

from django.contrib import admin
from workos import client as workos_client


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
            'fields': ('connection_id', 'organization_id', 'saved_attributes', 'jit_creation_type', 'jit_groups', 'portal_link')
        }),
        ('MFA Options', {
            'fields': ('totp_organization_name',)
        }),
    )

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
    readonly_fields = fields = ("mfa_factor", "mfa_type", "sso_id", "idp_id", "user", "rule", "created_at", "last_modified")


admin.site.register(LoginRule, LoginRuleAdmin)
admin.site.register(UserLogin, UserLoginAdmin)
