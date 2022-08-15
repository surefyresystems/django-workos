from workos_login.models import LoginRule, UserLogin

from django.contrib import admin


class LoginRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "priority", "method")
    filter_horizontal = ("jit_groups",)
    fieldsets = (
        (None, {
            'fields': ('name', 'method', 'priority')
        }),
        ('Users this rule applies to', {
            'fields': ('email_regex', 'lookup_attributes',)
        }),
        ('SSO Options', {
            'fields': ('connection_id', 'organization_id', 'jit_creation', 'jit_groups', 'jit_attributes')
        }),
        ('MFA Options', {
            'fields': ('totp_organization_name',)
        }),
    )


admin.site.register(LoginRule, LoginRuleAdmin)
admin.site.register(UserLogin)
