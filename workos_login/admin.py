from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html
from workos import BadRequestError, TransportError, WorkOSError
from django.utils.translation import gettext_lazy as _
from workos_login.models import LoginRule, UserLogin, LoginMethods, LogoutMethods

from django.contrib import admin
from django import forms
from workos_login.conf import conf
from workos_login.connections import create_saml_connection, get_connection_status, get_portal_link
from workos_login.utils import has_sandbox_credentials


class LoginRuleAdminForm(forms.ModelForm):
    class Meta:
        model = LoginRule
        fields = '__all__'

    def clean(self):
        cleaned_data = super().clean()
        sso_logout_method = cleaned_data.get('sso_logout_method')
        custom_logout_url = cleaned_data.get('custom_logout_url')
        if sso_logout_method == LogoutMethods.CUSTOM_URL and not custom_logout_url:
            self.add_error('custom_logout_url', _("This field is required when SSO Logout Method is set to Custom URL."))
        return cleaned_data


class CreateSAMLConnectionForm(forms.Form):
    CONNECTION_TYPE_CHOICES = [
        ("GenericSAML", "Generic SAML"),
        ("OktaSAML", "Okta"),
        ("AzureSAML", "Azure AD (SAML)"),
        ("GoogleSAML", "Google Workspace"),
        ("OneLoginSAML", "OneLogin"),
        ("ADFSSAML", "Active Directory FS"),
        ("PingOneSAML", "PingOne"),
    ]

    name = forms.CharField(required=False, help_text=_("Optional label for this connection, e.g. the customer's IdP name."))
    connection_type = forms.ChoiceField(choices=CONNECTION_TYPE_CHOICES, initial="GenericSAML", required=False)

    idp_metadata_url = forms.URLField(required=False, label=_("IdP Metadata URL"),
                                      help_text=_("If your IdP provides a metadata URL, use this instead of the manual fields below."))

    idp_entity_id = forms.CharField(required=False, label=_("IdP Entity ID"))
    idp_sso_url = forms.URLField(required=False, label=_("IdP SSO URL"))
    idp_signing_cert = forms.CharField(required=False, widget=forms.Textarea, label=_("IdP Signing Certificate (PEM)"))

    def clean(self):
        cleaned_data = super().clean()
        metadata_url = cleaned_data.get("idp_metadata_url")
        manual_fields = [cleaned_data.get("idp_entity_id"), cleaned_data.get("idp_sso_url"), cleaned_data.get("idp_signing_cert")]

        if metadata_url and any(manual_fields):
            raise ValidationError(_("Provide either an IdP Metadata URL or the manual fields below, not both."))
        if not metadata_url and not all(manual_fields):
            raise ValidationError(_("Provide either an IdP Metadata URL, or all three of IdP Entity ID, IdP SSO URL, and IdP Signing Certificate."))
        return cleaned_data


class LoginRuleAdmin(admin.ModelAdmin):
    form = LoginRuleAdminForm
    create_connection_form_class = CreateSAMLConnectionForm
    list_display = ("name", "priority", "method")
    filter_horizontal = ("jit_groups",)
    readonly_fields = ('portal_link', 'connection_status', 'create_connection_link')

    def get_fieldsets(self, request, obj=None):
        general = ["name", "method", "priority"]
        # If there are no sandbox credentials - leave the default of production only
        if has_sandbox_credentials():
            general.append("environment")
        # Only show email validation option for username/password rules
        if obj and obj.method == LoginMethods.USERNAME:
            general.append("require_validated_email")

        sso = ["connection_id", "organization_id", "connection_status", "saved_attributes",
               "jit_creation_type", "jit_groups", "portal_link"]
        if conf.WORKOS_ENABLE_CREATE_CONNECTION:
            sso.append("create_connection_link")
        sso += ["auto_update", "sso_logout_method", "custom_logout_url"]

        return (
            (None, {"fields": general}),
            ("Users this rule applies to", {"fields": ("email_regex", "lookup_attributes")}),
            ("SSO Options", {"fields": sso}),
            ("MFA Options", {"fields": ("totp_organization_name",)}),
        )

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                '<path:object_id>/create-connection/',
                self.admin_site.admin_view(self.create_connection_view),
                name='workos_login_loginrule_create_connection',
            ),
        ]
        return custom_urls + urls

    def create_connection_view(self, request, object_id):
        if not conf.WORKOS_ENABLE_CREATE_CONNECTION:
            raise Http404
        rule = self.get_object(request, object_id)
        if rule is None:
            raise Http404
        if not self.has_change_permission(request, rule):
            raise PermissionDenied

        change_url = reverse('admin:workos_login_loginrule_change', args=[rule.pk])

        if not rule.organization_id:
            messages.error(request, _("Only available for SSO with organization ID set."))
            return redirect(change_url)

        try:
            existing_connection = get_connection_status(rule)
        except (WorkOSError, TransportError):
            messages.error(request, _("Unable to verify connection status from WorkOS. Please try again."))
            return redirect(change_url)

        if existing_connection is not None:
            messages.error(request, _("A connection already exists for this organization."))
            return redirect(change_url)

        if request.method == 'POST':
            form = self.create_connection_form_class(request.POST)
            if form.is_valid():
                try:
                    connection = create_saml_connection(
                        rule,
                        name=form.cleaned_data['name'],
                        connection_type=form.cleaned_data['connection_type'],
                        idp_metadata_url=form.cleaned_data['idp_metadata_url'],
                        idp_entity_id=form.cleaned_data['idp_entity_id'],
                        idp_sso_url=form.cleaned_data['idp_sso_url'],
                        idp_signing_cert=form.cleaned_data['idp_signing_cert'],
                    )
                except BadRequestError as e:
                    form.add_error(None, str(e))
                except (WorkOSError, TransportError):
                    messages.error(request, _("Unable to create connection - please try again."))
                    return redirect(change_url)
                else:
                    messages.success(request, _("Connection created (state: %(state)s).") % {"state": connection.state})
                    return redirect(change_url)
        else:
            form = self.create_connection_form_class()

        context = {
            **self.admin_site.each_context(request),
            'title': _("Create Connection"),
            'rule': rule,
            'form': form,
            'opts': self.model._meta,
            'change_url': change_url,
        }
        return TemplateResponse(request, 'admin/workos_login/loginrule/create_connection.html', context)

    @admin.display(
        description='Portal Link',
    )
    def portal_link(self, obj):
        if obj and obj.organization_id:
            try:
                link = get_portal_link(obj)
                return format_html("<a href='{}'>Link to WorkOS Portal</a>", link)
            except BadRequestError:
                return _("You cannot have a portal link unless you set an Admin Portal Redirect Link")
            except (WorkOSError, TransportError):
                return _("Unable to generate a portal link from WorkOS.")
        return _("Only available for SSO with organization ID set.")

    @admin.display(
        description='Connection Status',
    )
    def connection_status(self, obj):
        if not obj or not (obj.connection_id or obj.organization_id):
            return _("Only available for SSO with connection or organization ID set.")
        try:
            connection = get_connection_status(obj)
        except (WorkOSError, TransportError):
            return _("Unable to fetch connection status from WorkOS.")
        if not connection:
            return _("No connection configured yet.")
        return format_html(
            "State: {}<br>Type: {}<br>Name: {}",
            connection.state, connection.connection_type, connection.name,
        )

    @admin.display(
        description='Create Connection',
    )
    def create_connection_link(self, obj):
        if not obj or not obj.pk:
            return _("Save this rule first.")
        if not obj.organization_id:
            return _("Only available for SSO with organization ID set.")
        try:
            connection = get_connection_status(obj)
        except (WorkOSError, TransportError):
            return _("Unable to fetch connection status from WorkOS.")
        if connection is not None:
            return _("A connection already exists for this organization - see status above.")
        url = reverse('admin:workos_login_loginrule_create_connection', args=[obj.pk])
        return format_html("<a href='{}'>Create Connection via API</a>", url)


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
