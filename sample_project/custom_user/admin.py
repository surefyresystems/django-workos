from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Profile

class ProfileAdmin(admin.ModelAdmin):
    list_display = ["__str__", "organization_name"]
admin.site.register(User, UserAdmin)
admin.site.register(Profile, ProfileAdmin)

# Register your models here.
