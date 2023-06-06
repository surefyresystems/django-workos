from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.mail import send_mail
from django.core.validators import RegexValidator
from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.dispatch import receiver

from workos_login.signals import workos_send_magic_link


class Address(models.Model):
    class Meta:
        ordering = ['id']
        index_together = (
            ("content_type", "object_id")
        )

    content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, blank=True, null=True)
    object_id = models.PositiveIntegerField(blank=True, null=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    # Maximum lengths come from USPS API requirements
    company_name = models.CharField(max_length=38, blank=True, verbose_name="Company Name")
    address1 = models.CharField(max_length=38, blank=True, verbose_name="Address line 1")
    address2 = models.CharField(max_length=38, blank=True, verbose_name="Address line 2")
    city = models.CharField(max_length=38, blank=True, verbose_name="City")
    state = models.CharField(
        max_length=2,
        blank=True,
        verbose_name="State Code",
        validators=[
            RegexValidator(
                regex="^[A-Z]{2}$",
                message="State code most consist of exactly 2 upper case characters",
                code="invalid_state_code"
            )
        ]
    )
    zip = models.CharField(max_length=5, blank=True, verbose_name="5 Digit Zip")

    primary = models.BooleanField(default=True, help_text="Is this the primary address for this account?")
    last_modified = models.DateTimeField(auto_now=True)

class MeetingRoom(models.Model):
    office_location = models.ForeignKey("OfficeLocation", on_delete=models.CASCADE, related_name="meeting_rooms")
    name = models.CharField(max_length=100)

class OfficeLocation(models.Model):
    addresses = GenericRelation(Address)
    location_id = models.CharField(max_length=50, unique=True, blank=False, null=False, default=None)

class User(AbstractUser):
    is_external = models.BooleanField(default=False)
    user_location = models.ForeignKey(OfficeLocation, blank=True, null=True, on_delete=models.CASCADE)



class Profile(models.Model):
    organization_name = models.CharField(blank=True, max_length=255)
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.user)


@receiver(workos_send_magic_link)
def my_handler(sender, **kwargs):
    """
    Handle a magic email custom send
    """
    email = kwargs["user"].email
    body = "Your magic link: {}".format(kwargs["link"])
    send_mail("New login link", body, settings.DEFAULT_FROM_EMAIL, [email])
