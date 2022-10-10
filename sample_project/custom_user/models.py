from django.conf import settings
from django.core.mail import send_mail
from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.dispatch import receiver

from workos_login.signals import workos_send_magic_link


class OfficeLocation(models.Model):
    address = models.CharField(max_length=1024, blank=False, null=False, default=None)
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
