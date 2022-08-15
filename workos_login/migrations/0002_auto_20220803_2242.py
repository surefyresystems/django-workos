# Generated by Django 4.0.6 on 2022-08-03 22:42

from django.db import migrations

DEFAULT_NAME = "Username/password login"


def create_initial_rule(apps, schema_editor):
    LoginRule = apps.get_model('workos_login', 'LoginRule')
    LoginRule.objects.create(
        name=DEFAULT_NAME,
        method="username",
        priority=1000,  # Put as a rule that is later than the default priority
        email_regex=".*"  # Match all
    )



class Migration(migrations.Migration):

    dependencies = [
        ('workos_login', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_initial_rule),
    ]
