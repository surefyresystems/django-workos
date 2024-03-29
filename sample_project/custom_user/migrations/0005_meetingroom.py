# Generated by Django 3.2.15 on 2023-06-05 22:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0004_auto_20230604_2126'),
    ]

    operations = [
        migrations.CreateModel(
            name='MeetingRoom',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('office_location', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='meeting_rooms', to='custom_user.officelocation')),
            ],
        ),
    ]
