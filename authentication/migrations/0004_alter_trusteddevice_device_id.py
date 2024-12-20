# Generated by Django 4.2.17 on 2024-12-17 05:44

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0003_alter_trusteddevice_device_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='trusteddevice',
            name='device_id',
            field=models.UUIDField(default=uuid.UUID('43e5b9a0-98ea-4f09-8899-b5d175ae4948'), unique=True),
        ),
    ]
