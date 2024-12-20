# Generated by Django 5.1.4 on 2024-12-20 17:11

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0014_alter_emailverification_token_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='token',
            field=models.UUIDField(default=uuid.UUID('93896e1c-08d9-4a44-9391-bacf1b69f340'), editable=False),
        ),
        migrations.AlterField(
            model_name='trusteddevice',
            name='device_id',
            field=models.UUIDField(default=uuid.UUID('8fe1992f-6594-45bb-bc50-71e682757308'), unique=True),
        ),
    ]