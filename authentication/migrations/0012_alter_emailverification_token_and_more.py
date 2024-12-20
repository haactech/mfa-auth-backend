# Generated by Django 4.2.17 on 2024-12-20 01:36

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0011_alter_emailverification_token_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='token',
            field=models.UUIDField(default=uuid.UUID('65912b4c-9096-4b54-8e2c-f6c9263449e0'), editable=False),
        ),
        migrations.AlterField(
            model_name='trusteddevice',
            name='device_id',
            field=models.UUIDField(default=uuid.UUID('29046eaf-75d8-46ee-abf1-533ea4ea61ad'), unique=True),
        ),
    ]