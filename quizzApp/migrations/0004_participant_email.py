# Generated by Django 5.1.3 on 2025-01-07 18:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quizzApp', '0003_participant_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='participant',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
    ]
