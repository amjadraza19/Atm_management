# Generated by Django 5.0.7 on 2024-07-25 12:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_customuser_amount'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='amount',
        ),
    ]
