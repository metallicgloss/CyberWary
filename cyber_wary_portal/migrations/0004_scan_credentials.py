# Generated by Django 4.0.2 on 2022-03-20 02:52

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('cyber_wary_portal', '0003_scan_system_info'),
    ]

    operations = [
        migrations.CreateModel(
            name='Browser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('browser_name', models.CharField(max_length=64, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.RemoveField(
            model_name='scan',
            name='progress',
        ),
        migrations.AddField(
            model_name='scanrecord',
            name='progress',
            field=models.IntegerField(choices=[(1, 'Pending'), (2, 'In Progress'), (3, 'Partially Completed'), (4, 'Completed'), (5, 'Nodata')], default=1, help_text='The current progress/status of a scan.', validators=[django.core.validators.MaxValueValidator(5), django.core.validators.MinValueValidator(1)]),
        ),
        migrations.CreateModel(
            name='CredentialScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('progress', models.IntegerField(choices=[(1, 'Pending'), (2, 'In Progress'), (3, 'Partially Completed'), (4, 'Completed')], default=1, help_text='The current progress/status of the check.', validators=[django.core.validators.MaxValueValidator(5), django.core.validators.MinValueValidator(1)])),
                ('scan_record', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.scanrecord')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='CredentialRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('url', models.CharField(max_length=128, null=True)),
                ('storage', models.DateTimeField(null=True)),
                ('username', models.CharField(max_length=64, null=True)),
                ('password_strength', models.IntegerField(choices=[(1, 'Very Weak'), (2, 'Weak'), (3, 'Ok'), (4, 'Strong'), (5, 'Very Strong')], default=3, validators=[django.core.validators.MaxValueValidator(5), django.core.validators.MinValueValidator(1)])),
                ('filename', models.CharField(max_length=128, null=True)),
                ('compromised', models.BooleanField(default=False)),
                ('occurrence', models.IntegerField(default=0)),
                ('browser', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.browser')),
                ('credential_scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.credentialscan')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
