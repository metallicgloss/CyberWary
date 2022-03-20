# Generated by Django 4.0.2 on 2022-02-22 14:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('cyber_wary_portal', '0002_initial_data_structure'),
    ]

    operations = [
        migrations.CreateModel(
            name='Bios',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('name', models.CharField(help_text='The name of the BIOS.', max_length=32, null=True)),
                ('version', models.CharField(help_text='The version / revision of the BIOS', max_length=16, null=True)),
                ('manufacturer', models.CharField(help_text='The manufacturer of the BIOS.', max_length=32, null=True)),
                ('release_date', models.DateField(help_text='The date of the BIOS installed on the device was released.', null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='BiosInstall',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('install_date', models.DateField(help_text='The date of the BIOS installed on the device.', null=True)),
                ('status', models.CharField(help_text='The status of the BIOS.', max_length=16, null=True)),
                ('primary', models.BooleanField(default=True, help_text='The flag for the OS being the primary installed.')),
                ('bios', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.bios')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Language',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('string', models.CharField(help_text='Readable language name.', max_length=32, null=True)),
                ('locale', models.CharField(help_text='Language locale.', max_length=5, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OperatingSystem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('name', models.CharField(help_text='The readable name of an operating system.', max_length=32, null=True)),
                ('version', models.CharField(help_text='The version of an operating system.', max_length=32, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OperatingSystemInstall',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('serial', models.CharField(help_text='The serial number of the operating system.', max_length=64, null=True)),
                ('timezone', models.CharField(help_text='The timezone configured on the system.', max_length=48, null=True)),
                ('install_date', models.DateField(help_text='The date that the version of the OS was installed.', null=True)),
                ('owner', models.CharField(help_text='The username of the configured operating system owner.', max_length=32, null=True)),
                ('logon_server', models.CharField(help_text='The configured logon server.', max_length=32, null=True)),
                ('installed_memory', models.CharField(help_text='The configured/installed physical system memory.', max_length=32, null=True)),
                ('domain', models.BooleanField(default=False, help_text='The status for the device being connected to a domain.')),
                ('portable', models.BooleanField(default=False, help_text='The status for the OS being mounted in a portable mode.')),
                ('virtual_machine', models.BooleanField(default=False, help_text='The VM/Virtualised environment status.')),
                ('debug_mode', models.BooleanField(default=False, help_text='The status for the device being configured in debug mode.')),
                ('keyboard', models.ForeignKey(default='en-GB', on_delete=django.db.models.deletion.SET_DEFAULT, to='cyber_wary_portal.language')),
                ('operating_system', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.operatingsystem')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AlterField(
            model_name='scan',
            name='browser_passwords',
            field=models.BooleanField(default=False, help_text='Flag for scan of passwords stored on the system.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='installed_antivirus',
            field=models.BooleanField(default=False, help_text='Flag for scan of check of anti-virus product installation.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='installed_applications',
            field=models.BooleanField(default=False, help_text='Flag for scan of installed applications.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='installed_patches',
            field=models.BooleanField(default=False, help_text='Flag for scan of installed OS updates and patches.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='network_adapters',
            field=models.BooleanField(default=False, help_text='Flag for scan of network adapters.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='network_exposure',
            field=models.BooleanField(default=False, help_text='Flag for scan of network exposure.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='network_firewall_rules',
            field=models.BooleanField(default=False, help_text='Flag for scan of firewall rules.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='startup_applications',
            field=models.BooleanField(default=False, help_text='Flag for scan of startup applications.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='system_services',
            field=models.BooleanField(default=False, help_text='Flag for scan of system services.'),
        ),
        migrations.AlterField(
            model_name='scan',
            name='system_users',
            field=models.BooleanField(default=False, help_text='Flag for scan of system users.'),
        ),
        migrations.CreateModel(
            name='ScanRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('device_id', models.CharField(help_text='The unique system ID assigned to the system.', max_length=48, null=True)),
                ('name', models.CharField(help_text='The name of the device being scanned.', max_length=32, null=True)),
                ('boot_time', models.DateTimeField(help_text='The date/time that the system was last powered on.', null=True)),
                ('current_user', models.CharField(help_text='The name of the user performing the scan.', max_length=32, null=True)),
                ('public_ip', models.CharField(help_text='The public IP of the scanned device.', max_length=16, null=True)),
                ('city', models.CharField(help_text='The location of the scanned device.', max_length=16, null=True)),
                ('country', models.CharField(help_text='The country of the scanned device.', max_length=2, null=True)),
                ('bios_install', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.biosinstall')),
                ('os_install', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.operatingsysteminstall')),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.scan')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OperatingSystemInstalledLanguages',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('installed_language', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.language')),
                ('operating_system_installation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.operatingsysteminstall')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]