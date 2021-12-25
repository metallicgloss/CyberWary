# Generated by Django 3.2.9 on 2021-12-25 02:32

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('cyber_wary_portal', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='OperatingSystem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('name', models.CharField(help_text='The readable name of an operating system.', max_length=64, null=True)),
                ('build_number', models.CharField(help_text='The build number of an operating system.', max_length=64, null=True)),
                ('version', models.CharField(help_text='The version of an operating system.', max_length=32, null=True)),
                ('architecture', models.CharField(help_text='The architecture type of the system.', max_length=8, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('type', models.IntegerField(choices=[(1, 'Blue'), (2, 'Red')], default=1, help_text='Type of scan being performed.', validators=[django.core.validators.MaxValueValidator(2), django.core.validators.MinValueValidator(1)])),
                ('title', models.CharField(default='Untitled Scan', help_text='An identifier for a scan.', max_length=64, null=True)),
                ('comment', models.TextField(help_text='Comments or details related to a scan.', max_length=2048, null=True)),
                ('max_devices', models.IntegerField(default=1, help_text='The number of devices that can be attached to a single scan request.', validators=[django.core.validators.MaxValueValidator(10), django.core.validators.MinValueValidator(1)])),
                ('scan_key', models.CharField(help_text='A unique key associated with the scan.', max_length=64)),
                ('completed', models.DateTimeField(help_text='The date/time that the scan completed.', null=True)),
                ('expiry', models.DateTimeField(help_text='The expiry date/time that new data can be submitted for a scan.', null=True)),
                ('progress', models.IntegerField(choices=[('1', 'Pending'), ('2', 'In Progress'), ('3', 'Partially Completed'), ('4', 'Completed'), ('5', 'Nodata')], default='1', help_text='The current progress/status of a scan.', validators=[django.core.validators.MaxValueValidator(5), django.core.validators.MinValueValidator(1)])),
                ('system_users', models.BooleanField(default=False, help_text='Flag for scan of system users.', null=True)),
                ('network_adapters', models.BooleanField(default=False, help_text='Flag for scan of network adapters.', null=True)),
                ('startup_applications', models.BooleanField(default=False, help_text='Flag for scan of startup applications.', null=True)),
                ('installed_applications', models.BooleanField(default=False, help_text='Flag for scan of installed applications.', null=True)),
                ('outdated_applications', models.BooleanField(default=False, help_text='Flag for scan of outdated applications.', null=True)),
                ('firewall_rules', models.BooleanField(default=False, help_text='Flag for scan of firewall rules.', null=True)),
                ('system_password', models.BooleanField(default=False, help_text='Flag for scan of system passwords.', null=True)),
                ('browser_passwords', models.BooleanField(default=False, help_text='Flag for scan of browser passwords.', null=True)),
                ('antivirus_product', models.BooleanField(default=False, help_text='Flag for scan of check of anti-virus product installation.', null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ScanRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('name', models.CharField(help_text='Name of the device being scanned.', max_length=32, null=True)),
                ('uuid', models.CharField(help_text='The unique system ID assigned to the system.', max_length=64, null=True)),
                ('os_install', models.DateField(help_text='The date that the version of the OS was installed.', null=True)),
                ('boot_time', models.DateTimeField(help_text='The date/time that the system was booted.', null=True)),
                ('boot_mode', models.CharField(help_text='The boot type of the device.', max_length=16, null=True)),
                ('boot_portable', models.BooleanField(default=False, help_text='A flag if the OS is mounted in a portable mode.', null=True)),
                ('public_ip', models.CharField(help_text='The public IP of the scanned device.', max_length=16, null=True)),
                ('os', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='cyber_wary_portal.operatingsystem')),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.scan')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SystemUsers',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('name', models.CharField(help_text='The full name of the user.', max_length=64, null=True)),
                ('sid', models.CharField(help_text='The SID of the user.', max_length=64, null=True)),
                ('type', models.IntegerField(choices=[(1, 'Microsoft'), (2, 'Local')], default=2, help_text='The type of account.', validators=[django.core.validators.MaxValueValidator(2), django.core.validators.MinValueValidator(1)])),
                ('last_logon', models.DateTimeField(help_text='The date/time that the account was last logged in.', null=True)),
                ('last_password_set', models.DateTimeField(help_text='The date/time that the password was last changed.', null=True)),
                ('active', models.BooleanField(default=False, help_text='Flag for active user.', null=True)),
                ('admin', models.BooleanField(default=False, help_text='Flag for administrative permissions.', null=True)),
                ('enabled', models.BooleanField(default=True, help_text='Flag for account enabled.', null=True)),
                ('record', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.scanrecord')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='NetworkAdapters',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(help_text='The name of the network adapter.', max_length=128, null=True)),
                ('description', models.CharField(help_text='The description of the network adapter.', max_length=128, null=True)),
                ('status', models.CharField(help_text='The uplink status of the adapter.', max_length=16, null=True)),
                ('mac_address', models.CharField(help_text='The physical / hardware address of the adapter.', max_length=17, null=True)),
                ('dns_servers', models.CharField(help_text='The DNS servers configured on the adapter.', max_length=64, null=True)),
                ('record', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.scanrecord')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='InternetProtocolAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('ip', models.CharField(help_text='The allocated address.', max_length=45, null=True)),
                ('gateway', models.CharField(help_text='The allocated gateway address.', max_length=45, null=True)),
                ('subnet', models.CharField(help_text='The allocated subnet.', max_length=45, null=True)),
                ('lease_obtained', models.DateTimeField(help_text='The DHCP lease obtained date/time.', null=True)),
                ('lease_expires', models.DateTimeField(help_text='The DHCP lease expiry date/time.', null=True)),
                ('adapter', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.networkadapters')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='BiosDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('status', models.BooleanField(default=True)),
                ('bios_manufacturer', models.CharField(help_text='The manufacturer of the BIOS.', max_length=64, null=True)),
                ('bios_version', models.CharField(help_text='The version / revision of the BIOS installed on the device.', max_length=16, null=True)),
                ('bios_date', models.DateField(help_text='The date of the BIOS installed on the device.', null=True)),
                ('bios_serial', models.CharField(help_text='The serial number of the BIOS installed on the device.', max_length=64, null=True)),
                ('record', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cyber_wary_portal.scanrecord')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
