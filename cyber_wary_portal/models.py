#
# GNU General Public License v3.0
# Cyber Wary - <https://github.com/metallicgloss/CyberWary>
# Copyright (C) 2021 - William P - <hello@metallicgloss.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from hashlib import md5

# --------------------------------------------------------------------------- #
#                        1.1 Default Fields Class                             #
# --------------------------------------------------------------------------- #


class DefaultFields(models.Model):
    # Default parameters to track creation date, last updated date and status.
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)

    # Define abstract class as true - all child classes to inherit fields.
    class Meta:
        abstract = True


# --------------------------------------------------------------------------- #
#                        1.2 System User Class                                #
# --------------------------------------------------------------------------- #

class SystemUser(AbstractUser):
    def get_gravatar_image(self):
        return 'http://www.gravatar.com/avatar/{}'.format(md5(self.email.encode()).hexdigest())


# --------------------------------------------------------------------------- #
#                        1.3 Scan Class                                       #
# --------------------------------------------------------------------------- #

class Scan(DefaultFields):
    class ScanTypes(models.TextChoices):
        BLUE = 'B'
        RED = 'R'

    class ScanStatus(models.IntegerChoices):
        PENDING = 1
        IN_PROGRESS = 2
        PARTIALLY_COMPLETED = 3
        COMPLETED = 4
        NODATA = 5

    # Foreign key to the user that owns the scan.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    type = models.CharField(
        max_length=1,
        choices=ScanTypes.choices,
        default=ScanTypes.BLUE,
        help_text="Type of scan being performed.",
        null=False
    )

    title = models.CharField(
        help_text="An identifier for a scan.",
        max_length=32,
        null=True
    )

    comment = models.TextField(
        help_text="Comments or details related to a scan.",
        max_length=2048,
        null=True
    )

    max_devices = models.IntegerField(
        default=1,
        help_text="The number of devices that can be attached to a single scan request.",
        validators=[
            MaxValueValidator(10),
            MinValueValidator(1)
        ],
        null=False
    )

    scan_key = models.CharField(
        help_text="A unique key associated with the scan.",
        max_length=32,
        null=False
    )

    completed = models.DateTimeField(
        help_text="The date/time that the scan completed.",
        null=True
    )

    expiry = models.DateTimeField(
        help_text="The expiry date/time that new data can be submitted for a scan.",
        null=True
    )

    progress = models.IntegerField(
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        help_text="The current progress/status of a scan.",
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ]
    )

    system_users = models.BooleanField(
        help_text="Flag for scan of system users.",
        default=False,
        null=True
    )

    network_adapters = models.BooleanField(
        help_text="Flag for scan of network adapters.",
        default=False,
        null=True
    )

    startup_applications = models.BooleanField(
        help_text="Flag for scan of startup applications.",
        default=False,
        null=True
    )

    installed_applications = models.BooleanField(
        help_text="Flag for scan of installed applications.",
        default=False,
        null=True
    )

    outdated_applications = models.BooleanField(
        help_text="Flag for scan of outdated applications.",
        default=False,
        null=True
    )

    firewall_rules = models.BooleanField(
        help_text="Flag for scan of firewall rules.",
        default=False,
        null=True
    )

    system_passwords = models.BooleanField(
        help_text="Flag for scan of system passwords.",
        default=False,
        null=True
    )

    browser_passwords = models.BooleanField(
        help_text="Flag for scan of browser passwords.",
        default=False,
        null=True
    )

    antivirus_product = models.BooleanField(
        help_text="Flag for scan of check of anti-virus product installation.",
        default=False,
        null=True
    )


class OperatingSystem(DefaultFields):
    name = models.CharField(
        help_text="The readable name of an operating system.",
        max_length=64,
        null=True
    )

    build_number = models.CharField(
        help_text="The build number of an operating system.",
        max_length=64,
        null=True
    )

    version = models.CharField(
        help_text="The version of an operating system.",
        max_length=32,
        null=True
    )

    architecture = models.CharField(
        help_text="The architecture type of the system.",
        max_length=8,
        null=True
    )


class ScanRecord(DefaultFields):
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE
    )

    name = models.CharField(
        help_text="Name of the device being scanned.",
        max_length=32,
        null=True
    )

    uuid = models.CharField(
        help_text="The unique system ID assigned to the system.",
        max_length=64,
        null=True
    )

    os = models.ForeignKey(
        OperatingSystem,
        on_delete=models.SET_NULL,
        null=True
    )

    os_install = models.DateField(
        help_text="The date that the version of the OS was installed.",
        null=True
    )

    boot_time = models.DateTimeField(
        help_text="The date/time that the system was booted.",
        null=True
    )

    boot_mode = models.CharField(
        help_text="The boot type of the device.",
        max_length=16,
        null=True
    )

    boot_portable = models.BooleanField(
        help_text="A flag if the OS is mounted in a portable mode.",
        default=False,
        null=True
    )

    public_ip = models.CharField(
        help_text="The public IP of the scanned device.",
        max_length=16,
        null=True
    )


class BiosDetails(DefaultFields):
    record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE
    )

    bios_manufacturer = models.CharField(
        help_text="The manufacturer of the BIOS.",
        max_length=64,
        null=True
    )

    bios_version = models.CharField(
        help_text="The version / revision of the BIOS installed on the device.",
        max_length=16,
        null=True
    )

    bios_date = models.DateField(
        help_text="The date of the BIOS installed on the device.",
        null=True
    )

    bios_serial = models.CharField(
        help_text="The serial number of the BIOS installed on the device.",
        max_length=64,
        null=True
    )


class SystemUsers(DefaultFields):
    class AccountType(models.TextChoices):
        MICROSOFT = 'M'
        LOCAL = 'L'

    record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE
    )

    name = models.CharField(
        help_text="The full name of the user.",
        max_length=64,
        null=True
    )

    sid = models.CharField(
        help_text="The SID of the user.",
        max_length=64,
        null=True
    )

    type = models.CharField(
        max_length=2,
        choices=AccountType.choices,
        default=AccountType.LOCAL,
        help_text="The type of account."
    )

    last_logon = models.DateTimeField(
        help_text="The date/time that the account was last logged in.",
        null=True
    )

    last_password_set = models.DateTimeField(
        help_text="The date/time that the password was last changed.",
        null=True
    )

    active = models.BooleanField(
        help_text="Flag for active user.",
        default=False,
        null=True
    )

    admin = models.BooleanField(
        help_text="Flag for administrative permissions.",
        default=False,
        null=True
    )

    enabled = models.BooleanField(
        help_text="Flag for account enabled.",
        default=True,
        null=True
    )


class NetworkAdapters(DefaultFields):
    record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE
    )

    name = models.CharField(
        help_text="The name of the network adapter.",
        max_length=128,
        null=True
    )

    description = models.CharField(
        help_text="The description of the network adapter.",
        max_length=128,
        null=True
    )

    status = models.CharField(
        help_text="The uplink status of the adapter.",
        max_length=16,
        null=True
    )

    mac_address = models.CharField(
        help_text="The physical / hardware address of the adapter.",
        max_length=17,
        null=True
    )

    dns_servers = models.CharField(
        help_text="The DNS servers configured on the adapter.",
        max_length=64,
        null=True
    )


class InternetProtocolAddress(DefaultFields):
    adapter = models.ForeignKey(
        NetworkAdapters,
        on_delete=models.CASCADE
    )

    ip = models.CharField(
        help_text="The allocated address.",
        max_length=45,
        null=True
    )

    gateway = models.CharField(
        help_text="The allocated gateway address.",
        max_length=45,
        null=True
    )

    subnet = models.CharField(
        help_text="The allocated subnet.",
        max_length=45,
        null=True
    )

    lease_obtained = models.DateTimeField(
        help_text="The DHCP lease obtained date/time.",
        null=True
    )

    lease_expires = models.DateTimeField(
        help_text="The DHCP lease expiry date/time.",
        null=True
    )

    
class ApiRequest(DefaultFields):
    class RequestMethod(models.IntegerChoices):
        GET = 1
        POST = 2
        PATCH = 3
        PUT = 4
        DELETE = 5

    # Foreign key to the user that owns the scan.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    type = models.CharField(
        help_text="The type of request made.",
        max_length=32,
        null=True
    )

    payload = models.TextField(
        help_text="The raw payload data.",
        null=True
    )

    method = models.IntegerField(
        choices=RequestMethod.choices,
        default=RequestMethod.GET,
        help_text="The type of request that was made.",
        null=False
    )

    response = models.CharField(
        help_text="The response code issued to the request.",
        max_length=8,
        null=True,
        default="200"
    )

    def get_payload_size(self):
        return len(self.payload)
