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

    system_services = models.BooleanField(
        help_text="Flag for scan of system services.",
        default=False,
        null=True
    )

    browser_passwords = models.BooleanField(
        help_text="Flag for scan of passwords stored on the system.",
        default=False,
        null=True
    )

    network_adapters = models.BooleanField(
        help_text="Flag for scan of network adapters.",
        default=False,
        null=True
    )

    network_exposure = models.BooleanField(
        help_text="Flag for scan of network exposure.",
        default=False,
        null=True
    )

    network_firewall_rules = models.BooleanField(
        help_text="Flag for scan of firewall rules.",
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

    installed_patches = models.BooleanField(
        help_text="Flag for scan of installed OS updates and patches.",
        default=False,
        null=True
    )

    installed_antivirus = models.BooleanField(
        help_text="Flag for scan of check of anti-virus product installation.",
        default=False,
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


class Language(DefaultFields):
    string = models.CharField(
        help_text="Readable language name.",
        max_length=32,
        null=True
    )

    locale = models.CharField(
        help_text="Language locale.",
        max_length=5,
        null=True
    )


class ScanRecord(DefaultFields):
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE
    )

    device_id = models.CharField(
        help_text="The unique system ID assigned to the system.",
        max_length=48,
        null=True
    )

    name = models.CharField(
        help_text="The name of the device being scanned.",
        max_length=32,
        null=True
    )

    boot_time = models.DateTimeField(
        help_text="The date/time that the system was last powered on.",
        null=True
    )
    
    current_user = models.CharField(
        help_text="The name of the user performing the scan.",
        max_length=32,
        null=True
    )

    public_ip = models.CharField(
        help_text="The public IP of the scanned device.",
        max_length=16,
        null=True
    )


class OperatingSystem(DefaultFields):
    name = models.CharField(
        help_text="The readable name of an operating system.",
        max_length=32,
        null=True
    )

    version = models.CharField(
        help_text="The version of an operating system.",
        max_length=32,
        null=True
    )


class OperatingSystemInstall(DefaultFields):
    record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE
    )

    operating_system = models.ForeignKey(
        OperatingSystem,
        on_delete=models.CASCADE
    )

    serial = models.CharField(
        help_text="The serial number of the operating system.",
        max_length=64,
        null=True
    )

    timezone = models.CharField(
        help_text="The timezone configured on the system.",
        max_length=48,
        null=True
    )

    install_date = models.DateField(
        help_text="The date that the version of the OS was installed.",
        null=True
    )
    
    keyboard = models.ForeignKey(
        Language,
        on_delete=models.SET_DEFAULT,
        default="en-GB"
    )

    owner = models.CharField(
        help_text="The username of the configured operating system owner.",
        max_length=32,
        null=True
    )

    logon_server = models.CharField(
        help_text="The configured logon server.",
        max_length=32,
        null=True
    )

    installed_memory = models.CharField(
        help_text="The configured/installed physical system memory.",
        max_length=32,
        null=True
    )

    domain = models.BooleanField(
        help_text="The status for the device being connected to a domain.",
        default=False,
        null=True
    )

    portable = models.BooleanField(
        help_text="The status for the OS being mounted in a portable mode.",
        default=False,
        null=True
    )

    virtual_machine = models.BooleanField(
        help_text="The VM/Virtualised environment status.",
        default=False,
        null=True
    )

    debug_mode = models.BooleanField(
        help_text="The status for the device being configured in debug mode.",
        default=False,
        null=True
    )

    
class OperatingSystemInstalledLanguages(DefaultFields):
    operating_system_installation = models.ForeignKey(
        OperatingSystemInstall,
        on_delete=models.CASCADE
    )

    installed_language = models.ForeignKey(
        Language,
        on_delete=models.CASCADE
    )


class Bios(DefaultFields):
    name = models.CharField(
        help_text="The name of the BIOS.",
        max_length=32,
        null=True
    )

    version = models.CharField( 
        help_text="The version / revision of the BIOS",
        max_length=16,
        null=True
    )

    manufacturer = models.CharField(
        help_text="The manufacturer of the BIOS.",
        max_length=32,
        null=True
    )

    release_date = models.DateField(
        help_text="The date of the BIOS installed on the device was released.",
        null=True
    )


class BiosInstall(DefaultFields):
    record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE
    )

    bios = models.ForeignKey(
        Bios,
        on_delete=models.CASCADE
    )

    install_date = models.DateField(
        help_text="The date of the BIOS installed on the device.",
        null=True
    )

    status = models.CharField(
        help_text="The status of the BIOS.",
        max_length=16,
        null=True
    )

    primary = models.BooleanField(
        help_text="The flag for the OS being the primary installed.",
        max_length=16,
        null=True
    )