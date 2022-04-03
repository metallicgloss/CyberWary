#
# GNU General Public License v3.0
# Cyber Wary - <https://github.com/metallicgloss/CyberWary>
# Copyright (C) 2022 - William P - <hello@metallicgloss.com>
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

# Module/Library Import
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from hashlib import md5


# --------------------------------------------------------------------------- #
#                                                                             #
#                                 CORE MODELS                                 #
#                                                                             #
#      Classes associated with the core functionality of the application.     #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. System Models                                     #
#                            1.1 Default Fields                               #
#                            1.2 System User                                  #
#                            1.3 API Request                                  #
#                            1.4 Language                                     #
#                        2. Operating System                                  #
#                            2.1 OS Version                                   #
#                            2.2 OS Install                                   #
#                            2.3 OS Installed Languages                       #
#                        3. BIOS                                              #
#                            3.1 BIOS Version                                 #
#                            3.2 BIOS Installation                            #
#                        4. Scan                                              #
#                            4.1 Scan Group                                   #
#                            4.2 Scan Record                                  #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                              1. System Models                               #
# --------------------------------------------------------------------------- #
#                           1.1 Default Fields Class                          #
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
#                            1.2 System User Class                            #
# --------------------------------------------------------------------------- #

class SystemUser(AbstractUser):
    # Define the name for the custom Django user.

    # Return gravatar image URL based on the email address of the user.
    def get_gravatar_image(self):
        return 'http://www.gravatar.com/avatar/{}'.format(md5(self.email.encode()).hexdigest())


# --------------------------------------------------------------------------- #
#                            1.3 API Request Class                            #
# --------------------------------------------------------------------------- #

class ApiRequest(DefaultFields):
    # Model to store each API requested made to the application by a user.

    # Types of API request supported by the platform.
    class RequestMethod(models.IntegerChoices):
        GET = 1
        POST = 2
        PATCH = 3
        PUT = 4
        DELETE = 5

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        help_text="The system user that is associated with the api request call.",
    )

    type = models.CharField(
        max_length=32,
        null=True,
        help_text="The name/type of the request made."
    )

    payload = models.TextField(
        null=True,
        help_text="The raw request payload data."
    )

    method = models.IntegerField(
        choices=RequestMethod.choices,
        default=RequestMethod.GET,
        null=False,
        help_text="The method of the request that was used."
    )

    response = models.CharField(
        default="200",
        max_length=8,
        null=True,
        help_text="The response code issued to the request."
    )

    # Return the size of the raw payload submitted in the request.
    def get_payload_size(self):
        return len(self.payload)


# --------------------------------------------------------------------------- #
#                                1.4 Language                                 #
# --------------------------------------------------------------------------- #

class Language(DefaultFields):
    # Model to store languages installed throughout a computer system.

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The readable name of the language"
    )

    locale = models.CharField(
        max_length=5,
        null=True,
        help_text="The locale identifier of the language."
    )


# --------------------------------------------------------------------------- #
#                             2. Operating System                             #
# --------------------------------------------------------------------------- #
#                            2.1 OS Version Class                             #
# --------------------------------------------------------------------------- #

class OperatingSystem(DefaultFields):
    # Model to store the version of an operating system.

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The readable name of the operating system."
    )

    version = models.CharField(
        max_length=32,
        null=True,
        help_text="The version of the operating system."
    )


# --------------------------------------------------------------------------- #
#                            2.2 OS Install Class                             #
# --------------------------------------------------------------------------- #

class OperatingSystemInstall(DefaultFields):
    # Model to store the individual installation of an OS on a system.

    os = models.ForeignKey(
        OperatingSystem,
        on_delete=models.CASCADE,
        help_text="The operating system version that the installation is associated with."
    )

    serial = models.CharField(
        max_length=64,
        null=True,
        help_text="The serial number issued to the operating system installation."
    )

    timezone = models.CharField(
        max_length=48,
        null=True,
        help_text="The timezone configured on the system."
    )

    install_date = models.DateField(
        null=True,
        help_text="The date that the version of the OS was installed."
    )

    keyboard = models.ForeignKey(
        Language,
        on_delete=models.SET_DEFAULT,
        default="en-GB",
        help_text="Foreign key to map the keyboard language to an installed language."
    )

    owner = models.CharField(
        max_length=32,
        null=True,
        help_text="The username of the configured operating system owner."
    )

    logon_server = models.CharField(
        max_length=32,
        null=True,
        help_text="The configured logon server."
    )

    installed_memory = models.CharField(
        max_length=32,
        null=True,
        help_text="The configured/installed physical system memory."
    )

    domain = models.BooleanField(
        default=False,
        help_text="The status for the device being connected to a domain."
    )

    portable = models.BooleanField(
        default=False,
        help_text="The status for the OS being mounted in a portable mode."
    )

    virtual_machine = models.BooleanField(
        default=False,
        help_text="The VM/Virtualised environment status."
    )

    debug_mode = models.BooleanField(
        default=False,
        help_text="The status for the device being configured in debug mode."
    )


# --------------------------------------------------------------------------- #
#                       2.3 OS Installed Language Class                       #
# --------------------------------------------------------------------------- #

class OperatingSystemInstalledLanguages(DefaultFields):
    # Model to store the individual languages installed in a computer system.

    os_install = models.ForeignKey(
        OperatingSystemInstall,
        on_delete=models.CASCADE,
        help_text="The operating system install that the installed language is associated with."
    )

    language = models.ForeignKey(
        Language,
        on_delete=models.CASCADE,
        help_text="The language that is installed."
    )


# --------------------------------------------------------------------------- #
#                                   3. BIOS                                   #
# --------------------------------------------------------------------------- #
#                            3.1 BIOS Version Class                           #
# --------------------------------------------------------------------------- #

class Bios(DefaultFields):
    # Model to store versions of BIOS software uploaded to the platform.

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The name of the BIOS."
    )

    version = models.CharField(
        max_length=16,
        null=True,
        help_text="The version / revision of the BIOS"
    )

    manufacturer = models.CharField(
        max_length=32,
        null=True,
        help_text="The manufacturer of the BIOS."
    )

    release_date = models.DateField(
        null=True,
        help_text="The date of the BIOS installed on the device was released."
    )


# --------------------------------------------------------------------------- #
#                         3.2 BIOS Installation Class                         #
# --------------------------------------------------------------------------- #

class BiosInstall(DefaultFields):
    # Model to store the individual installation of BIOS firmware on a computer system.

    bios = models.ForeignKey(
        Bios,
        on_delete=models.CASCADE,
        help_text="The version of the BIOS that the install is associated with."
    )

    install_date = models.DateField(
        null=True,
        help_text="The date of the BIOS installed on the device."
    )

    install_status = models.CharField(
        max_length=16,
        null=True,
        help_text="The status of the BIOS."
    )

    primary = models.CharField(
        max_length=16,
        null=True,
        help_text="The status for the OS being the primary installed."
    )


# --------------------------------------------------------------------------- #
#                                   4. Scan                                   #
# --------------------------------------------------------------------------- #
#                             4.1 Scan Group Class                            #
# --------------------------------------------------------------------------- #

class Scan(DefaultFields):
    # Model to store the scan group/template defined by the user to be used when performing scans on devices.

    # Types of scan that can be performed by the platform.
    class ScanTypes(models.TextChoices):
        BLUE = 'B'  # Defensive Scan
        RED = 'R'  # Offensive Scan

    # Foreign key to the user that owns the scan.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )

    type = models.CharField(
        max_length=1,
        choices=ScanTypes.choices,
        default=ScanTypes.BLUE,
        blank=False,
        help_text="Type of scan being performed (red - offensive / blue - defensive)."
    )

    title = models.CharField(
        max_length=32,
        null=True,
        help_text="A user-defined identifier for a scan."
    )

    comment = models.TextField(
        max_length=2048,
        null=True,
        help_text="Comments or additional details related to a scan."
    )

    max_devices = models.IntegerField(
        default=1,
        validators=[
            MaxValueValidator(10),
            MinValueValidator(1)
        ],
        null=False,
        help_text="The number of devices that can be attached to a single scan request."
    )

    scan_key = models.CharField(
        max_length=32,
        blank=False,
        help_text="A unique key associated with the scan."
    )

    completed = models.DateTimeField(
        null=True,
        help_text="The date/time that the scan completed."
    )

    expiry = models.DateTimeField(
        null=True,
        help_text="The expiry date/time that new data can be submitted for a scan."
    )

    system_users = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include system users."
    )

    browser_passwords = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include browser passwords stored on the system."
    )

    network_firewall_rules = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include firewall rules."
    )

    installed_applications = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include installed applications."
    )

    installed_patches = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include installed OS updates and patches."
    )

    installed_antivirus = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include check of anti-virus product installation."
    )


# --------------------------------------------------------------------------- #
#                            4.2 Scan Record Class                            #
# --------------------------------------------------------------------------- #

class ScanRecord(DefaultFields):
    # Model to store the records of an individual scan of a device.

    # Status of an active scan.
    class ScanStatus(models.IntegerChoices):
        PENDING = 1
        IN_PROGRESS = 2
        PARTIALLY_COMPLETED = 3
        COMPLETED = 4
        NODATA = 5

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        help_text="The scan that the record is associated with."
    )

    device_id = models.CharField(
        max_length=48,
        null=True,
        help_text="The unique system ID assigned to the system."
    )

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The name of the device being scanned."
    )

    os_install = models.ForeignKey(
        OperatingSystemInstall,
        on_delete=models.CASCADE,
        help_text="The Operating System install that the record is associated with."
    )

    bios_install = models.ForeignKey(
        BiosInstall,
        on_delete=models.CASCADE,
        help_text="The BIOS install that the record is associated with."
    )

    boot_time = models.DateTimeField(
        null=True,
        help_text="The date/time that the system was last powered on."
    )

    current_user = models.CharField(
        max_length=48,
        null=True,
        help_text="The name of the user performing the scan."
    )

    public_ip = models.CharField(
        max_length=16,
        null=True,
        help_text="The public IP of the scanned device."
    )

    city = models.CharField(
        max_length=16,
        null=True,
        help_text="The location of the scanned device."
    )

    country = models.CharField(
        max_length=2,
        null=True,
        help_text="The country of the scanned device."
    )

    progress = models.IntegerField(
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ],
        help_text="The current progress/status of a scan."
    )
