#
# GNU General Public License v3.0
# CyberWary - <https://github.com/metallicgloss/CyberWary>
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
from cyber_wary_portal.models.core import *
from django.db import models


# --------------------------------------------------------------------------- #
#                                                                             #
#                              CREDENTIAL MODELS                              #
#                                                                             #
#     Models associated with credential scan component of a system scan.      #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Credential Models                                 #
#                            1.1 Browser                                      #
#                            1.2 Credential Scan                              #
#                            1.3 Credential Record                            #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                            1. Credential Models                             #
# --------------------------------------------------------------------------- #
#                              1.1 Browser Class                              #
# --------------------------------------------------------------------------- #

class Browser(DefaultFields):
    # Model to store the name of the individual browser a credential is associated with.
    name = models.CharField(
        max_length=64,
        null=True,
        help_text="The name of the browser"
    )


# --------------------------------------------------------------------------- #
#                          1.2 Credential Scan Class                          #
# --------------------------------------------------------------------------- #

class CredentialScan(DefaultFields):
    # Model to store the store the status of credential import as part of a scan.

    # Available status settings for a credential import.
    class ScanStatus(models.IntegerChoices):
        PENDING = 1
        IN_PROGRESS = 2
        PARTIALLY_COMPLETED = 3
        COMPLETED = 4

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the credential scan group is associated with."
    )

    progress = models.IntegerField(
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ],
        help_text="The current progress/status of the credential processing."
    )


# --------------------------------------------------------------------------- #
#                         1.3 Credential Record Class                         #
# --------------------------------------------------------------------------- #

class Credential(DefaultFields):
    # Model to store an individual credential captured from a scanned device.

    # Available rating for password security.
    class SecurityRating(models.IntegerChoices):
        VERY_WEAK = 1
        WEAK = 2
        MEDIUM = 3
        STRONG = 4
        VERY_STRONG = 5

    credential_scan = models.ForeignKey(
        CredentialScan,
        on_delete=models.CASCADE,
        help_text="The credential scan group that the credential is associated with."
    )

    url = models.CharField(
        max_length=128,
        null=True,
        help_text="The URL that the credential is associated with."
    )

    browser = models.ForeignKey(
        Browser,
        on_delete=models.CASCADE,
        help_text="The browser that the credential has been captured from."
    )

    storage = models.DateTimeField(
        null=True,
        help_text="The date/time that the credential was created/stored."
    )

    username = models.CharField(
        max_length=64,
        null=True,
        help_text="The username/email address associated with the credential."
    )

    password_strength = models.IntegerField(
        choices=SecurityRating.choices,
        default=SecurityRating.MEDIUM,
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ],
        help_text="The strength of the password associated with the credential."
    )

    filename = models.CharField(
        max_length=128,
        null=True,
        help_text="The filename on the system that the credential was captured from."
    )

    compromised = models.BooleanField(
        default=False,
        help_text="The flag to identify if the password has appeared in a data breach."
    )

    occurrence = models.IntegerField(
        default=0,
        help_text="The number of times that the password has been seen in a data breach."
    )
