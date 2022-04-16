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
from cyber_wary_portal.models.core import *
from django.db import models


# --------------------------------------------------------------------------- #
#                                                                             #
#                              WINDOWS USER MODEL                             #
#                                                                             #
#         Model associated the Windows User Check component of a scan.        #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                               1. Windows User                               #
# --------------------------------------------------------------------------- #
#                                   1.1 User                                  #
# --------------------------------------------------------------------------- #

class WindowsUser(DefaultFields):
    # Model to store an individual account associated with a scanned device.

    # The type of account that can be installed.
    class AccountType(models.IntegerChoices):
        LOCAL = 1
        MICROSOFT = 2

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the user is associated with."
    )

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The username of the user account (Name)."
    )

    full_name = models.CharField(
        max_length=32,
        null=True,
        help_text="The full readable name of the user account (FullName)."
    )

    description = models.CharField(
        max_length=128,
        null=True,
        help_text="The description of the user account (Description)."
    )

    sid = models.CharField(
        max_length=48,
        null=True,
        help_text="The security identifier of the user account (SID/AccountDomainSid)."
    )

    source = models.IntegerField(
        choices=AccountType.choices,
        default=AccountType.LOCAL,
        validators=[
            MaxValueValidator(2),
            MinValueValidator(1)
        ],
        help_text="The type of user account (Microsoft or Local) (PrincipalSource)."
    )

    enabled = models.BooleanField(
        default=False,
        help_text="The status of the user account within the system (Enabled)."
    )

    last_logon = models.DateTimeField(
        null=True,
        help_text="The last logon date for the user account (LastLogon)."
    )

    password_changeable = models.DateTimeField(
        null=True,
        help_text="The date/time that the password is required to be changed by (PasswordChangeableDate)."
    )

    password_expiry = models.DateTimeField(
        null=True,
        help_text="The date/time that the current password defined on the user account will expire (PasswordExpires)."
    )

    password_permission = models.BooleanField(
        default=False,
        help_text="The flag to identify if the account is able to change its password (UserMayChangePassword)."
    )

    password_required = models.BooleanField(
        default=False,
        help_text="The flag to identify if a password reset is required on the account (PasswordRequired)."
    )

    password_last_set = models.DateTimeField(
        null=True,
        help_text="The date/time of the last time the password for the account was updated or changed (PasswordLastSet)."
    )
