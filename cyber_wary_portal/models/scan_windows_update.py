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
#                            WINDOWS UPDATE MODELS                            #
#                                                                             #
#          Models associated the Windows Update component of a scan.          #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Windows Update                                    #
#                            1.1 Pending Updates                              #
#                            1.2 Installed Updates                            #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                              1. Windows Update                              #
# --------------------------------------------------------------------------- #
#                          1.1 Pending Updates Class                          #
# --------------------------------------------------------------------------- #

class UpdatePending(DefaultFields):
    # Model to store the currently pending updates queued by Windows Update.

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender detection is associated with."
    )

    title = models.CharField(
        max_length=256,
        null=True,
        help_text="The title of an update (Title)."
    )

    description = models.CharField(
        max_length=1024,
        null=True,
        help_text="The description that accompanies the update (Description)."
    )

    install_deadline = models.DateTimeField(
        null=True,
        help_text="The date/time that the install is required to be installed by (Deadline)."
    )

    eula_accepted = models.BooleanField(
        default=False,
        help_text="The flag to confirm that the EULA has been accepted by the user (EulaAccepted)."
    )

    beta = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is in BETA (IsBeta)."
    )

    downloaded = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update has been already downloaded (IsDownloaded)."
    )

    hidden = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is hidden from the end user (IsHidden)."
    )

    mandatory = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is mandatory to be installed (IsMandatory)."
    )

    uninstallable = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is able to be individually uninstalled (IsUninstallable)."
    )

    reboot_required = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update will require a restart to install (RebootRequired)."
    )

    date_check = models.DateTimeField(
        null=True,
        help_text="The date/time that the update was last checked (LastDeploymentChangeTime)."
    )

    download_size = models.BigIntegerField(
        default=0,
        null=True,
        help_text="The maximum download/install size for the update (MaxDownloadSize)."
    )

    security_rating = models.CharField(
        max_length=32,
        null=True,
        help_text="The security severity rating for the update (MsrcSeverity)."
    )

    cves = models.CharField(
        max_length=128,
        null=True,
        help_text="The list of CVEs associated with the update (CveIDs)."
    )

    driver_date = models.CharField(
        max_length=128,
        null=True,
        help_text="The date that the driver/update was released (DriverVerDate)."
    )

    driver_manufacturer = models.CharField(
        max_length=128,
        null=True,
        help_text="The software developer of the driver/update (DriverProvider)."
    )

    driver_model = models.CharField(
        max_length=128,
        null=True,
        help_text="The device that the update/firmware/driver is for (DriverModel)."
    )


# --------------------------------------------------------------------------- #
#                         1.1 Installed Updates Class                         #
# --------------------------------------------------------------------------- #

class UpdateInstalled(DefaultFields):
    # Model to store the recently installed updates by Windows Defender (~6 months)

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender detection is associated with."
    )

    date = models.DateTimeField(
        null=True,
        help_text="The date/time that the update was installed (Date)."
    )

    title = models.CharField(
        max_length=256,
        null=True,
        help_text="The title of an update (Title)."
    )

    description = models.CharField(
        max_length=1024,
        null=True,
        help_text="The description that accompanies the update (Description)."
    )

    kb = models.CharField(
        max_length=16,
        null=True,
        help_text="The microsoft KB identifier (KB)."
    )

    result = models.CharField(
        max_length=16,
        null=True,
        help_text="The status of the installation (Result)."
    )
