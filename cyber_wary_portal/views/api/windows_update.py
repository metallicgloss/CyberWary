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

# Module/Library Import
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.data_import import *
from django.http.response import HttpResponse
from rest_framework.decorators import api_view


# --------------------------------------------------------------------------- #
#                                                                             #
#                           WINDOWS UPDATE API VIEWS                          #
#                                                                             #
#             Views associated with the Windows Update API calls.             #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Windows Update Actions                            #
#                            1.1 Pending Patches/Updates                      #
#                            1.2 Installed Patches/Updates                    #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                          1. Windows Update Actions                          #
# --------------------------------------------------------------------------- #
#                         1.1 Pending Patches/Updates                         #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def patches_pending(request):
    # Import and process pending patches currently queued by Windows Update.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'patches/installed',
        'patches',
        True
    )

    if(check_existing(scan, scan_record, UpdatePending)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Define empty list for new objects to be appended to for mass creation.
    pending_updates = []

    for patch in data:
        # For each pending update currently queued.
        try:
            # Create object and append to list for mass creation.
            pending_updates.pending(
                UpdatePending(
                    scan_record=scan_record,
                    title=patch['Title'],
                    description=patch['Description'],
                    install_deadline=patch['Deadline'],
                    eula_accepted=patch['EulaAccepted'],
                    beta=patch['IsBeta'],
                    downloaded=patch['IsDownloaded'],
                    hidden=patch['IsHidden'],
                    mandatory=patch['IsMandatory'],
                    uninstallable=patch['IsMandatory'],
                    reboot_required=patch['RebootRequired'],
                    date_check=convert_unix_to_dt(patch['LastDeploymentChangeTime']),
                    download_size=patch['MaxDownloadSize'],
                    security_rating=patch['MsrcSeverity'],
                    cves=patch['CveIDs'],
                    driver_date=convert_unix_to_dt(patch['DriverVerDate']),
                    driver_manufacturer=patch['DriverProvider'],
                    driver_model=patch['DriverModel']
                )
            )

        except KeyError:
            # Missing / Malformed data that differs to the default Windows output. Skip record.
            pass

    # Bulk create defined objects.
    UpdatePending.objects.bulk_create(pending_updates)

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                        1.2 Installed Patches/Updates                        #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def patches_installed(request):
    # Import and process patches recently installed (~6 months) by Windows Update.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'patches/installed',
        'patches'
    )

    if(check_existing(scan, scan_record, UpdateInstalled)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Define empty list for new objects to be appended to for mass creation.
    installed_updates = []

    for patch in data:
        # For each update/patch that has been installed.
        try:
            # Create object and append to list for mass creation.
            installed_updates.append(
                UpdateInstalled(
                    scan_record=scan_record,
                    date=convert_unix_to_dt(patch['Date']),
                    title=patch['Title'],
                    description=patch['Description'],
                    kb=patch['KB'],
                    result=patch['Result'],
                )
            )

        except KeyError:
            # Missing / Malformed data that differs to the default Windows output. Skip record.
            pass

    # Bulk create defined objects.
    UpdateInstalled.objects.bulk_create(installed_updates)

    return HttpResponse('Success')
