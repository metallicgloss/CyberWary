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
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.data_import import *
from django.http.response import HttpResponse
from rest_framework.decorators import api_view
import re
import threading


# --------------------------------------------------------------------------- #
#                                                                             #
#                              SOFTWARE API VIEWS                             #
#                                                                             #
#     Views associated with the installed and startup software API calls.     #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Software Actions                                  #
#                            1.1 Installed Applications                       #
#                            1.2 Startup Applications                         #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                             1. Software Actions                             #
# --------------------------------------------------------------------------- #
#                          1.1 Installed Applications                         #
# --------------------------------------------------------------------------- #


@api_view(['POST', ])  # API Call - Accept POST method only.
def applications_installed(request):
    # Store all of the installed applications included in the payload, and attempt to determine if they include vulnerabilities.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'applications/installed',
        'applications',
        True
    )

    if(check_existing(scan, scan_record, Software)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Define empty list for new objects to be appended to for passing to thread.
    software = []

    for application in data:
        # For each firewall rule defined.
        install_path = ""

        # Set install_path based on included key - varies per software and is not standardised.
        if("InstallLocation" in application):
            install_path = application['InstallLocation']
        elif("InstallSource" in application):
            install_path = application['InstallSource']

        if(application.get('DisplayName') is not None and application.get('DisplayVersion') is not None):
            # If software has a valid name and version (filters our base firmware).
            software.append(
                Software.objects.create(
                    scan_record=scan_record,
                    name=application.get(
                        'DisplayName'
                    ),
                    version=re.sub(
                        "[^\d\.]",
                        "",
                        application.get(
                            'DisplayVersion'
                        )
                    ),
                    version_major=application.get(
                        'VersionMajor'
                    ),
                    version_minor=application.get(
                        'VersionMinor'
                    ),
                    publisher=Publisher.objects.get_or_create(
                        name=application.get(
                            'Publisher'
                        )
                    )[0],
                    install_path=install_path,
                    install_date=convert_date(
                        application.get(
                            'InstallDate'
                        )
                    )
                )
            )

    # Execute in thread to detach from main import process.
    import_thread = threading.Thread(
        target=search_cpe,
        args=[software]
    )

    # Start the import
    import_thread.start()

    return HttpResponse('Success')
