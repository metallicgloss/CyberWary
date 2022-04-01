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
from cyber_wary_portal.models import CredentialScan, Credential, Browser
from cyber_wary_portal.utils.data_import import *
from django.http.response import HttpResponse
from rest_framework.decorators import api_view
import json


# --------------------------------------------------------------------------- #
#                                                                             #
#                             CREDENTIAL API VIEW                             #
#                                                                             #
#        View associated with the browser password import API request.        #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                         1. Browser Passwords Action                         #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def browser_passwords(request):
    # Import and process browser passwords captured during the credential scan component.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'browser_passwords',
        'credentials'
    )

    # Remove raw payload associated with the API request.
    api_request.payload = "Pending Processing"
    api_request.save()

    if(check_existing(scan, scan_record, CredentialScan)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Create credential scan group.
    credential_scan = CredentialScan.objects.create(
        scan_record=scan_record,
        progress=CredentialScan.ScanStatus.IN_PROGRESS
    )

    # Define empty list for new objects to be appended to for mass creation.
    credential_list = []

    for id, credential in enumerate(data):
        # For each password in the uploaded payload.

        if(credential.get('Password') != ""):
            # If password isn't blank, check hashed credential against the HaveIBeenPwned dataset.
            compromised, occurrence = check_credential(credential.get('Password'))
        else:
            compromised, occurrence = [False, 0]

        if(credential['Created Time'] != ""):
            # If created time isn't blank, import time.
            created = make_aware(
                datetime.strptime(
                    credential.get('Created Time'),
                    "%d/%m/%Y %H:%M:%S"  # To Verify for other date formats
                )
            )
        else:
            created = None

        # Import security rating.
        match credential.get('Password Strength'):
            case "Very Strong":
                password_strength = Credential.SecurityRating.VERY_STRONG
            case "Strong":
                password_strength = Credential.SecurityRating.STRONG
            case "Medium":
                password_strength = Credential.SecurityRating.MEDIUM
            case "Weak":
                password_strength = Credential.SecurityRating.WEAK
            case _:
                password_strength = Credential.SecurityRating.VERY_WEAK

        # Initalise object and append to list for mass creation.
        credential_list.append(
            Credential(
                credential_scan=credential_scan,
                url=credential.get('URL'),
                browser=Browser.objects.get_or_create(
                    name=credential.get('Web Browser')
                )[0],
                storage=created,
                username=credential.get('User Name'),
                password_strength=password_strength,
                filename=credential.get('Filename'),
                compromised=compromised,
                occurrence=occurrence
            )
        )

        # Remove the hashed credential in the raw payload.
        data[id]['Password'] = "--- HASH REMOVED - NOT STORED ---"

    # Bulk create defined objects.
    Credential.objects.bulk_create(credential_list)

    # Mark credential scan as complete after loop finished.
    credential_scan.progress = CredentialScan.ScanStatus.COMPLETED
    credential_scan.save()

    # Store modified (hashes removed) raw request payload in the ApiRequest object.
    api_request.payload = json.dumps(data)
    api_request.save()

    return HttpResponse('Success')
