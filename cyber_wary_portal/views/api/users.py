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
#                             SYSTEM USER API VIEW                            #
#                                                                             #
#          View associated with the system user import API request.           #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                            1. System User Action                            #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def system_users(request):
    # Import and process system users captured during the scan component.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'system_users',
        'users'
    )

    if(check_existing(scan, scan_record, User)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Define empty list for new objects to be appended to for mass creation.
    system_users = []

    for user in data:
        # For each user in the payload

        if(user.get('PrincipalSource') == 4):
            # If account source is 4, update to Microsoft.
            user['PrincipalSource'] = User.AccountType.MICROSOFT

        try:
            # Create user object and append to list for mass creation.
            system_users.append(
                User(
                    scan_record=scan_record,
                    name=user.get('Name'),
                    full_name=user.get('FullName'),
                    description=user.get('Description'),
                    sid=user.get('SID'),
                    source=user.get('PrincipalSource'),
                    last_logon=convert_unix_to_dt(user.get('LastLogon')),
                    enabled=user.get('Enabled'),
                    password_changeable=convert_unix_to_dt(
                        user.get('PasswordChangeableDate')
                        ),
                    password_expiry=convert_unix_to_dt(user.get('PasswordExpires')),
                    password_permission=user.get('UserMayChangePassword'),
                    password_required=user.get('PasswordRequired'),
                    password_last_set=convert_unix_to_dt(user.get('PasswordLastSet'))
                )
            )

        except KeyError:
            # Missing / Malformed data that differs to the default Windows output. Skip record.
            pass

    # Bulk create defined objects.
    User.objects.bulk_create(system_users)

    return HttpResponse('Success')
