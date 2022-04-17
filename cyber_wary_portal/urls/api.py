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

from cyber_wary_portal.views.api import *
from django.conf.urls import include
from django.urls import path

urlpatterns = [
    path(
        'settings/',
        api_core.api,
        name='api'
    ),

    path(
        'payload',
        api_core.api_payload,
        name='api_payload'
    ),

    path(
        'credential',
        api_core.credential,
        name='credential'
    ),

    path(
        'cve',
        api_core.cve,
        name='cve'
    ),


    path('v1/', include([
        path(
            'start_scan',
            api_core.start_scan,
            name='start_scan'
        ),

        path(
            'end_scan',
            api_core.end_scan,
            name='end_scan'
        ),

        path(
            'browser_passwords',
            credential.browser_passwords,
            name='browser_passwords'
        ),

        path(
            'applications_installed',
            software.applications_installed,
            name='applications_installed'
        ),

        path(
            'system_users',
            users.system_users,
            name='system_users'
        ),

        path('firewall/', include([
            path(
                'rules',
                windows_defender.firewall_rules,
                name='firewall_rules'
            ),

            path(
                'applications',
                windows_defender.firewall_applications,
                name='firewall_applications'
            ),

            path(
                'ips',
                windows_defender.firewall_ips,
                name='firewall_ips'
            ),

            path(
                'ports',
                windows_defender.firewall_ports,
                name='firewall_ports'
            ),
        ])),

        path('antivirus/', include([
            path(
                'status',
                windows_defender.antivirus_status,
                name='antivirus_status'
            ),

            path(
                'preferences',
                windows_defender.antivirus_preferences,
                name='antivirus_preferences'
            ),

            path(
                'detections',
                windows_defender.antivirus_detections,
                name='antivirus_detections'
            ),
        ])),

        path('patches/', include([
            path(
                'pending',
                windows_update.patches_pending,
                name='patches_pending'
            ),

            path(
                'installed',
                windows_update.patches_installed,
                name='patches_installed'
            ),
        ])),

    ])),
]
