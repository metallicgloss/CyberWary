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

from cyber_wary_portal.views import api
from django.conf.urls import include
from django.urls import path

urlpatterns = [
    path(
        'payload',
        api.api_payload,
        name='api_payload'
    ),

    path(
        'credential',
        api.credential,
        name='credential'
    ),


    path('v1/', include([
        path(
            'start_scan',
            api.start_scan,
            name='start_scan'
        ),

        path(
            'end_scan',
            api.end_scan,
            name='end_scan'
        ),

        path(
            'firewall_rules',
            api.firewall_rules,
            name='firewall_rules'
        ),

        path(
            'network_adapters',
            api.network_adapters,
            name='network_adapters'
        ),

        path('applications/', include([
            path(
                'startup',
                api.applications_startup,
                name='startup'
            ),

            path(
                'installed',
                api.applications_installed,
                name='installed'
            ),
        ])),

        path('patches/', include([
            path(
                'pending',
                api.patches_pending,
                name='pending'
            ),

            path(
                'installed',
                api.patches_installed,
                name='installed'
            ),
        ])),

        path('antivirus/', include([
            path(
                'status',
                api.antivirus_status,
                name='status'
            ),

            path(
                'settings',
                api.antivirus_settings,
                name='settings'
            ),

            path(
                'detections',
                api.antivirus_detections,
                name='settings'
            ),
        ])),

        path(
            'system_users',
            api.system_users,
            name='system_users'
        ),

        path(
            'browser_passwords',
            api.browser_passwords,
            name='browser_passwords'
        ),

    ])),
]
