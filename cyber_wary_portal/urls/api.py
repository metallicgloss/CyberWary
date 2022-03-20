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


    path('v1/', include([
        path(
            'start_scan',
            api.start_scan,
            name='start_scan'
        ),

        path(
            'network_adapters',
            api.firewall_rules,
            name='network_adapters'
        ),

        path(
            'firewall_rules',
            api.firewall_rules,
            name='firewall_rules'
        ),

        path('applications/', include([
            path(
                'startup',
                api.firewall_rules,
                name='startup'
            ),

            path(
                'installed',
                api.firewall_rules,
                name='installed'
            ),
        ])),

        path('patches/', include([
            path(
                'pending',
                api.firewall_rules,
                name='pending'
            ),

            path(
                'installed',
                api.firewall_rules,
                name='installed'
            ),
        ])),

        path('antivirus/', include([
            path(
                'status',
                api.firewall_rules,
                name='status'
            ),

            path(
                'settings',
                api.firewall_rules,
                name='settings'
            ),
        ])),

        path(
            'system_users',
            api.firewall_rules,
            name='system_users'
        ),

        path('services/', include([
            path(
                'system',
                api.firewall_rules,
                name='system'
            ),

            path(
                'microsoft',
                api.firewall_rules,
                name='microsoft'
            ),

            path(
                'microsoft',
                api.firewall_rules,
                name='microsoft'
            ),

            path(
                'non_default',
                api.firewall_rules,
                name='non_default'
            ),

        ])),

        path(
            'browser_passwords',
            api.firewall_rules,
            name='browser_passwords'
        ),

    ])),
]
