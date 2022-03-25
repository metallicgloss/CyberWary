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

from cyber_wary_portal.views import portal
from cyber_wary_portal.forms import ScanFormStep1, ScanFormStep2
from cyber_wary_portal.views.portal import ScanCreationWizard
from django.conf.urls import include
from django.urls import path
from django.views.generic import RedirectView

urlpatterns = [
    path(
        '',
        portal.index,
        name='portal'
    ),

    path('scan/', include([
        path(
            'create',
            ScanCreationWizard.as_view(
                [
                    ScanFormStep1,
                    ScanFormStep2
                ]
            ),
            name='create'
        ),

        path(
            'script/preview',
            portal.preview_script,
            name='preview_script'
        ),

        path(
            'history',
            portal.history,
            name='history'
        ),

        path(
            'activity/<scan_key>',
            portal.activity,
            name='activity'
        ),

        path(
            'record/<scan_key>',
            portal.scan,
            name='scan'
        ),

        path(
            'record/<scan_key>/<report>',
            portal.report,
            name='report'
        ),
    ])),

    path('account/', include([

        path(
            '',
            include('allauth.urls')
        ),

        path(
            'modify/',
            portal.modify,
            name='account_modify'
        ),

        path(
            'delete/',
            portal.delete,
            name='account_delete'
        ),


        # Void two unneeded URLs included within allauth
        path(
            'password/change/',
            RedirectView.as_view(
                pattern_name='portal',
                permanent=True
            )
        ),

        path(
            'password/set/',
            RedirectView.as_view(
                pattern_name='portal',
                permanent=True
            )
        ),

    ])),
]
