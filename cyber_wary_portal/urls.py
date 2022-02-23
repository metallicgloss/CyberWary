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

from cyber_wary_portal import views
from django.conf.urls import include
from django.urls import path
from django.views.generic import RedirectView
from .forms import ScanFormStep1, ScanFormStep2
from .views import ScanCreationWizard

urlpatterns = [
    # ----------------------------------------------------------------------- #
    #                                Core URLs                                #
    # ----------------------------------------------------------------------- #

    path(
        '',
        views.index,
        name='portal'
    ),

    path(
        'scan/create',
        ScanCreationWizard.as_view(
            [
                ScanFormStep1,
                ScanFormStep2
            ]
        ),
        name='create'
    ),

    path(
        'scan/script/preview',
        views.preview_script,
        name='preview_script'
    ),

    path(
        'scan/history',
        views.history,
        name='history'
    ),

    path(
        'scan/activity/<scan_key>',
        views.activity,
        name='activity'
    ),

    path(
        'scan/record/<scan_key>',
        views.scan,
        name='scan'
    ),

    path(
        'scan/record/<scan_key>/<report>',
        views.report,
        name='report'
    ),

    # ----------------------------------------------------------------------- #
    #                      Authentication & Account URLs                      #
    # ----------------------------------------------------------------------- #

    # Void two unneeded URLs included within allauth
    path(
        'account/password/change/',
        RedirectView.as_view(
            pattern_name='portal',
            permanent=True
        )
    ),

    path(
        'account/password/set/',
        RedirectView.as_view(
            pattern_name='portal',
            permanent=True
        )
    ),

    path(
        'account/',
        include('allauth.urls')
    ),

    path(
        'account/modify/',
        views.modify,
        name='account_modify'
    ),

    path(
        'api/',
        views.api,
        name='api'
    ),

    path(
        'api/payload',
        views.api_payload,
        name='api_payload'
    ),

    path(
        'api/v1/start_scan',
        views.start_scan,
        name='start_scan'
    ),

    path(
        'api/v1/firewall_rules',
        views.firewall_rules,
        name='firewall_rules'
    ),
]
