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
        'create',
        views.create,
        name='create'
    ),

    path(
        'report',
        views.report,
        name='report'
    ),

    path(
        'scans',
        views.scans,
        name='scans'
    ),

    # ----------------------------------------------------------------------- #
    #                      Authentication & Account URLs                      #
    # ----------------------------------------------------------------------- #

    # Void two unneeded URLs included within allauth
    path('account/password/change/',RedirectView.as_view(pattern_name='portal',permanent=True)),
    path('account/password/set/',RedirectView.as_view(pattern_name='portal',permanent=True)),

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
        'api/v1/start_scan',
        views.start_scan,
        name='start_scan'
    ),
]
