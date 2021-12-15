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

from django.conf.urls import include
from django.contrib.auth import views as auth_views
from django.urls import path
from cyber_wary_portal import views
from .forms import LoginForm

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


    path(
        'login/',
        auth_views.LoginView.as_view(
            template_name="registration/login.html",
            authentication_form=LoginForm
        ),
        name='login'
    ),


    path(
        'register/',
        views.register,
        name='register'
    ),
    
    path(
        '',
        include('django.contrib.auth.urls')
    ),

    path(
        'modify/',
        views.modify,
        name='modify'
    ),
]