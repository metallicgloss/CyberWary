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
from cyber_wary_portal.models import ApiRequest, Credential, CPE, CVEMatches, FirewallRules, Software, CyberWaryUser
from django.shortcuts import render

# --------------------------------------------------------------------------- #
#                                                                             #
#                                  SITE VIEWS                                 #
#                                                                             #
#                Views associated with the public facing site.                #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. General Views                                     #
#                            1.1 Index                                        #
#                            1.2 Software                                     #
#                            1.3 Privacy Policy                               #
#                            1.4 Terms of Service                             #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                              1. General Views                               #
# --------------------------------------------------------------------------- #
#                                  1.1 Index                                  #
# --------------------------------------------------------------------------- #

def index(request):
    return render(
        request,
        'index.html',
        {
            'metrics': {
                'users': CyberWaryUser.objects.all().count(),
                'applications': Software.objects.all().count(),
                'passwords': Credential.objects.all().count()
            }
        }
    )


# --------------------------------------------------------------------------- #
#                                1.2 Software                                 #
# --------------------------------------------------------------------------- #

def software(request):
    return render(
        request,
        'software.html',
        {
            'metrics': {
                'requests': ApiRequest.objects.all().count(),
                'rules': FirewallRules.objects.all().count(),
                'vulnerabilities': CVEMatches.objects.filter(
                    cpe__in=CPE.objects.filter(
                        id__in=Software.objects.exclude(
                            cpe=None
                        ).values_list('cpe')
                    )
                ).count()
            }
        }
    )


# --------------------------------------------------------------------------- #
#                              1.3 Privacy Policy                             #
# --------------------------------------------------------------------------- #

def pp(request):
    return render(request, 'pp.html')


# --------------------------------------------------------------------------- #
#                            1.4 Terms of Service                             #
# --------------------------------------------------------------------------- #

def tos(request):
    return render(request, 'tos.html')
