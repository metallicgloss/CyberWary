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

from datetime import datetime
from django.conf import settings
from django.utils.timezone import make_aware


def get_ip_address(request):
    if(not settings.DEBUG):
        ip = request.META.get('HTTP_CF_CONNECTING_IP')

        if ip is None:
            ip = request.META.get('REMOTE_ADDR')

    else:
        ip = "185.216.147.18"

    return ip


def convert_date(date):
    if date is not None:
        date = make_aware(
            datetime.fromtimestamp(
                int(
                    date[date.find("(")+1:date.find(")")][0:10]
                )
            )
        )

    return date
