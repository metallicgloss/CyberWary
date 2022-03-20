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
import requests
from cyber_wary_portal.models import ApiRequest, Scan, ScanRecord

from django.http.response import HttpResponse, JsonResponse, HttpResponseNotFound, HttpResponseBadRequest
import json

def bad_request(api_object):
    api_object.response = 400
    api_object.save()
    return HttpResponseBadRequest()


def setup_request(request, type, field):
    payload = request.data[field]
    device = request.data['device_id'].replace('{', '').replace('}', '')

    api_request = ApiRequest.objects.create(
        user = request.user,
        type = type,
        payload = json.dumps(payload),
        method = ApiRequest.RequestMethod.POST
    )

    try:
        scan = Scan.objects.get(
            user = request.user,
            scan_key = request.data['scan_key']
        )
    except Scan.DoesNotExist:
        scan = False

    try:
        scan_record = ScanRecord.objects.get(
            scan = scan,
            device_id = device
        )
    except ScanRecord.DoesNotExist:
        scan_record = False

    return [api_request, device, scan, scan_record, payload]

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


def check_credential(credential_sha1):
    password_data = requests.get(
        "https://api.pwnedpasswords.com/range/" + credential_sha1[0:5],
        headers={
            'User-Agent': 'CyberWary Research Project'
        },
    ).content.decode(
        "utf-8"
    ).split(
        "\r\n"
    )

    formatted_data = dict(
        hash.split(':') for hash in password_data
    )

    if credential_sha1[5:] in formatted_data:
        return [True, formatted_data[credential_sha1[5:]]]
    else:
        return [False, 0]
