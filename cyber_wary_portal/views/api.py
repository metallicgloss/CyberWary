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

from cyber_wary_portal.models import *
from cyber_wary_portal.utils.data_import import get_ip_address, convert_date
from django.contrib.auth.decorators import login_required
from django.contrib.gis.geoip2 import GeoIP2
from django.http.response import HttpResponse, JsonResponse, HttpResponseNotFound, HttpResponseBadRequest
from rest_framework.decorators import api_view
import json


@login_required
def api_payload(request):
    if request.method == 'POST':
        payload_id = request.POST['payloadID']
        request_type = request.POST['type']
    else:
        payload_id = request.GET['payloadID']
        request_type = request.GET['type']

    try:
        return JsonResponse(
            json.loads(
                ApiRequest.objects.get(
                    user=request.user,
                    pk=payload_id,
                    type=request_type,
                ).payload
            ), safe=False
        )
    except ApiRequest.DoesNotExist:
        return HttpResponseNotFound()


@api_view(['POST', ])
def start_scan(request):
    data = json.loads(
        request.POST['system_information']
    )

    api_request = ApiRequest(
        user=request.user,
        type='start_scan',
        payload=json.dumps(data),
        method=ApiRequest.RequestMethod.POST
    )
    api_request.save()

    device_id = request.POST['device_id'].replace(
        '{', ''
    ).replace(
        '}', ''
    )

    scan_check = Scan.objects.filter(
        user=request.user,
        scan_key=request.POST['scan_key']
    ).exists()

    if(scan_check):
        scan = Scan.objects.get(
            user=request.user,
            scan_key=request.POST['scan_key']
        )

        existing_record_check = ScanRecord.objects.filter(
            scan=scan,
            device_id=device_id
        ).exists()

        if(not existing_record_check):
            geo_ip = GeoIP2()

            os_install = OperatingSystemInstall(
                operating_system=OperatingSystem.objects.get_or_create(
                    name=data['OsName'],
                    version=data['OsVersion']
                )[0],
                serial=data['OsSerialNumber'],
                timezone=data['TimeZone'],
                install_date=convert_date(data['OsInstallDate']),
                keyboard=Language.objects.get_or_create(
                    locale=data['KeyboardLayout']
                )[0],
                owner=data['CsPrimaryOwnerName'],
                logon_server=data['LogonServer'],
                installed_memory=data['CsPhyicallyInstalledMemory'],
                domain=data['CsPartOfDomain'],
                portable=data['OsPortableOperatingSystem'],
                virtual_machine=data['HyperVisorPresent'],
                debug_mode=data['OsDebug'],
            )
            os_install.save()

            for language in data['OsMuiLanguages']:
                OperatingSystemInstalledLanguages(
                    operating_system_installation=os_install,
                    installed_language=Language.objects.get_or_create(
                        locale=language
                    )[0],
                ).save()

            scan_record = ScanRecord(
                scan=scan,
                device_id=device_id,
                name=data['CsDNSHostName'],
                os_install=os_install,
                bios_install=BiosInstall.objects.create(
                    bios=Bios.objects.get_or_create(
                        name=data['BiosName'],
                        version=data['BiosVersion'],
                        manufacturer=data['BiosManufacturer'],
                        release_date=convert_date(data['BiosReleaseDate'])
                    )[0],
                    install_date=convert_date(data['BiosInstallDate']),
                    status=data['BiosStatus'],
                    primary=data['BiosPrimaryBIOS']
                ),
                boot_time=convert_date(data['OsLastBootUpTime']),
                current_user=data['CsUserName'],
                public_ip=get_ip_address(request),
                city=geo_ip.city(get_ip_address(request))['city'],
                country=geo_ip.country_code(get_ip_address(request)).lower(),
            )
            scan_record.save()

            return HttpResponse('')

    api_request.response = 403
    api_request.save()

    return HttpResponseBadRequest()


@api_view(['POST', ])
def firewall_rules(request):
    ApiRequest(
        user=request.user,
        type='firewall_rules',
        payload=json.dumps(
            json.loads(
                request.POST['rules']
            )
        ),
        method=ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)
