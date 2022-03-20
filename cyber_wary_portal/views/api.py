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

from http.client import HTTPResponse
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.data_import import *
from django.contrib.auth.decorators import login_required
from django.contrib.gis.geoip2 import GeoIP2
from django.http.response import HttpResponse, JsonResponse, HttpResponseNotFound
from rest_framework.decorators import api_view
import json
import re


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
                    user = request.user,
                    pk = payload_id,
                    type = request_type,
                ).payload
            ), safe = False
        )
    except ApiRequest.DoesNotExist:
        return HttpResponseNotFound()

@login_required
def credential(request):
    if request.method == 'POST':
        try:
            credential_record = CredentialRecord.objects.filter(
                credential_scan__scan_record__scan__user = request.user,
                pk = request.POST['credentialID']
            )[0]

            credential = {}
            credential['username'] = credential_record.username
            credential['password_strength'] = credential_record.get_password_strength_display()
            credential['storage'] = credential_record.storage
            credential['browser'] = credential_record.browser.browser_name
            credential['compromised'] = credential_record.compromised
            credential['occurrence'] = credential_record.occurrence
            credential['filename'] = credential_record.filename

            if "android" in credential_record.url:
                credential['url'] = re.sub(r'/.+?@', '', credential_record.url)
            else:
                credential['url'] = credential_record.url

            return JsonResponse(
                credential
            )
        except CredentialRecord.DoesNotExist:
            return HttpResponseNotFound()
    
    else:
        return HttpResponseBadRequest()



@api_view(['POST', ])
def start_scan(request):
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'browser_passwords',
        'system_information'
    )
    
    if(False in [scan, not scan_record]):
        return bad_request(api_request)
    
    geo_ip = GeoIP2()

    os_install = OperatingSystemInstall.objects.create(
        operating_system = OperatingSystem.objects.get_or_create(
            name = payload['OsName'],
            version = payload['OsVersion']
        )[0],
        serial = payload['OsSerialNumber'],
        timezone = payload['TimeZone'],
        install_date = convert_date(payload['OsInstallDate']),
        keyboard = Language.objects.get_or_create(
            locale = payload['KeyboardLayout']
        )[0],
        owner = payload['CsPrimaryOwnerName'],
        logon_server = payload['LogonServer'],
        installed_memory = payload['CsPhyicallyInstalledMemory'],
        domain = payload['CsPartOfDomain'],
        portable = payload['OsPortableOperatingSystem'],
        virtual_machine = payload['HyperVisorPresent'],
        debug_mode = payload['OsDebug'],
    )

    for language in payload['OsMuiLanguages']:
        OperatingSystemInstalledLanguages.objects.create(
            operating_system_installation = os_install,
            installed_language = Language.objects.get_or_create(
                locale = language
            )[0],
        )

    ScanRecord.objects.create(
        scan = scan,
        device_id = device,
        name = payload['CsDNSHostName'],
        os_install = os_install,
        bios_install = BiosInstall.objects.create(
            bios = Bios.objects.get_or_create(
                name = payload['BiosName'],
                version = payload['BiosVersion'],
                manufacturer = payload['BiosManufacturer'],
                release_date = convert_date(payload['BiosReleaseDate'])
            )[0],
            install_date = convert_date(payload['BiosInstallDate']),
            status = payload['BiosStatus'],
            primary = payload['BiosPrimaryBIOS']
        ),
        boot_time = convert_date(payload['OsLastBootUpTime']),
        current_user = payload['CsUserName'],
        public_ip = get_ip_address(request),
        city = geo_ip.city(get_ip_address(request))['city'],
        country = geo_ip.country_code(get_ip_address(request)).lower(),
    )

    return HttpResponse('')


@api_view(['POST', ])
def firewall_rules(request):
    ApiRequest(
        user = request.user,
        type = 'firewall_rules',
        payload = json.dumps(
            json.loads(
                request.POST['rules']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)


@api_view(['POST', ])
def network_adapters(request):
    ApiRequest(
        user = request.user,
        type = 'network_adapters',
        payload = json.dumps(
            json.loads(
                request.POST['system_information']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)


@api_view(['POST', ])
def applications_startup(request):
    ApiRequest(
        user = request.user,
        type = 'applications_startup',
        payload = json.dumps(
            json.loads(
                request.POST['applications']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)


@api_view(['POST', ])
def applications_installed(request):
    ApiRequest(
        user = request.user,
        type = 'applications_installed',
        payload = json.dumps(
            json.loads(
                request.POST['applications']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)


@api_view(['POST', ])
def patches_pending(request):
    ApiRequest(
        user = request.user,
        type = 'patches_pending',
        payload = json.dumps(
            json.loads(
                request.POST['patches']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)


@api_view(['POST', ])
def patches_installed(request):
    ApiRequest(
        user = request.user,
        type = 'patches_installed',
        payload = json.dumps(
            json.loads(
                request.POST['patches']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()

    return JsonResponse(request.data)


@api_view(['POST', ])
def antivirus_status(request):
    ApiRequest(
        user = request.user,
        type = 'antivirus_status',
        payload = json.dumps(
            json.loads(
                request.POST['status']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def antivirus_settings(request):
    ApiRequest(
        user = request.user,
        type = 'antivirus_settings',
        payload = json.dumps(
            json.loads(
                request.POST['settings']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def antivirus_detections(request):
    ApiRequest(
        user = request.user,
        type = 'antivirus_settings',
        payload = json.dumps(
            json.loads(
                request.POST['detections']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def system_users(request):
    ApiRequest(
        user = request.user,
        type = 'system_users',
        payload = json.dumps(
            json.loads(
                request.POST['users']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def services_system(request):
    ApiRequest(
        user = request.user,
        type = 'services_system',
        payload = json.dumps(
            json.loads(
                request.POST['services']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def services_microsoft(request):
    ApiRequest(
        user = request.user,
        type = 'services_microsoft',
        payload = json.dumps(
            json.loads(
                request.POST['services']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def services_non_default(request):
    ApiRequest(
        user = request.user,
        type = 'services_non_default',
        payload = json.dumps(
            json.loads(
                request.POST['services']
            )
        ),
        method = ApiRequest.RequestMethod.POST
    ).save()


@api_view(['POST', ])
def browser_passwords(request):
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'browser_passwords',
        'credentials'
    )
    api_request.payload = "Pending Processing"
    api_request.save()

    existing_scan = CredentialScan.objects.filter(
        scan_record = scan_record,
    ).exists()

    if(False in [scan, scan_record, not existing_scan]):
        return bad_request(api_request)

    credential_scan = CredentialScan.objects.create(
        scan_record = scan_record,
        progress = CredentialScan.ScanStatus.IN_PROGRESS
    )

    for id, credential in enumerate(payload):
        if(credential['Password'] != ""):
            compromised, occurrence = check_credential(credential['Password'])
        else:
            compromised, occurrence = [False, 0]

        if(credential['Created Time'] != ""):
            created = make_aware(
                datetime.strptime(
                    credential['Created Time'],
                    "%d/%m/%Y %H:%M:%S" #To Verify for other date formats
                )
            )
        else:
            created = None
        
        if(credential['Password Strength'] == "Very Strong"):
            password_strength = CredentialRecord.SecurityRating.VERY_STRONG
        elif (credential['Password Strength'] == "Strong"):
            password_strength = CredentialRecord.SecurityRating.STRONG
        elif (credential['Password Strength'] == "Medium"):
            password_strength = CredentialRecord.SecurityRating.MEDIUM
        elif (credential['Password Strength'] == "Weak"):
            password_strength = CredentialRecord.SecurityRating.WEAK
        else:
            password_strength = CredentialRecord.SecurityRating.VERY_WEAK
        
        CredentialRecord.objects.create(
            credential_scan = credential_scan,
            url = credential['URL'],
            browser = Browser.objects.get_or_create(
                browser_name = credential['Web Browser']
            )[0],
            storage = created,
            username = credential['User Name'],
            password_strength = password_strength,
            filename = credential['Filename'],
            compromised = compromised,
            occurrence = occurrence
        )
        payload[id]['Password'] = "--- HASH REMOVED - NOT STORED ---"

    api_request.payload = payload
    api_request.save()

    return HttpResponse('')