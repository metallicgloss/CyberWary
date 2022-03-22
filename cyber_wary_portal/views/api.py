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
            credential = Credential.objects.filter(
                credential_scan__scan_record__scan__user = request.user,
                pk = request.POST['credentialID']
            )[0]

            formatted_credential = {}
            formatted_credential['username'] = credential.username
            formatted_credential['password_strength'] = credential.get_password_strength_display()
            formatted_credential['storage'] = credential.storage
            formatted_credential['browser'] = credential.browser.name
            formatted_credential['compromised'] = credential.compromised
            formatted_credential['occurrence'] = credential.occurrence
            formatted_credential['filename'] = credential.filename

            if "android" in credential.url:
                formatted_credential['url'] = re.sub(r'/.+?@', '', credential.url)
            else:
                formatted_credential['url'] = credential.url

            return JsonResponse(
                formatted_credential
            )
        except Credential.DoesNotExist:
            return HttpResponseNotFound()
    
    else:
        return HttpResponseBadRequest()


@api_view(['POST', ])
def start_scan(request):
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'start_scan',
        'system_information'
    )
    
    if(False in [scan, not scan_record]):
        return bad_request(api_request)
    
    geo_ip = GeoIP2()

    os_install = OperatingSystemInstall.objects.create(
        os = OperatingSystem.objects.get_or_create(
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
            os_install = os_install,
            language = Language.objects.get_or_create(
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
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'antivirus/status',
        'status '
    )

    existing_import = SecurityRecord.objects.filter(
        scan_record = scan_record,
    ).exists()

    if(False in [scan, scan_record, not existing_import]):
        return bad_request(api_request)

    SecurityRecord.objects.create(
        scan_record = scan_record,
        behavior_monitoring = payload['BehaviorMonitorEnabled'],
        tamper_protection = payload['IsTamperProtected'],
        realtime_protection = payload['RealTimeProtectionEnabled'],
        reboot_required = payload['RebootRequired'],
        access_protection = payload['OnAccessProtectionEnabled'],
        download_protection = payload['IoavProtectionEnabled'],
        virtual_machine = payload['IsVirtualMachine'],
        full_scan_required = payload['FullScanRequired'],
        full_scan_overdue = payload['FullScanOverdue'],
        full_scan_last = convert_date(payload['FullScanEndTime']),
        quick_scan_overdue =payload['QuickScanOverdue'],
        quick_scan_last = convert_date(payload['QuickScanEndTime']),
        as_enabled = payload['AntispywareEnabled'],
        as_signature_update = convert_date(payload['AntispywareSignatureLastUpdated']),
        as_signature_version = payload['AntispywareSignatureVersion'],
        av_enabled = payload['AntivirusEnabled'],
        av_signature_update = convert_date(payload['AntivirusSignatureLastUpdated']),
        av_signature_version = payload['AntivirusSignatureVersion'],
        nri_enabled = payload['NISEnabled'],
        nri_signature_update = convert_date(payload['NISSignatureLastUpdated']),
        nri_signature_version = payload['NISSignatureVersion']
    )

    return HttpResponse('')

    


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
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'system_users',
        'users'
    )

    existing_import = User.objects.filter(
        scan_record = scan_record,
    ).exists()

    if(False in [scan, scan_record, not existing_import]):
        return bad_request(api_request)

    
    for user in payload:
        if(user['PrincipalSource'] == 4):
            user['PrincipalSource'] = 2

        User.objects.create(
            scan_record = scan_record,
            name = user['Name'],
            full_name = user['FullName'],
            description = user['Description'],
            sid = user['SID'],
            source = user['PrincipalSource'],
            last_logon = convert_date(user['LastLogon']),
            enabled = user['Enabled'],
            password_changeable = convert_date(user['PasswordChangeableDate']),
            password_expiry = convert_date(user['PasswordExpires']),
            password_permission = user['UserMayChangePassword'],
            password_required = user['PasswordRequired'],
            password_last_set = convert_date(user['PasswordLastSet'])
        )

    return HttpResponse('')


@api_view(['POST', ])
def browser_passwords(request):
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'browser_passwords',
        'credentials'
    )
    api_request.payload = "Pending Processing"
    api_request.save()

    existing_import = CredentialScan.objects.filter(
        scan_record = scan_record,
    ).exists()

    if(False in [scan, scan_record, not existing_import]):
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
            password_strength = Credential.SecurityRating.VERY_STRONG
        elif (credential['Password Strength'] == "Strong"):
            password_strength = Credential.SecurityRating.STRONG
        elif (credential['Password Strength'] == "Medium"):
            password_strength = Credential.SecurityRating.MEDIUM
        elif (credential['Password Strength'] == "Weak"):
            password_strength = Credential.SecurityRating.WEAK
        else:
            password_strength = Credential.SecurityRating.VERY_WEAK
        
        Credential.objects.create(
            credential_scan = credential_scan,
            url = credential['URL'],
            browser = Browser.objects.get_or_create(
                name = credential['Web Browser']
            )[0],
            storage = created,
            username = credential['User Name'],
            password_strength = password_strength,
            filename = credential['Filename'],
            compromised = compromised,
            occurrence = occurrence
        )
        payload[id]['Password'] = "--- HASH REMOVED - NOT STORED ---"

    api_request.payload = json.dumps(payload)
    api_request.save()

    return HttpResponse('')

    

@api_view(['POST', ])
def end_scan(request):
    api_request, device, scan, scan_record, payload = setup_request(
        request,
        'end_scan',
        'completed'
    )
    
    if(False in [scan, scan_record]):
        return bad_request(api_request)

    scan_record.progress = scan_record.ScanStatus.COMPLETED
    scan_record.save()

    return HttpResponse('')