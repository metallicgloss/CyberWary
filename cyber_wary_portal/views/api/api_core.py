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

# Module/Library Import
from cvss import CVSS2, CVSS3
from cyber_wary_portal.forms import ApiKeyForm
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.data_import import *
from datetime import datetime
from django.contrib.auth.decorators import login_required
from django.contrib.gis.geoip2 import GeoIP2
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse, HttpResponseNotFound
from django.shortcuts import render
from django.urls import reverse
from django.utils.timezone import make_aware
from pytz import timezone
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
import json
import re


# --------------------------------------------------------------------------- #
#                                                                             #
#                                CORE API VIEWS                               #
#                                                                             #
#      Views associated with the core functionality of the platform API.      #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Portal Actions                                    #
#                            1.1 View Log & Settings                          #
#                            1.2 View API Payload                             #
#                            1.3 View Credential Details                      #
#                        2. Scan Actions                                      #
#                            2.1 Start Scan                                   #
#                            2.2 End Scan                                     #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                              1. Portal Action                               #
# --------------------------------------------------------------------------- #
#                           1.1 View Log & Settings                           #
# --------------------------------------------------------------------------- #


@login_required
def api(request):
    # Web request to view the API log & settings page.
    key_updated = False

    if request.method == 'POST':
        # Post request - regeneration of API key request.
        form = ApiKeyForm(request.POST)

        if form.is_valid():
            # Form is valid, if confirmation given, re-generate key.
            if(form.data.get('confirmation') == "true"):
                api_key = Token.objects.filter(user=request.user)
                new_key = api_key[0].generate_key()
                api_key.update(
                    key=new_key,
                    created=make_aware(
                        datetime.now(),
                        timezone=timezone("Europe/London")
                    )
                )

                # Make a record that the API key has been re-generated.
                ApiRequest(
                    user=request.user,
                    type='regenerate_api_key',
                    payload=json.dumps(
                        json.loads(
                            '{ "request": "Re-generate API Key Request" }'
                        )
                    ),
                    method=ApiRequest.RequestMethod.POST
                ).save()

                # Redirect user back with update status.
                return HttpResponseRedirect(
                    "%s?update=true" % reverse('api')
                )

    else:
        # GET request, load page.
        form = ApiKeyForm()

        # Create user token if not generated, else, get existing token.
        api_key = Token.objects.get_or_create(
            user=request.user
        )

        if(request.GET.get('update') is not None):
            key_updated = True

    # Query all API logs for the user.
    api_log = ApiRequest.objects.filter(
        user=request.user
    ).order_by(
        '-created'
    )

    return render(
        request,
        'account/api.html',
        {
            'form': form,
            'api_key': api_key[0],
            'update': key_updated,
            'api_log': api_log
        }
    )


# --------------------------------------------------------------------------- #
#                             1.2 View API Payload                            #
# --------------------------------------------------------------------------- #

@login_required
def api_payload(request):
    # Function to return the raw payload associated with an API request to the user.

    # Default the location for the request data to be from POST
    data = request.POST

    if request.method == 'GET':
        # If GET request (loaded in new tab), switch data location to GET.
        data = request.GET

    try:
        # Attempt to retrieve and return the payload from the ApiRequest object after being formatted into JSON.
        return JsonResponse(
            json.loads(
                ApiRequest.objects.get(
                    user=request.user,
                    pk=data.get('payloadID'),
                    type=data.get('type'),
                ).payload
            ), safe=False
        )

    except ApiRequest.DoesNotExist:
        # ApiRequest query failed, return error.
        return HttpResponseNotFound()


# --------------------------------------------------------------------------- #
#                         1.3 View Credential Details                         #
# --------------------------------------------------------------------------- #

@login_required
def credential(request):
    # Function to return the stored credential details for population into the popup.

    if request.method == 'POST':
        try:
            # Attempt to retrieve the Credential object that matches the submitted request.
            credential = Credential.objects.filter(
                credential_scan__scan_record__scan__user=request.user,
                pk=request.POST.get('credentialID')
            )[0]

        except Credential.DoesNotExist:
            # No Credential matching the request was found; return error.
            return HttpResponseNotFound()

        # Re-format object into stripped down JSON data structure.
        formatted = {}
        formatted['username'] = credential.username
        formatted['password_strength'] = credential.get_password_strength_display()
        formatted['storage'] = credential.storage
        formatted['browser'] = credential.browser.name
        formatted['compromised'] = credential.compromised
        formatted['occurrence'] = credential.occurrence
        formatted['filename'] = credential.filename

        if "android" in credential.url:
            # If URL contains android (android data URL), strip data from URL to return domain.
            formatted['url'] = re.sub(
                r'/.+?@',  # Contents between / and @
                '',
                credential.url
            )
        else:
            # No re-formatting needed.
            formatted['url'] = credential.url

        return JsonResponse(
            formatted
        )

    else:
        # GET request was made - not permitted for this call; return error.
        return HttpResponseBadRequest()


# --------------------------------------------------------------------------- #
#                             1.4 View CVE Details                            #
# --------------------------------------------------------------------------- #

@login_required
def cve(request):
    # Function to return the stored credential details for population into the popup.

    if request.method == 'POST':
        # Re-format object into stripped down JSON data structure.
        formatted = {}

        # Get all CVEs related to the submitted CPE.
        cve_matches = CVEMatches.objects.filter(
            cpe__identifier=request.POST.get('cpe')
        )

        if cve_matches.exists():
            # If the CPE has at least one CVE.

            for match in cve_matches:    
                # For each detected CVE.

                if('CVSS' in match.cve.cvss):
                    # If CVSS is included in the vector, use Version 3.
                    vector = CVSS3(match.cve.cvss)
                else:
                    # Use version 2.
                    vector = CVSS2(match.cve.cvss)

                # Add CVE to the formatted list for JSON reply.
                formatted[match.cve.identifier] = {
                    'assigner': match.cve.assigner,
                    'description': match.cve.description,
                    'published': match.cve.published.strftime("%d/%m/%Y"),
                    'severity_rating': vector.severities()[0],
                    'severity_score': vector.scores()[0],
                    'references': []
                }                    

                # Lookup all references and support links associated with the CVE.
                cve_references = CVEReference.objects.filter(
                    cve=match.cve
                )

                if cve_references.exists():
                    # If there are references associated with the CVE.

                    for reference in cve_references:
                        # For each reference, add to the list.

                        formatted[match.cve.identifier]['references'].append(
                            {
                                'url': reference.url,
                                'source': reference.source,
                                'tags': reference.tags
                            }                            
                        )

        return JsonResponse(
            formatted
        )

    else:
        # GET request was made - not permitted for this call; return error.
        return HttpResponseBadRequest()


# --------------------------------------------------------------------------- #
#                               2. Scan Actions                               #
# --------------------------------------------------------------------------- #
#                                2.1 Start Scan                               #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def start_scan(request):
    # API call to initialise the scan for a device.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'start_scan',
        'system_information'
    )

    if(False in [scan, not scan_record]):
        # If the scan group does not exist, or there is already an existing record for this device associated with the scan group.
        return bad_request(api_request)

    # Initialise GeoIP2 instance for future geolocation.
    geo_ip = GeoIP2()

    try:
        # Create record for device being scanned.
        scan_record = ScanRecord.objects.create(
            scan=scan,
            device_id=device,
            name=data.get('CsDNSHostName'),
            os_install=OperatingSystemInstall.objects.create(  # Create object for the OS installation.
                os=OperatingSystem.objects.get_or_create(  # If Operating System Version/Name not seen before, create object.
                    name=data.get('OsName'),
                    version=data.get('OsVersion')
                )[0],
                serial=data.get('OsSerialNumber'),
                timezone=data.get('TimeZone'),
                install_date=convert_unix_to_dt(data.get('OsInstallDate')),
                keyboard=Language.objects.get_or_create(  # If Language not seen before, create object.
                    locale=data.get('KeyboardLayout')
                )[0],
                owner=data.get('CsPrimaryOwnerName'),
                logon_server=data.get('LogonServer'),
                installed_memory=data.get('CsPhyicallyInstalledMemory'),
                domain=data.get('CsPartOfDomain'),
                portable=data.get('OsPortableOperatingSystem'),
                virtual_machine=data.get('HyperVisorPresent'),
                debug_mode=data.get('OsDebug'),
            ),
            bios_install=BiosInstall.objects.create(  # Create object for the BIOS installation.
                bios=Bios.objects.get_or_create(  # If BIOS Version not seen before, create object.
                    name=data.get('BiosName'),
                    version=data.get('BiosVersion'),
                    manufacturer=data.get('BiosManufacturer'),
                    release_date=convert_unix_to_dt(data.get('BiosReleaseDate'))
                )[0],
                install_date=convert_unix_to_dt(data.get('BiosInstallDate')),
                install_status=data.get('BiosStatus'),
                primary=data.get('BiosPrimaryBIOS')
            ),
            boot_time=convert_unix_to_dt(data.get('OsLastBootUpTime')),
            current_user=data.get('CsUserName'),
            public_ip=get_ip_address(request),
            city=geo_ip.city(get_ip_address(request)).get('city'),
            country=geo_ip.country_code(get_ip_address(request)).lower(),
        )

    except KeyError:
        # Missing / Malformed data that differs to the default Windows output. Fail request; return error.
        return bad_request(api_request)

    for language in data.get('OsMuiLanguages'):
        # For each language detected as being installed on the system, create install languages record.
        OperatingSystemInstalledLanguages.objects.create(
            os_install=scan_record.os_install,
            language=Language.objects.get_or_create(
                locale=language
            )[0],
        )

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                                 2.2 End Scan                                #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def end_scan(request):
    # Mark data upload associated with a device scan as complete.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'end_scan',
        'completed'
    )

    if(False in [scan, scan_record]):
        # If scan group or scan record doesn't exist; return error.
        return bad_request(api_request)

    # Update status for the scan record and save.
    scan_record.progress = scan_record.ScanStatus.COMPLETED
    scan_record.save()

    return HttpResponse('Success')
