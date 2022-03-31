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

from cyber_wary_portal.models import ApiRequest, Scan, ScanRecord, DefenderExclusion, CPE, CWE, CVE
from datetime import datetime
from django.conf import settings
from django.http.response import HttpResponseBadRequest
from django.utils.timezone import make_aware
import json
import requests
from django.db.models import Q


def bad_request(api_request):
    api_request.response = 400
    api_request.save()
    return HttpResponseBadRequest()


def setup_request(request, type, field, convert=False):
    if(convert):
        payload = json.loads(request.data[field])
    else:
        payload = request.data[field]

    device = request.data['device_id'].replace('{', '').replace('}', '')

    api_request = ApiRequest.objects.create(
        user=request.user,
        type=type,
        payload=json.dumps(payload),
        method=ApiRequest.RequestMethod.POST
    )

    try:
        scan = Scan.objects.get(
            user=request.user,
            scan_key=request.data['scan_key']
        )
    except Scan.DoesNotExist:
        scan = False

    try:
        scan_record = ScanRecord.objects.get(
            scan=scan,
            device_id=device
        )
    except ScanRecord.DoesNotExist:
        scan_record = False

    return [api_request, device, scan, scan_record, payload]


def check_existing(scan, scan_record, object_type):
    # Check for any existing imports associated with the same scan record.
    existing_import = object_type.objects.filter(
        scan_record=scan_record,
    ).exists()

    if(False in [scan, scan_record, not existing_import]):
        # If scan group or scan record cannot be found, or an existing import has taken place; return error.
        return True
    else:
        return False


def get_ip_address(request):
    if(not settings.DEBUG):
        ip = request.META.get('HTTP_CF_CONNECTING_IP')

        if ip is None:
            ip = request.META.get('REMOTE_ADDR')

    else:
        ip = "185.216.147.18"

    return ip


def convert_unix_to_dt(date):
    if date is not None:
        date = make_aware(
            datetime.fromtimestamp(
                int(
                    date[date.find("(")+1:date.find(")")][0:10]
                )
            )
        )

    return date


def convert_date(date):
    if date is not None:
        date = datetime.strptime(date, '%Y%m%d').strftime('%Y-%m-%d')
    return date


def import_exclusions(exclusion_list, exclusion_type, exclusion_method, preference):
    if exclusion_list is not None:
        if "N/A" not in exclusion_list[0]:
            for exclusion in exclusion_list:
                DefenderExclusion.objects.create(
                    preference=preference,
                    type=exclusion_type,
                    method=exclusion_method,
                    value=exclusion
                )


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


def import_cpe(software):
    software.save()
    
    title_filter = CPE.objects

    for word in software.name.split(" "):
        # Name Lookup
        title_filter = title_filter.filter(Q(identifier__icontains=word) | Q(title__icontains=word))

        if(title_filter.count() > 1):
            version_lookup = check_cpe_version(title_filter, software.version)
            
            if(version_lookup == None):
                # Online Check
                print("Online Check here")
            elif(version_lookup.count() > 1):
                continue
            elif(version_lookup.count() == 1):
                print(version_lookup[0].identifier)
                return version_lookup[0]

        elif(title_filter.count() == 1):
            print(title_filter[0].identifier)
            return title_filter[0]

        else:
            # Online Check
            print("Online Check here")
            break
			



def check_cpe_version(version_filter, version):
    full_filter = version_filter.filter(identifier__icontains=":" + str(version))

    if(full_filter.count() == 1):
        return full_filter
    else:
        count = 0
        for fragment in version.split("."):
            if(count != 0):
                build_version = fragment + "." + fragment
            else:
                build_version = fragment

            fragment_filter = version_filter.filter(identifier__icontains=str(build_version))
        
            if(fragment_filter.count() > 1 and count > 0):
                final_filter = fragment_filter.filter(identifier__icontains=str(build_version)+":")
                
                if(final_filter.count() == 1):
                    return final_filter

            elif(fragment_filter.count() == 1):
                return version_filter

            elif(fragment_filter.count() == 0):
                return None

            count += 1
    

def remote_cpe_check(name, version):
    remote_cpe = requests.get(
        "https://services.nvd.nist.gov/rest/json/cpes/1.0/",
        headers={
            'User-Agent': 'CyberWary Research Project'
        },
        params={
            'keyword': name + " " + version
        }
    )

    if(len(remote_cpe.json()['cpes'])):
        return remote_cpe.json()['cpes'][0]['cpe23Uri']
    
    else:
        return []