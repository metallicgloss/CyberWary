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


def check_cpe(name, version, version_major, version_minor):
    cpe_filter = CPE.objects

    if(version_major is not None):
        version_filter = cpe_filter.filter(identifier__icontains=":"+str(version_major)+"."+str(version_minor))

        if(len(version_filter) != 0):
            check_cpe_name(version_filter, name, version)
            
        else:
            return None


    else:
        print("NO MAJOR VERSION")
        version_filter = cpe_filter.filter(identifier__icontains=version)

        if(len(cpe_filter) == 0):
            version_filter = cpe_filter.filter(title__icontains=version)

        check_cpe_name(version_filter, name, version)


def check_cpe_name(filter, name, version):
    old_filter = filter
    for name_fragment in name.split(" "):
        print(name_fragment)
        name_filter = old_filter.filter(identifier__icontains=name_fragment)
        print(len(name_filter))

        if(len(name_filter) == 1):
            print(name_filter[0].identifier)
            return name_filter[0].identifier
        elif(len(name_filter) > 1):
            print("More than 1")
            pass
        else:
            print("Final attempt, adding new fragment turns to 0")
            final = old_filter.filter(identifier__icontains=version)

            if(len(final) == 1):
                print(final[0].identifier)
                return final[0].identifier
            
            else:
                version_check = check_cpe_version(old_filter, version)

                if(len(version_check) == 0):
                    return remote_cpe_check(name, version)

                else:
                    return version_check

        old_filter = name_filter


def check_cpe_version(filter, version):
    count = 0
    for version_fragment in version.split("."):
        if(count != 0):
            version_fragment = "." + version_fragment

        version_filter = filter.filter(identifier__icontains=version_fragment)
        
        if(len(version_filter) == 1):
            return version_filter[0].identifier
        elif(len(version_filter) > 1):
            pass
        else:
            return None

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
        return None