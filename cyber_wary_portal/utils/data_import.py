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
from cyber_wary_portal.models import ApiRequest, Scan, ScanRecord, DefenderExclusion, CPE
from datetime import datetime
from django.conf import settings
from django.http.response import HttpResponseBadRequest
from django.utils.timezone import make_aware
import json
import requests


# --------------------------------------------------------------------------- #
#                                                                             #
#                           DATA IMPORT ASSISTANCE                            #
#                                                                             #
#      Functions to assist with the import of script component payloads.      #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Common Request Functions                          #
#                            1.1 Setup Request                                #
#                            1.2 Check For Existing                           #
#                            1.3 Mark as Bad Request                          #
#                        2. Import Helper Functions                           #
#                            2.1 Get IP Address                               #
#                            2.2 Convert Date                                 #
#                            2.3 Convert Unix Date                            #
#                            2.4 Import Exclusions                            #
#                            2.5 Check Credential Compromise                  #
#                        3. CPE Import Functions                              #
#                            3.1 Search CPE                                   #
#                            3.2 Search CPE by Version                        #
#                            3.3 Search CPE by Remote                         #
#                            3.4 Search CPE by Manual Override                #                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                         1. Common Request Functions                         #
# --------------------------------------------------------------------------- #
#                              1.1 Setup Request                              #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
#                           1.2 Check For Existing                            #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
#                           1.3 Mark as Bad Request                           #
# --------------------------------------------------------------------------- #
def bad_request(api_request):
    api_request.response = 400
    api_request.save()
    return HttpResponseBadRequest()


# --------------------------------------------------------------------------- #
#                          2. Import Helper Functions                         #
# --------------------------------------------------------------------------- #
#                              2.1 Get IP Address                             #
# --------------------------------------------------------------------------- #

def get_ip_address(request):
    # Get the IP address associated with a request.

    if(not settings.DEBUG):
        # If deployed to production.

        # Get CloudFlare pass-through IP address
        ip = request.META.get('HTTP_CF_CONNECTING_IP')

        if ip is None:
            # If CloudFlare IP is not set, attempt to get default header field.
            ip = request.META.get('REMOTE_ADDR')

    else:
        # In development mode - default to CloudFlare DNS IP as placeholder.
        ip = "1.1.1.1"

    return ip


# --------------------------------------------------------------------------- #
#                               2.2 Convert Date                              #
# --------------------------------------------------------------------------- #

def convert_date(date):
    # Convert a compressed date returned by PowerShell into usable datetime object.
    if date is not None:
        try:
            # Attempt to parse date.
            date = datetime.strptime(date, '%Y%m%d').strftime('%Y-%m-%d')

        except ValueError:
            # Parsing failed - unexpected data format.
            date = None

    return date


# --------------------------------------------------------------------------- #
#                            2.3 Convert Unix Date                            #
# --------------------------------------------------------------------------- #

def convert_unix_to_dt(date):
    # Convert unix timestamp returned by PowerShell to usable datetime object.

    if date is not None:
        # If date isn't null.

        try:
            # Attempt to parse date.
            date = make_aware(
                datetime.fromtimestamp(
                    int(
                        date[date.find("(")+1:date.find(")")][0:10]
                    )
                )
            )

        except ValueError:
            # Parsing failed - unexpected data format.
            date = None

    return date


# --------------------------------------------------------------------------- #
#                            2.4 Import Exclusions                            #
# --------------------------------------------------------------------------- #

def import_exclusions(exclusion_list, exclusion_type, exclusion_method, preference):
    # Import exclusions associated with Windows Defender.

    if exclusion_list is not None:
        # If list is not null

        if "N/A" not in exclusion_list[0]:
            for exclusion in exclusion_list:
                # For each exclusion, create object.
                DefenderExclusion.objects.create(
                    preference=preference,
                    type=exclusion_type,
                    method=exclusion_method,
                    value=exclusion
                )


# --------------------------------------------------------------------------- #
#                       2.5 Check Credential Compromise                       #
# --------------------------------------------------------------------------- #

def check_credential(credential_sha1):
    # Perform remote check on HaveIBeenPwned Passwords API for compromise

    # Get API request payload.
    password_data = requests.get(
        # Pass first 5 characters of SHA1 hash.
        "https://api.pwnedpasswords.com/range/" + credential_sha1[0:5],
        headers={
            'User-Agent': 'CyberWary Research Project'
        },
    ).content.decode(
        "utf-8"
    ).split(
        "\r\n"
    )

    # Format HTTPResponse into JSON Dict for traversal.
    formatted_data = dict(
        hash.split(':') for hash in password_data
    )

    if credential_sha1[5:] in formatted_data:
        # If the full hash (minus the first five characters) exists in the returned dataset.

        # Return marked as compromised and full hash.
        return [True, formatted_data[credential_sha1[5:]]]

    else:
        # Return marked as not detected in dataset and 0.
        return [False, 0]


# --------------------------------------------------------------------------- #
#                           3. CPE Import Functions                           #
# --------------------------------------------------------------------------- #
#                               3.1 Search CPE                                #
# --------------------------------------------------------------------------- #

def search_cpe(software):
    # Function called in thread.
    # Perform a full lookup for any CPE associated with the software.

    for application in software:
        # For each application detected in the system, scan for CPEs.

        # Define base filter target - called each application to reset filters.
        title_filter = CPE.objects

        # Initialise blank keyword variable.
        keyword = ""

        # Check CPE exists in manual override set.
        cpe = search_cpe_by_manual_override(application)

        if(cpe != ""):
            # If CPE not detected (not overwritten in the manual check)

            for word in application.name.split(" "):
                # Split application name, iterate through each word.

                # Build keyword for each loop
                keyword += word + " "

                # Lookup CPE based on existing filters as well as the new word in the name.
                title_filter = title_filter.filter(title__icontains=word)

                if(title_filter.count() > 1):
                    # Filter with existing filters to search by name returns more than one possible match.

                    # Search existing filtered dataset by version to see if exact match.
                    version_lookup = search_cpe_by_version(
                        title_filter,
                        application.version
                    )

                    if(version_lookup == None):
                        # Applying any combination of version to the filter returns no results.
                        # Further lookups with additional name filters will not improve search.

                        # Perform a final lookup on the remote dataset to see if new version released.
                        cpe = search_cpe_by_remote(
                            # Pass through keyword (all words searched in filter)
                            keyword,
                            application.version
                        )

                    elif(version_lookup.count() > 1):
                        # Even with version filters applied, name sort too broad, returned more than 1 result.

                        # Continue to apply next title word to filter.
                        continue

                    elif(version_lookup.count() == 1):
                        # Returned an exact match for the title name filters and version number.

                        # Assign CPE to the discovered value.
                        cpe = version_lookup[0]

                elif(title_filter.count() == 1):
                    # Returned an exact match for the title name filter.
                    # CAUTION: Without matches with exact version number, false positive rate higher than liked.

                    # Assign CPE to the discovered value.
                    cpe = title_filter[0]

        if(cpe != "" and cpe is not None):
            # If CPE has been discovered and set.

            # Assign CPE to application
            application.cpe = cpe
            application.save()


# --------------------------------------------------------------------------- #
#                          3.2 Search CPE by Version                          #
# --------------------------------------------------------------------------- #

def search_cpe_by_version(version_filter, version):
    # Apply additional filters upon existing filtered dataset to attempt to find match with version.

    # Apply full version string as a filter.
    full_filter = version_filter.filter(
        identifier__icontains=":" + str(version)
    )

    if(full_filter.count() == 1):
        # Applying the full version to the current filters returned a single result - CPE found.
        return full_filter

    else:
        count = 0

        for fragment in version.split("."):
            # Split version by period, and iterate per fragment.

            if(count != 0):
                # If not the first iteration, append the new fragment to the current build version.
                build_version = build_version + "." + str(fragment)
            else:
                # On the first iteration, set the build version to be the first fragment.
                build_version = str(fragment)

            # Filter by current build version lookup term.
            fragment_filter = version_filter.filter(
                identifier__icontains=build_version
            )

            if(fragment_filter.count() > 1 and count > 0):
                # Filter returned more than one result, and not on the first iteration.
                # Skip on the first iteration due to high false-positive rate for searching by single number.

                # Filter to apply : to end of current build version.
                # CPE versions can be shorted - EG - :10.2.5.122: can be grouped as :10.2.5:
                shortened_version_filter = fragment_filter.filter(
                    identifier__icontains=build_version + ":"
                )

                if(shortened_version_filter.count() == 1):
                    # Shortened version filter returned a single CPE.
                    return shortened_version_filter

            elif(fragment_filter.count() == 1):
                # Version lookup on top of existing filters returned a single result.
                return version_filter

            elif(fragment_filter.count() == 0):
                # Applying version filter returns no results, unable to determine exact CPE.
                return None

            # Increment count by 1
            count += 1


# --------------------------------------------------------------------------- #
#                          3.3 Search CPE by Remote                           #
# --------------------------------------------------------------------------- #

def search_cpe_by_remote(name, version):
    # Check for CPE on the remote hosted instance.

    # Get returned payload from API request.
    remote_cpe = requests.get(
        "https://services.nvd.nist.gov/rest/json/cpes/1.0/",
        headers={
            'User-Agent': 'CyberWary Research Project'  # Identify user.
        },
        params={
            'keyword': name + version,  # Send application name and version as keywords
            # Only get exact matches (to prevent searching by only version number)
            'isExactMatch': "true",
            'includeDeprecated': "true"  # Include old or deprecated CPEs.
        }
    ).json()

    if(remote_cpe['totalResults'] > 0):
        # If remote lookup returned more than one result.

        # Lookup cached CPEs to see if one matches.
        existing_cpe = CPE.objects.filter(
            identifier=remote_cpe['result']['cpes'][0]['cpe23Uri']
        )

        if(existing_cpe.exists()):
            # Match fount.
            return existing_cpe[0]

        else:
            # No match found, new CPE since import.

            # Create CPE.
            return CPE.objects.create(
                title=remote_cpe.get('cpes')[0].get('titles')[0].get('title'),
                identifier=remote_cpe.get('cpes')[0].get('cpe23Uri')
            )

    else:
        # No results found for query.
        return None


# --------------------------------------------------------------------------- #
#                      3.4 Search CPE by Manual Override                      #
# --------------------------------------------------------------------------- #

def search_cpe_by_manual_override(software):
    # Manual override for odd behaviour lookups identified

    if("Microsoft 365 Apps for enterprise" in software.name):
        return CPE.objects.get(
            identifier='cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*'
        )
    if("Microsoft 365" in software.name):
        return CPE.objects.get(
            identifier='cpe:2.3:a:microsoft:365_apps:-:*:*:*:*:*:*:*'
        )

    # No matches
    return ""
