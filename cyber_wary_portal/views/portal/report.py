#
# GNU General Public License v3.0
# CyberWary - <https://github.com/metallicgloss/CyberWary>
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
from cyber_wary_portal.models import *
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.gis.geoip2 import GeoIP2
from django.db.models import Count
from django.http.response import HttpResponseNotFound
from django.shortcuts import render


# --------------------------------------------------------------------------- #
#                                                                             #
#                                 REPORT VIEW                                 #
#                                                                             #
#               The view associated with the generated report.                #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                             1. Generated Report                             #
# --------------------------------------------------------------------------- #
#                               1.1 Scan Report                               #
# --------------------------------------------------------------------------- #


@login_required
def report(request, scan_key, report):
    scan_data = {}

    # Capture the current scan record required for the report.
    try:
        scan_record = ScanRecord.objects.get(
            scan=Scan.objects.get(
                user=request.user,
                scan_key=scan_key
            ),
            id=report
        )

    except (ScanRecord.DoesNotExist, Scan.DoesNotExist):
        return HttpResponseNotFound()

    # Determine the duration of the scan.
    scan_duration = scan_record.updated - scan_record.created

    # ----------------------------------------------------------------------- #
    #                          Installed Applications                         #
    # ----------------------------------------------------------------------- #

    if(scan_record.scan.installed_applications):
        # If Installed Applications scan component is enabled.

        try:
            # If software objects exist for the scan record.
            applications = Software.objects.filter(
                scan_record=scan_record
            )

            # Store copy of the list of applications in the value returned to the template engine.
            scan_data['installed_applications'] = applications

            running_total = 0

            # Apply a filter to the list of applications installed to count installs by date.
            scan_data['install_timeline'] = applications.values(
                'install_date'
            ).annotate(
                Count('install_date')
            ).order_by(
                'install_date'
            ).exclude(
                install_date=None  # Ignore invalid dates.
            )

            for date in scan_data['install_timeline']:
                # For each date, append the count to a running total
                running_total += date['install_date__count']
                date['running_total'] = running_total

            # Initialise variables for
            scan_data['cves'] = 0
            scan_data['vulnerable_applications'] = 0

            for application in applications.order_by('name'):
                # For each application

                if application.cpe is not None:
                    # If application has a valid CPE

                    # Search for any matched CVEs
                    cve_matches = CVEMatches.objects.filter(
                        cpe=application.cpe
                    )

                    if cve_matches.exists():
                        # If a match exists, mark CVE match as true and add to CVE counters.
                        application.cve_match = True

                        scan_data['vulnerable_applications'] += 1
                        scan_data['cves'] += cve_matches.count()

        except (Software.DoesNotExist):
            scan_data['installed_applications'] = None

    # ----------------------------------------------------------------------- #
    #                            Browser Passwords                            #
    # ----------------------------------------------------------------------- #

    if(scan_record.scan.browser_passwords):
        # If Browser Passwords scan component is enabled.

        try:
            # Capture any credentials associated with the credential group linked to the scan record.
            scan_data['browser_passwords'] = Credential.objects.filter(
                credential_scan=CredentialScan.objects.get(
                    scan_record=scan_record
                )
            ).order_by('-occurrence')

            # Get list of usernames with an annotated count for their occurrences
            scan_data['usernames'] = scan_data['browser_passwords'].all().values(
                "username"
            ).annotate(
                Count(
                    'username'
                )
            )

            # Get the count of any credentials marked as compromised
            scan_data['compromised'] = scan_data['browser_passwords'].filter(
                compromised=True
            ).count()

            # Get the count of any credentials not marked as very strong.
            scan_data['weak'] = scan_data['browser_passwords'].exclude(
                password_strength=Credential.SecurityRating.VERY_STRONG
            ).count()

        except (Credential.DoesNotExist, CredentialScan.DoesNotExist):
            scan_data['browser_passwords'] = None

    # ----------------------------------------------------------------------- #
    #                        Windows Defender Firewall                        #
    # ----------------------------------------------------------------------- #

    if(scan_record.scan.network_firewall_rules):
        # If Windows Defender Firewall scan component is enabled.

        try:
            # Search for all firewall rules associated with the scan group
            scan_data['firewall_rules'] = FirewallRules.objects.filter(
                scan_record=scan_record
            ).order_by('name')

        except (FirewallRules.DoesNotExist):
            scan_data['firewall_rules'] = None

    # ----------------------------------------------------------------------- #
    #                       Windows Defender Anti-Virus                       #
    # ----------------------------------------------------------------------- #

    if(scan_record.scan.installed_antivirus):
        # If Windows Defender Anti-Virus scan component is enabled.

        try:
            # Try to get Defender values associated with the scan record.

            # Get the current defender status and set of preferences.
            scan_data['antivirus_status'] = DefenderStatus.objects.filter(
                scan_record=scan_record
            )[0]

            scan_data['antivirus_preferences'] = DefenderPreference.objects.filter(
                scan_record=scan_record
            )[0]

            # Search for list of preferences or exclusions associated with the scan.
            scan_data['antivirus_exclusions'] = DefenderExclusion.objects.filter(
                preference=scan_data['antivirus_preferences']
            )

            scan_data['antivirus_detections'] = DefenderDetection.objects.filter(
                scan_record=scan_record
            ).order_by('-created')

        except (Credential.DoesNotExist, CredentialScan.DoesNotExist, IndexError):
            scan_data['antivirus_status'] = None

    # ----------------------------------------------------------------------- #
    #                             Windows Updates                             #
    # ----------------------------------------------------------------------- #

    if(scan_record.scan.installed_patches):
        # If Windows Update scan component is enabled.

        try:
            # Collect two separated lists for installed and pending updates.
            scan_data['installed_patches'] = UpdateInstalled.objects.filter(
                scan_record=scan_record
            ).order_by('-date')

            scan_data['pending_patches'] = UpdatePending.objects.filter(
                scan_record=scan_record
            )

        except (UpdateInstalled.DoesNotExist, UpdatePending.DoesNotExist):
            scan_data['installed_patches'] = None

    # ----------------------------------------------------------------------- #
    #                               System Users                              #
    # ----------------------------------------------------------------------- #

    if(scan_record.scan.system_users):
        # If System Users scan component is enabled.

        try:
            # Get list of all system users.
            scan_data['system_users'] = WindowsUser.objects.filter(
                scan_record=scan_record
            )

            # Get count of any enabled accounts classified as default.
            scan_data['enabled_defaults'] = scan_data['system_users'].filter(
                name__in=[
                    'Administrator',
                    'DefaultAccount',
                    'Guest',
                    'WDAGUtilityAccount'
                ],
                enabled=True
            ).count()

        except (WindowsUser.DoesNotExist):
            scan_data['system_users'] = None

    return render(
        request,
        'scan/report/report.html',
        {
            # Pass the coordinates that match the geolocation of the IP.
            'coords': GeoIP2().lat_lon(scan_record.public_ip),
            'maps_key': settings.MAPS_KEY,
            'scan_data': scan_data,
            # Convert difference to usable time.
            'scan_duration': divmod(scan_duration.days * 86400 + scan_duration.seconds, 60),
            'scan_record': scan_record,
        }
    )
