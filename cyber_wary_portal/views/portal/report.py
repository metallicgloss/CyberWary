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

    try:
        scan_record = ScanRecord.objects.get(
            scan=Scan.objects.get(
                user=request.user,
                scan_key=scan_key
            ),
            id=report
        )
        scan_duration = scan_record.updated - scan_record.created

    except (ScanRecord.DoesNotExist, Scan.DoesNotExist):
        return HttpResponseNotFound()

    if(scan_record.scan.installed_applications):
        try:
            applications = Software.objects.filter(
                scan_record=scan_record
            )

            running_total = 0

            scan_data['install_timeline'] = applications.values(
                'install_date'
            ).annotate(
                Count('install_date')
            ).order_by(
                'install_date'
            ).exclude(install_date=None)

            for date in scan_data['install_timeline']:
                running_total += date['install_date__count']
                date['running_total'] = running_total

            scan_data['installed_applications'] = []
            scan_data['cves'] = 0
            scan_data['vulnerable_applications'] = 0
            scan_data['installed_applications_count'] = applications.count()

            for application in applications.order_by('name'):
                if application.cpe is not None:
                    cve_matches = CVEMatches.objects.filter(
                        cpe=application.cpe
                    )

                    if cve_matches.exists():
                        application.cve_match = True

                        scan_data['vulnerable_applications'] += 1
                        scan_data['cves'] += cve_matches.count()

                scan_data['installed_applications'].append(application)

        except (Software.DoesNotExist):
            scan_data['installed_applications'] = None

    if(scan_record.scan.browser_passwords):
        try:
            scan_data['browser_passwords'] = Credential.objects.filter(
                credential_scan=CredentialScan.objects.get(
                    scan_record=scan_record
                )
            ).order_by('-occurrence')
            scan_data['usernames'] = scan_data['browser_passwords'].all().values(
                "username"
            ).annotate(
                Count(
                    'username',
                    distinct=True
                )
            )
            scan_data['compromised'] = scan_data['browser_passwords'].filter(
                compromised=True
            ).count()
            scan_data['weak'] = scan_data['browser_passwords'].exclude(
                password_strength=Credential.SecurityRating.VERY_STRONG
            ).count()

        except (Credential.DoesNotExist, CredentialScan.DoesNotExist):
            scan_data['browser_passwords'] = None

    if(scan_record.scan.installed_patches):
        try:
            scan_data['installed_patches'] = UpdateInstalled.objects.filter(
                scan_record=scan_record
            ).order_by('-date')

            scan_data['pending_patches'] = UpdatePending.objects.filter(
                scan_record=scan_record
            )

        except (UpdateInstalled.DoesNotExist, UpdatePending.DoesNotExist):
            scan_data['installed_patches'] = None

    if(scan_record.scan.network_firewall_rules):
        try:
            scan_data['firewall_rules'] = FirewallRules.objects.filter(
                scan_record=scan_record
            ).order_by('name')

        except (FirewallRules.DoesNotExist):
            scan_data['firewall_rules'] = None

    if(scan_record.scan.installed_antivirus):
        try:
            scan_data['antivirus_status'] = DefenderStatus.objects.filter(
                scan_record=scan_record
            )[0]

            scan_data['antivirus_preferences'] = DefenderPreference.objects.filter(
                scan_record=scan_record
            )[0]

            scan_data['antivirus_exclusions'] = DefenderExclusion.objects.filter(
                preference=scan_data['antivirus_preferences']
            )

            scan_data['antivirus_detections'] = DefenderDetection.objects.filter(
                scan_record=scan_record
            ).order_by('-created')

        except (Credential.DoesNotExist, CredentialScan.DoesNotExist, IndexError):
            scan_data['antivirus_status'] = None


    if(scan_record.scan.system_users):
        try:
            scan_data['system_users'] = User.objects.filter(
                scan_record=scan_record
            )
            scan_data['enabled_defaults'] = scan_data['system_users'].filter(
                name__in=[
                    'Administrator',
                    'DefaultAccount',
                    'Guest',
                    'WDAGUtilityAccount'
                ],
                enabled=True
            ).count()
        except (User.DoesNotExist):
            scan_data['system_users'] = None

    return render(
        request,
        'scan/report/report.html',
        {
            'coords': GeoIP2().lat_lon(scan_record.public_ip),
            'maps_key': settings.MAPS_KEY,
            'scan_data': scan_data,
            'scan_duration': divmod(scan_duration.days * 86400 + scan_duration.seconds, 60),
            'scan_record': scan_record,
        }
    )
