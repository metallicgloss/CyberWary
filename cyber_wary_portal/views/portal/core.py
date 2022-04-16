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
from cyber_wary_portal.forms import AccountModificationForm, ScanFormStep2, AccountDeletionForm
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.script_generation import generate_script
from datetime import timedelta, datetime
from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.gis.geoip2 import GeoIP2
from django.db.models import Count
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse, HttpResponseNotFound
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.timezone import make_aware
from formtools.wizard.views import SessionWizardView
from rest_framework.authtoken.models import Token


# --------------------------------------------------------------------------- #
#                                                                             #
#                                 PORTAL VIEWS                                #
#                                                                             #
#                 Views associated with the portal interface.                 #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. General Views                                     #
#                            1.1 Dashboard                                    #
#                        2. Account Views                                     #
#                            2.1 Modify Account                               #
#                            2.2 Delete Account Acction                       #
#                        3. Scan Views                                        #
#                            3.1 Create Scan Group                            #
#                            3.2 Scan Script Generation Action                #
#                            3.3 Scan Activity Action                         #
#                            3.4 Scan Group History                           #
#                            3.5 Scan Group                                   #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                              1. General Views                               #
# --------------------------------------------------------------------------- #
#                             1.1 Dashboard View                              #
# --------------------------------------------------------------------------- #

@login_required
def index(request):
    # Retrieve all scan records associated with all scan groups created by the user.
    scan_records = ScanRecord.objects.filter(
        scan__in=Scan.objects.filter(
            user=request.user
        )
    )

    # Retrieve all API requests initiated by the user.
    requests = ApiRequest.objects.filter(
        user=request.user
    )

    # Retrieve all applications associated with the scan records.
    applications = Software.objects.filter(
        scan_record__in=scan_records
    ).order_by('-created')

    # Retrieve all credential metrics associated with scan records.
    credentials = recent_at_risk_creds = Credential.objects.filter(
        credential_scan__in=CredentialScan.objects.filter(
            scan_record__in=scan_records
        ),
    ).order_by('-updated')

    # Define date 7 days ago.
    date_last_week = datetime.now() - timedelta(days=7)

    #
    # Filters for Numerical Metrics
    #

    # Extend scan records requests filter to restrict data to only those in the last 7 days.
    recent_scan_records = scan_records.filter(
        created__gte=make_aware(date_last_week)
    )

    # Extend API requests filter to restrict data to only those in the last 7 days.
    recent_requests = requests.filter(
        created__gte=make_aware(date_last_week)
    )

    # Extend applications filter to restrict data to only those in the last 7 days.
    recent_applications = applications.filter(
        created__gte=make_aware(date_last_week)
    )

    #
    # Filters for Dashboard Lists
    #

    # Extend credentials filter to only compromised credentials in the last 7 days.
    recent_at_risk_creds = credentials.filter(
        compromised=True,
        created__gte=make_aware(date_last_week)
    ).all()[:16]  # Restrict to max of 16 records.

    # Sort applications by date.
    recent_apps = recent_applications.order_by(
        '-updated'
    ).all()[:16]  # Restrict to max of 16 records.

    # Get recent scan records.
    recent_devices = scan_records.order_by('-created')[:16]

    #
    # Map Data Generation
    #

    locations = []

    for ip in scan_records.values("public_ip").distinct():
        # For each unique IP address, add lat and long.
        locations.append(GeoIP2().lat_lon(ip['public_ip']))

    #
    # OS Chart Data
    #

    # Annotate scan record dataset to add count values for each unique OS.
    operating_systems = scan_records.values(
        'os_install__os__name'
    ).annotate(
        Count(
            'name'
        )
    )

    return render(
        request,
        'dashboard.html',
        {
            'maps_key': settings.MAPS_KEY,
            'locations': locations,
            'requests': requests.count(),
            'recent_requests': recent_requests.count(),
            'scan_records': scan_records.count(),
            'recent_scan_records': recent_scan_records.count(),
            'applications': applications.count(),
            'recent_applications': recent_applications.count(),
            'operating_systems': operating_systems,
            'recent_at_risk_creds': recent_at_risk_creds,
            'recent_apps': recent_apps,
            'recent_devices': recent_devices
        }
    )


# --------------------------------------------------------------------------- #
#                              2. Account Views                               #
# --------------------------------------------------------------------------- #
#                           2.1 Modify Account View                           #
# --------------------------------------------------------------------------- #

@login_required
def modify(request):
    errors = []
    profile_updated = False

    if request.method == 'POST':
        # Post request, submitting / saving of data.
        form = AccountModificationForm(request.POST)

        if form.is_valid():
            # Get existing user.
            user = CyberWaryUser.objects.get(
                pk=request.user.pk
            )

            # Add valid class to fields with valid data.
            user.first_name = form.data.get('first_name')
            user.last_name = form.data.get('last_name')

            try:
                # Check for existing user.
                existing_user = CyberWaryUser.objects.get(
                    email=form.data.get('email')
                )

                # If email isn't owned by current user, existing email.
                if(existing_user.pk != request.user.pk):
                    form.add_error(
                        'email',
                        "There is already an existing user with that email address, so it could not be updated."
                    )

            except CyberWaryUser.DoesNotExist:
                # User doesn't exist with that email - its completely free to be used.
                user.email = form.data.get('email')

            if form.data.get('password1') != "" and form.data.get('password1') == form.data.get('password2'):
                # If password not blank and match, set password and mark as valid.
                user.set_password(form.data.get('password1'))

            elif form.data.get('password1') != "":
                # Add errors stating fields didn't match.
                form.add_error(
                    'password2',
                    "The passwords entered did not match."
                )

            # Save user with modified details.
            user.save()

            return HttpResponseRedirect(
                "%s?update=true" % reverse('account_modify')
            )

    else:
        # Standard GET request, load AccountDetailsForm form and populate with user data.
        form = AccountModificationForm(
            instance=CyberWaryUser.objects.get(
                pk=request.user.pk
            )
        )

        if(request.GET.get('update') is not None):
            profile_updated = True

    # Render Page
    return render(
        request,
        'account/modify.html',
        {
            'form': form,
            'account_delete_form': AccountDeletionForm(),
            'errors': errors,
            'update': profile_updated
        }
    )


# --------------------------------------------------------------------------- #
#                          2.2 Delete Account Acction                         #
# --------------------------------------------------------------------------- #

@login_required
def delete(request):
    if request.method == 'POST':
        # Post request, submitting / saving of data.
        form = AccountDeletionForm(request.POST)

        if form.is_valid():
            # Get existing user.
            user = CyberWaryUser.objects.get(
                pk=request.user.pk
            )

            # Log user out before account deletion.
            logout(request)
            user.delete()

            # Redirect to dashboard (will return to login)
            return redirect(reverse('dashboard'))

    else:
        # Request not made via POST. Return to account modify.
        return redirect(reverse('account_modify'))


# --------------------------------------------------------------------------- #
#                                3. Scan Views                                #
# --------------------------------------------------------------------------- #
#                         3.1 Create Scan Group View                          #
# --------------------------------------------------------------------------- #

class ScanCreationWizard(LoginRequiredMixin, SessionWizardView):
    # Class to handle the two page form for the scan creation (details and components)
    instance = None
    template_name = "scan/create.html"

    def get_form_instance(self, step):
        # Define the instance of the object self to be a Scan
        if self.instance is None:
            self.instance = Scan()
        return self.instance

    def get_context_data(self, form, **kwargs):
        context = super(ScanCreationWizard, self).get_context_data(
            form=form,
            **kwargs
        )

        if self.steps.current == '1':
            # If page has progressed onto the second page, store the cleaned data in the object.
            step_1_data = self.get_cleaned_data_for_step('0')
            context.update(step_1_data)
        return context

    def done(self, form_list, **kwargs):
        # Form completed, define the new random key and the user before creating the object.
        self.instance.user = self.request.user
        self.instance.scan_key = get_random_string(length=32)
        self.instance.save()

        # Redirect to the scan view page.
        return redirect('scan', self.instance.scan_key)


# --------------------------------------------------------------------------- #
#                      3.2 Scan Script Generation Action                      #
# --------------------------------------------------------------------------- #

@login_required
def preview_script(request):
    # Call typically made by AJAX request to generate a script based on the current form settings.
    scan_form = ScanFormStep2(request.POST)

    if scan_form.is_valid():
        return HttpResponse(
            generate_script(
                'preview',
                scan_form.cleaned_data,
                Token.objects.get_or_create(  # If the user hasn't visited the API page before, create API token.
                    user=request.user
                )[0].key
            )
        )

    else:
        return HttpResponse(
            "Unable to generate script."
        )


# --------------------------------------------------------------------------- #
#                          3.3 Scan Activity Action                           #
# --------------------------------------------------------------------------- #

@login_required
def activity(request, scan_key):
    # Call to detect any new scan records that have been created - typically called by Ajax.

    try:
        # Attempt to get a valid scan object.
        scan = Scan.objects.get(
            user=request.user,
            scan_key=scan_key
        )

    except Scan.DoesNotExist:
        return HttpResponseNotFound()

    # Query all existing scan records associated with the scan group.
    scan_records = ScanRecord.objects.filter(
        scan=scan
    )

    devices = {}

    for record in scan_records:
        # Format output for each device that has an associated scan record.
        devices[record.device_id] = {
            'id': record.id,
            'name': record.name,
            'country': record.country,
            'os': record.os_install.os.name,
            'owner': record.os_install.owner
        }

    return JsonResponse(devices)


# --------------------------------------------------------------------------- #
#                         3.4 Scan Group History View                         #
# --------------------------------------------------------------------------- #

@login_required
def history(request):
    # List scan history / scan groups.
    user_scans = Scan.objects.filter(
        user=request.user
    ).order_by('-created')

    # Get the date 7 days ago.
    date_last_week = datetime.now() - timedelta(days=7)

    # Apply additional filter to only retrieve scans in the last week.
    user_scans_last_week = user_scans.filter(
        created__gte=make_aware(date_last_week)
    )

    # Capture a list of all user scans.
    records = ScanRecord.objects.filter(
        scan__in=user_scans
    )

    # Apply additional filter to only retrieve records in the last week.
    records_last_week = records.filter(
        created__gte=make_aware(date_last_week)
    )

    # Capture a list of all unique device names.
    devices = records.values(
        'device_id'
    ).distinct()

    # Apply additional filter to only retrieve devices scanned in the last week.
    devices_last_week = records_last_week.values(
        'device_id'
    ).distinct()

    # Capture a list of credentials, filtering only to unique values of the url and username that have been compromised.
    credentials = Credential.objects.filter(
        credential_scan__in=CredentialScan.objects.filter(
            scan_record__in=records
        ),
        compromised=True
    ).values(
        'url',
        'username'
    ).distinct()

    # Apply additional filter to only credentials scanned in the last week.
    credentials_last_week = credentials.filter(
        created__gte=make_aware(date_last_week)
    )

    return render(
        request,
        'scan/history.html',
        {
            'user_scans': user_scans,
            'user_scans_last_week': user_scans_last_week.count(),
            'records': records.count(),
            'records_last_week': records_last_week.count(),
            'devices': devices.count(),
            'devices_last_week': devices_last_week.count(),
            'credentials': credentials.count(),
            'credentials_last_week': credentials_last_week.count()
        }
    )


# --------------------------------------------------------------------------- #
#                             3.5 Scan Group View                             #
# --------------------------------------------------------------------------- #

@login_required
def scan(request, scan_key):
    try:
        # If scan exists, get data.
        scan = Scan.objects.get(
            user=request.user,
            scan_key=scan_key
        )
    except Scan.DoesNotExist:
        return HttpResponseNotFound()

    # Render the second step of the scan to get the data stored in it.
    scan_form = ScanFormStep2(scan)

    return render(
        request,
        'scan/scan.html',
        {
            'scan': scan,
            'script': generate_script(  # Generate the script for displaying.
                'live',
                scan_form.data.__dict__,
                Token.objects.get_or_create(
                    user=request.user
                )[0].key  # Get the user's API key.
            ),
            'records': ScanRecord.objects.filter(
                scan=scan
            ),
            'scan_key': scan_key
        }
    )
