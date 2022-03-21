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

from cyber_wary_portal.forms import AccountModificationForm, ApiKeyForm, ScanFormStep2, AccountDeletionForm
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.script_generation import generate_script
from cyber_wary_portal.utils.data_import import check_credential
from datetime import datetime
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth import logout
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse, HttpResponseNotFound
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.timezone import make_aware
from formtools.wizard.views import SessionWizardView
from pytz import timezone
from rest_framework.authtoken.models import Token
from django.db.models import Count
import json


@login_required
def index(request):
    return render(request, 'dashboard.html')


class ScanCreationWizard(LoginRequiredMixin, SessionWizardView):
    instance = None
    template_name = "scan/create.html"

    def get_form_instance(self, step):
        if self.instance is None:
            self.instance = Scan()
        return self.instance

    def get_context_data(self, form, **kwargs):
        context = super(ScanCreationWizard, self).get_context_data(
            form=form, **kwargs)

        if self.steps.current == '1':
            step_1_data = self.get_cleaned_data_for_step('0')
            context.update(step_1_data)
        return context

    def done(self, form_list, **kwargs):
        self.instance.user = self.request.user
        self.instance.scan_key = get_random_string(length=32)
        self.instance.save()
        return redirect('scan', self.instance.scan_key)


@login_required
def preview_script(request):
    scan_form = ScanFormStep2(request.POST)

    if scan_form.is_valid():
        return HttpResponse(
            generate_script(
                'preview',
                scan_form.cleaned_data,
                Token.objects.get_or_create(
                    user=request.user
                )[0].key
            )
        )

    else:
        return HttpResponse(
            "Unable to generate script."
        )


@login_required
def activity(request, scan_key):
    try:
        scan = Scan.objects.get(
            user=request.user,
            scan_key=scan_key
        )
    except Scan.DoesNotExist:
        return HttpResponseNotFound()

    scan_records = ScanRecord.objects.filter(
        scan=scan
    )

    devices = {}

    for record in scan_records:
        devices[record.device_id] = {
            'id': record.id,
            'name': record.name,
            'country': record.country,
            'os': record.os_install.operating_system.name,
            'owner': record.os_install.owner
        }

    return JsonResponse(devices)


@login_required
def scan(request, scan_key):
    try:
        scan = Scan.objects.get(
            user=request.user,
            scan_key=scan_key
        )
    except Scan.DoesNotExist:
        return HttpResponseNotFound()

    scan_form = ScanFormStep2(scan)

    return render(
        request,
        'scan/scan.html',
        {
            'scan': scan,
            'script': generate_script(
                'live',
                scan_form.data.__dict__,
                Token.objects.get_or_create(
                    user=request.user
                )[0].key
            ),
            'records': ScanRecord.objects.filter(
                scan=scan
            ),
            'scan_key': scan_key
        }
    )


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

    if(scan_record.scan.system_users):
        try:
            scan_data['system_users'] = UserRecord.objects.filter(
                scan_record=scan_record
            )
            scan_data['enabled_defaults'] = scan_data['system_users'].filter(
                name__in = ['Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount'],
                enabled = True
            ).count()
        except (UserRecord.DoesNotExist):
            scan_data['system_users'] = None

    if(scan_record.scan.browser_passwords):
        try:
            scan_data['browser_passwords'] = CredentialRecord.objects.filter(
                credential_scan=CredentialScan.objects.get(
                    scan_record=scan_record
                )
            )
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
                password_strength=CredentialRecord.SecurityRating.VERY_STRONG
            ).count()

        except (CredentialRecord.DoesNotExist, CredentialScan.DoesNotExist):
            scan_data['browser_passwords'] = None

            

    return render(
        request,
        'scan/report.html',
        {
            'coords': GeoIP2().lat_lon(scan_record.public_ip),
            'maps_key': settings.MAPS_KEY,
            'scan_data': scan_data,
            'scan_duration': divmod(scan_duration.days * 86400 + scan_duration.seconds, 60),
            'scan_record': scan_record,
        }
    )


@login_required
def history(request):
    return render(
        request,
        'scan/history.html',
        {
            'user_scans': Scan.objects.filter(
                user=request.user
            ).order_by('-created')
        }
    )


@login_required
def modify(request):
    errors = []
    profile_updated = False

    if request.method == 'POST':
        # Post request, submitting / saving of data.
        form = AccountModificationForm(request.POST)

        if form.is_valid():
            # Get existing user.
            user = SystemUser.objects.get(
                pk=request.user.pk
            )

            # Add valid class to fields with valid data.
            user.first_name = form.data.get('first_name')
            user.last_name = form.data.get('last_name')

            try:
                # Check for existing user.
                existing_user = SystemUser.objects.get(
                    email=form.data.get('email')
                )

                # If email isn't owned by current user, existing email.
                if(existing_user.pk != request.user.pk):
                    form.add_error(
                        'email',
                        "There is already an existing user with that email address, so it could not be updated."
                    )

            except SystemUser.DoesNotExist:
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
            instance=SystemUser.objects.get(
                pk=request.user.pk
            )
        )

        if(request.GET.get('update') is not None):
            profile_updated = True

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


@login_required
def delete(request):
    if request.method == 'POST':
        # Post request, submitting / saving of data.
        form = AccountDeletionForm(request.POST)

        if form.is_valid():
            # Get existing user.
            user = SystemUser.objects.get(
                pk=request.user.pk
            )

            logout(request)

            user.delete()

            return redirect(reverse('account_delete'))

    else:
        return redirect(reverse('account_modify'))


@login_required
def api(request):
    key_updated = False

    if request.method == 'POST':
        form = ApiKeyForm(request.POST)

        if form.is_valid():

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

                return HttpResponseRedirect(
                    "%s?update=true" % reverse('api')
                )

    else:
        form = ApiKeyForm()
        api_key = Token.objects.get_or_create(
            user=request.user
        )

        if(request.GET.get('update') is not None):
            key_updated = True

    api_log = ApiRequest.objects.filter(user=request.user).order_by('-created')

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
