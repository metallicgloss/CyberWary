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

from warnings import catch_warnings
from .forms import AccountModificationForm, ApiKeyForm
from .models import SystemUser, ApiRequest, Scan
from datetime import datetime
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.timezone import make_aware
from formtools.wizard.views import SessionWizardView
from pytz import timezone
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
import json


@login_required
def index(request):
    return render(request, 'dashboard.html')


class ScanCreationWizard(SessionWizardView):
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
        return redirect('history')


@login_required
def report(request):
    return render(request, 'report.html')


@login_required
def history(request):
    user_scans = Scan.objects.filter(user=request.user).order_by('-created')
    return render(
        request,
        'scan/history.html',
        {
            'user_scans': user_scans
        }
    )


# --------------------------------------------------------------------------- #
#                           6. Account Modification                           #
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
            'errors': errors,
            'update': profile_updated
        }
    )


# --------------------------------------------------------------------------- #
#                           6. Account Modification                           #
# --------------------------------------------------------------------------- #

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


@login_required
def api_payload(request):
    if request.method == 'POST':
        try:
            return JsonResponse(
                json.loads(
                    ApiRequest.objects.get(
                        user=request.user,
                        pk=request.POST['payloadID'],
                        type=request.POST['type'],
                    ).payload
                )
            )
        except ApiRequest.DoesNotExist:
            return JsonResponse("No Payload Found")
    else:
        return redirect("portal")


@api_view(['POST', ])
def start_scan(request):
    request_log = ApiRequest(
        user=request.user,
        type='start_scan',
        payload=json.dumps(
            json.loads(
                request.POST['system_information']
            )
        ),
        method=ApiRequest.RequestMethod.POST
    )
    request_log.save()

    return JsonResponse(request.data)
