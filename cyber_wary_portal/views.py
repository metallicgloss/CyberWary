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

from .forms import AccountModificationForm, ScanForm, ApiKeyForm
from .models import SystemUser, ApiRequest, Scan
from datetime import datetime
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.timezone import make_aware
from pytz import timezone
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
import json


@login_required
def index(request):
    return render(request, 'dashboard.html')


@login_required
def create(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            scan = form.save(commit=False)
            scan.user = request.user
            scan.scan_key = get_random_string(length=32)
            scan.save()
            return redirect('scans')

    else:
        form = ScanForm()

    return render(
        request,
        'create.html',
        {
            'form': form
        }
    )


@login_required
def report(request):
    return render(request, 'report.html')


@login_required
def scans(request):
    user_scans = Scan.objects.filter(user=request.user)
    return render(
        request,
        'scans.html',
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
                "%s?update=true" % reverse('modify')
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
    
    api_log = ApiRequest.objects.filter(user=request.user)

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


@api_view(['POST',])
def start_scan(request):
    
    request_log = ApiRequest(
        user=request.user,
        type='start_scan',
        payload=json.loads(request.POST['system_information'].replace("'", '"')),
        method=ApiRequest.RequestMethod.POST
    )
    request_log.save()

    return JsonResponse(request.data)