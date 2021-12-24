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

from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from .forms import AccountDetailsForm, AccountModificationForm
from .models import SystemUser


@login_required
def index(request):
    return render(request, 'dashboard.html')


@login_required
def create(request):
    return render(request, 'create.html')


@login_required
def report(request):
    return render(request, 'report.html')


@login_required
def scans(request):
    return render(request, 'scans.html')


# --------------------------------------------------------------------------- #
#                           5. Account Registration                           #
# --------------------------------------------------------------------------- #


def register(request):
    if request.method == 'POST':
        form = AccountDetailsForm(request.POST)

        if form.is_valid():
            # Form contains all required values - save as new user.
            form.save()

            username = form.data.get('username')
            raw_password = form.data.get('password1')

            # Authenticate user session with provided details.
            user = authenticate(username=username, password=raw_password)
            login(request, user)

            return redirect('portal')

    else:
        form = AccountDetailsForm()

    return render(
        request,
        'registration/register.html',
        {
            'form': form
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
            user = SystemUser.objects.get(pk=request.user.pk)

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
            instance=SystemUser.objects.get(pk=request.user.pk)
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
