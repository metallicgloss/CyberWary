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

from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from .forms import RegistrationForm

def index(request):
    print(request.user.get_gravatar_image())
    return render(request, 'dashboard.html')


# --------------------------------------------------------------------------- #
#                           5. Account Registration                           #
# --------------------------------------------------------------------------- #


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        if form.is_valid():
            # Form contains all required values - save as new user.
            form.save()

            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')

            # Authenticate user session with provided details.
            user = authenticate(username=username, password=raw_password)
            login(request, user)

            return redirect('portal')

    else:
        form = RegistrationForm()

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
    pass
