
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
from cyber_wary_portal.models import CyberWaryUser, Scan
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.validators import MaxValueValidator, MinValueValidator

# --------------------------------------------------------------------------- #
#                                                                             #
#                                DJANGO FORMS                                 #
#                                                                             #
#   Forms used throughout the application for input validation and mapping.   #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Account Forms                                     #
#                            1.1 Account Creation                             #
#                            1.2 Account Modification                         #
#                            1.3 Account Deletion                             #
#                            1.4 Reset API Key                                #
#                        2. Scan Forms                                        #
#                            2.1 Scan Details                                 #
#                            2.2 Scan Components                              #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                              1. Account Forms                               #
# --------------------------------------------------------------------------- #
#                            1.1 Account Creation                             #
# --------------------------------------------------------------------------- #

class AccountDetailsForm(UserCreationForm):
    username = forms.CharField(
        label='Username',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Create a username...'
            }
        ),
        min_length=4,
        max_length=16
    )

    first_name = forms.CharField(
        label='Forename',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter your forename...'
            }
        ),
        min_length=2,
        max_length=64
    )

    last_name = forms.CharField(
        label='Surname',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter your surname...'
            }
        )
    )

    email = forms.EmailField(
        label='Email Address',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter your email address...'
            }
        )
    )

    # Password
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Create a password...'
            }
        )
    )

    # Confirm Password
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Re-enter your password...'
            }
        )
    )

    class Meta:
        # Associate with the CyberWaryUser Model
        model = CyberWaryUser
        # Map Fields
        fields = (
            'username',
            'first_name',
            'last_name',
            'email'
        )

    def __init__(self, *args, **kwargs):
        super(AccountDetailsForm, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            # For each field.

            # Mark as required
            field.required = True

            # Disable autofocus.
            field.widget.attrs.pop("autofocus", None)


# --------------------------------------------------------------------------- #
#                           1.2 Account Modification                          #
# --------------------------------------------------------------------------- #

class AccountModificationForm(UserCreationForm):
    first_name = forms.CharField(
        label='Forename',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter your forename...'
            }
        ),
        required=True,
        min_length=2,
        max_length=64
    )

    last_name = forms.CharField(
        label='Surname',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter your surname...'
            }
        ),
        required=True
    )

    email = forms.EmailField(
        label='Email Address',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter your email address...'
            }
        ),
        required=True
    )

    # Password
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Create a password...'
            }
        ),
        required=False
    )

    # Confirm Password
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Re-enter your password...'
            }
        ),
        required=False
    )

    class Meta:
        # Associate with the CyberWaryUser Model
        model = CyberWaryUser
        # Map Fields
        fields = (
            'first_name',
            'last_name',
            'email'
        )

    def __init__(self, *args, **kwargs):
        super(AccountModificationForm, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            # For each field

            # Add the animation class.
            field.widget.attrs['class'] = 'form-input-animation'
            field.widget.attrs.pop("autofocus", None)


# --------------------------------------------------------------------------- #
#                             1.3 Account Deletion                            #
# --------------------------------------------------------------------------- #

class AccountDeletionForm(forms.Form):
    confirmation = forms.BooleanField(
        label='Confirm Account Deletion?',
        help_text='When your account is deleted, it is irrevocably removed from the system.',
        required=True,
        initial=False
    )


# --------------------------------------------------------------------------- #
#                              1.4 Reset API Key                              #
# --------------------------------------------------------------------------- #

class ApiKeyForm(forms.Form):
    confirmation = forms.BooleanField(
        label='Confirm Key Regeneration?',
        help_text='When you re-generate your key, any requests made with the existing key will be rejected.',
        required=True,
        initial=False
    )


# --------------------------------------------------------------------------- #
#                                2. Scan Forms                                #
# --------------------------------------------------------------------------- #
#                              2.1 Scan Details                               #
# --------------------------------------------------------------------------- #

class ScanFormStep1(forms.ModelForm):
    # Part 1 of 2
    TYPES = (
        ('B', 'Blue Team'),
        ('R', 'Red Team')
    )

    type = forms.ChoiceField(
        label='Type',
        choices=TYPES,
        required=True
    )

    title = forms.CharField(
        label='Title',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Enter a name for the scan...'
            }
        ),
        required=True,
        min_length=2,
        max_length=32
    )

    comment = forms.CharField(
        label='Notes/Comments',
        widget=forms.Textarea(
            attrs={
                'rows': '5'
            }
        ),
        required=False,
        max_length=2048
    )

    max_devices = forms.IntegerField(
        label='Maximum Associated Devices',
        required=True,
        initial=1,
        min_value=1,
        max_value=10,
        validators=[
            MaxValueValidator(10),
            MinValueValidator(1)
        ]
    )

    expiry = forms.DateTimeField(
        label='Expiry Date/Time'
    )

    class Meta:
        # Associate with the Scan model.
        model = Scan
        fields = (
            'type',
            'title',
            'comment',
            'max_devices',
            'expiry'
        )

    def __init__(self, *args, **kwargs):
        super(ScanFormStep1, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            # For each field

            if (field.label == 'Notes/Comments'):
                # If notes field, add additional class.
                field.widget.attrs['class'] = 'form-input-animation form-text-area'

            else:
                # Add animation class to each field.
                field.widget.attrs['class'] = 'form-input-animation'
            field.widget.attrs.pop("autofocus", None)


# --------------------------------------------------------------------------- #
#                             2.2 Scan Components                             #
# --------------------------------------------------------------------------- #

class ScanFormStep2(forms.ModelForm):
    # Part 2 of 2
    system_users = forms.BooleanField(
        label='User Accounts',
        help_text='Analyses the user accounts setup on the device.',
        required=False,
        initial=False
    )

    browser_passwords = forms.BooleanField(
        label='Browser Passwords',
        help_text='Analyses the browser passwords accessible/stored on the device.',
        required=False,
        initial=False
    )

    network_firewall_rules = forms.BooleanField(
        label='Firewall Rules',
        help_text='Analyses the firewall rules configured on the device.',
        required=False,
        initial=False
    )

    installed_applications = forms.BooleanField(
        label='Installed Applications',
        help_text='Analyses the third-party applications installed on the device.',
        required=False,
        initial=False
    )

    installed_patches = forms.BooleanField(
        label='Operating System Patches',
        help_text='Analyses the operating system patches installed on the device.',
        required=False,
        initial=False
    )

    installed_antivirus = forms.BooleanField(
        label='Windows Defender Settings',
        help_text='Analyses the Windows Defender status and settings.',
        required=False,
        initial=False
    )

    class Meta:
        # Associate with the Scan model.
        model = Scan
        fields = (
            'system_users',
            'browser_passwords',
            'network_firewall_rules',
            'installed_applications',
            'installed_patches',
            'installed_antivirus'
        )

    def __init__(self, *args, **kwargs):
        super(ScanFormStep2, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            # Add animation class to each field.
            field.widget.attrs['class'] = 'form-input-animation'
            field.widget.attrs.pop("autofocus", None)
