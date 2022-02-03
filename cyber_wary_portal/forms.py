
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

from .models import SystemUser, Scan
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.validators import MaxValueValidator, MinValueValidator


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
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Create a password...'
            }
        )
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Re-enter your password...'
            }
        )
    )

    class Meta:
        model = SystemUser
        fields = (
            'username',
            'first_name',
            'last_name',
            'email'
        )

    def __init__(self, *args, **kwargs):
        super(AccountDetailsForm, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            field.required = True
            field.widget.attrs.pop("autofocus", None)


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
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Create a password...'
            }
        ),
        required=False
    )
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
        model = SystemUser
        fields = (
            'first_name',
            'last_name',
            'email'
        )

    def __init__(self, *args, **kwargs):
        super(AccountModificationForm, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input-animation'
            field.widget.attrs.pop("autofocus", None)



class ScanForm(forms.ModelForm):
    TYPES = (
        ('B', 'Blue Team'),
        ('R', 'Red Team')
    )

    type = forms.ChoiceField(
        label='Scan Type',
        choices=TYPES,
        required=True
    )

    title = forms.CharField(
        label='Scan Title',
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
        label='Scan Comments',
        widget=forms.Textarea(
            attrs={
                'rows': '5'
            }
        ),
        required=False,
        max_length=2048
    )

    max_devices = forms.IntegerField(
        label='Maxmimum Associated Devices',
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
        label='Expiry Date of Scan'
    )


    class Meta:
        model = Scan
        fields = (
            'type',
            'title',
            'comment',
            'max_devices',
            'expiry',
            'system_users',
            'network_adapters',
            'startup_applications',
            'installed_applications',
            'outdated_applications',
            'firewall_rules',
            'system_passwords',
            'browser_passwords',
            'antivirus_product'
        )

    def __init__(self, *args, **kwargs):
        super(ScanForm, self).__init__(* args, ** kwargs)
        for field in self.fields.values():
            if (field.label == 'Scan Comments'):
                field.widget.attrs['class'] = 'form-input-animation form-text-area'
            else:
                field.widget.attrs['class'] = 'form-input-animation'
            field.widget.attrs.pop("autofocus", None)



class ApiKeyForm(forms.Form):
    confirmation = forms.BooleanField(
        label='Confirm Key Regeneration?',
        help_text='When you re-generate your key, any requests made with the existing key will be rejected.',
        required=True,
        initial=False
    )
