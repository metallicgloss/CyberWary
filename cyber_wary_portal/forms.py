
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

from .models import SystemUser
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.forms.widgets import PasswordInput, TextInput, EmailInput, HiddenInput


class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label="Username",
        widget=TextInput(
            attrs={
                'class': 'validate',
                'placeholder': 'Enter your username...'
            }
        )
    )
    password = forms.CharField(
        label="Password",
        widget=PasswordInput(
            attrs={
                'placeholder': 'Enter your password...'
            }
        )
    )

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__( * args, ** kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input-animation'
            field.required = True


class AccountDetailsForm(UserCreationForm):
    username = forms.CharField(
        label='Username',
        widget=TextInput(
            attrs={
                'placeholder': 'Create a username...'
            }
        ),
        min_length=4, 
        max_length=16
    )
    first_name = forms.CharField(
        label='Forename',
        widget=TextInput(
            attrs={
                'placeholder': 'Enter your forename...'
            }
        ),
        min_length=2, 
        max_length=64
    )
    last_name = forms.CharField(
        label='Surname',
        widget=TextInput(
            attrs={
                'placeholder': 'Enter your surname...'
            }
        )
    )
    email = forms.EmailField(
        label='Email Address',
        widget=TextInput(
            attrs={
                'placeholder': 'Enter your email address...'
            }
        )
    )
    password1 = forms.CharField(
        label='Password',
        widget=PasswordInput(
            attrs={
                'placeholder': 'Create a password...'
            }
        )
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=PasswordInput(
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
        super(AccountDetailsForm, self).__init__( * args, ** kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input-animation'
            field.required = True
            field.widget.attrs.pop("autofocus", None)

            

class AccountModificationForm(UserCreationForm):
    first_name = forms.CharField(
        label='Forename',
        widget=TextInput(
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
        widget=TextInput(
            attrs={
                'placeholder': 'Enter your surname...'
            }
        ),
        required=True
    )
    email = forms.EmailField(
        label='Email Address',
        widget=TextInput(
            attrs={
                'placeholder': 'Enter your email address...'
            }
        ),
        required=True
    )
    password1 = forms.CharField(
        label='Password',
        widget=PasswordInput(
            attrs={
                'placeholder': 'Create a password...'
            }
        ),
        required=False
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=PasswordInput(
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
        super(AccountModificationForm, self).__init__( * args, ** kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input-animation'
            field.widget.attrs.pop("autofocus", None)