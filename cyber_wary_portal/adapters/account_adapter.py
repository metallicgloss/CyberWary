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


# # Module/Library Import
from django.conf import settings
from allauth.account.adapter import DefaultAccountAdapter


class UserRegistrationControlAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        # Reference - https://ref.cyberwary.com/ubhy6
        return settings.ACCOUNT_REGISTRATION_OPEN
