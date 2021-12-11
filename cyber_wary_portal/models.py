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

from django.contrib.auth.models import AbstractUser
from django.db import models
import hashlib

# --------------------------------------------------------------------------- #
#                        1.1 Default Fields Class                             #
# --------------------------------------------------------------------------- #

class DefaultFields(models.Model):
    # Default parameters to track creation date, last updated date and status.
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)

    # Define abstract class as true - all child classes to inherit fields.
    class Meta:
        abstract = True


# --------------------------------------------------------------------------- #
#                        1.2 System User Class                                #
# --------------------------------------------------------------------------- #

class SystemUser(AbstractUser):
    def get_gravatar_image(self):
        return 'http://www.gravatar.com/avatar/{}'.format(hashlib.md5(self.email.encode()).hexdigest())
