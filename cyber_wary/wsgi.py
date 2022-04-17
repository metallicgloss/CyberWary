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
from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.core.wsgi import get_wsgi_application
import os, sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../cyber_wary")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../cyber_wary_portal")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../cyber_wary_site")))

os.environ.setdefault(
    'DJANGO_SETTINGS_MODULE',
    'cyber_wary.settings'
)

application = StaticFilesHandler(
    get_wsgi_application()
)
