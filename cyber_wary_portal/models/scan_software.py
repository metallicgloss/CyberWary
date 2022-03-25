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

# Module/Library Import
from cyber_wary_portal.models.core import *
from django.db import models


# --------------------------------------------------------------------------- #
#                                                                             #
#                               SOFTWARE MODELS                               #
#                                                                             #
#          Models associated the software check component of a scan.          #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                   1. Public Definitions                                     #
#                       1.1 Common Platform Enumeration                       #
#                       1.2 Common Weakness Enumeration                       #
#                       1.3 Common Vulnerabilities and Exposures              #
#                       1.4 CVE References                                    #
#                       1.5 CVE Linked Weaknesses                             #
#                       1.6 CVE Linked Platforms                              #
#                   2. Software                                               #
#                       2.1 Publisher                                         #
#                       2.2 Installed Software                                #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                            1. Public Definitions                            #
# --------------------------------------------------------------------------- #
#                    1.1 Common Platform Enumeration Class                    #
# --------------------------------------------------------------------------- #

class CPE(DefaultFields):
    # Model to store the identifier for a CPE.

    identifier = models.CharField(
        max_length=256,
        null=True,
        help_text="The identifier for the CPE."
    )

    title = models.CharField(
        max_length=192,
        null=True,
        help_text="The title/name for the software referenced by the CPE."
    )


# --------------------------------------------------------------------------- #
#                    1.2 Common Weakness Enumeration Class                    #
# --------------------------------------------------------------------------- #

class CWE(DefaultFields):
    # Model to store the identifier for a CWE.

    identifier = models.IntegerField(
        default=0,
        null=False,
        help_text="The identifier for the CWE."
    )

    name = models.CharField(
        max_length=192,
        null=True,
        help_text="The name given to the CWE."
    )

    description = models.CharField(
        max_length=512,
        null=True,
        help_text="The description given to the CWE."
    )


# --------------------------------------------------------------------------- #
#                1.3 Common Vulnerabilities and Exposures Class               #
# --------------------------------------------------------------------------- #

class CVE(DefaultFields):
    # Model to store the identifier information surrounding a CVE.

    identifier = models.IntegerField(
        default=0,
        null=False,
        help_text="The identifier for the CVE."
    )

    assigner = models.CharField(
        max_length=64,
        null=True,
        help_text="The assigner for the CVE."
    )

    description = models.CharField(
        max_length=512,
        null=True,
        help_text="The description of the CVE."
    )

    cvss = models.CharField(
        max_length=64,
        null=True,
        help_text="The CVSS v3 vector string of the CVE."
    )

    published = models.DateTimeField(
        null=True,
        help_text="The date/time that the CVE was published."
    )


# --------------------------------------------------------------------------- #
#                             1.4 CVE References                              #
# --------------------------------------------------------------------------- #

class CVEReference(DefaultFields):
    # Model to store the links and references associated with a CVE.

    cve = models.ForeignKey(
        CVE,
        on_delete=models.CASCADE,
        help_text="The CVE that the reference is associated with."
    )

    url = models.CharField(
        max_length=128,
        null=True,
        help_text="The URL for the reference."
    )

    name = models.CharField(
        max_length=128,
        null=True,
        help_text="The name for the reference."
    )

    source = models.CharField(
        max_length=128,
        null=True,
        help_text="The source for the reference."
    )

    tags = models.CharField(
        max_length=128,
        null=True,
        help_text="The tags associated with the reference."
    )


# --------------------------------------------------------------------------- #
#                       1.5 CVE Linked Weaknesses Class                       #
# --------------------------------------------------------------------------- #

class CVEWeaknesses(DefaultFields):
    # Model to store the weaknesses related to a specific CVE.

    cve = models.ForeignKey(
        CVE,
        on_delete=models.CASCADE,
        help_text="The CVE that the weakness is associated with."
    )

    cwe = models.ForeignKey(
        CWE,
        on_delete=models.CASCADE,
        help_text="The weakness that the CVE is associated with."
    )


# --------------------------------------------------------------------------- #
#                       1.6 CVE Linked Platforms Class                        #
# --------------------------------------------------------------------------- #

class CVEMatches(DefaultFields):
    # Model to store the platforms/software associated with a specific CVE.

    cve = models.ForeignKey(
        CVE,
        on_delete=models.CASCADE,
        help_text="The CVE that the CPE is linked to."
    )

    cpe = models.ForeignKey(
        CPE,
        on_delete=models.CASCADE,
        help_text="The CPE that features the CVE."
    )


# --------------------------------------------------------------------------- #
#                                 2. Software                                 #
# --------------------------------------------------------------------------- #
#                             2.1 Publisher Class                             #
# --------------------------------------------------------------------------- #

class Publisher(DefaultFields):
    # Model to store names of publishers.

    name = models.CharField(
        max_length=128,
        null=True,
        help_text="The name of the publisher."
    )

    logo = models.CharField(
        max_length=256,
        null=True,
        help_text="The logo of the publisher."
    )

    website = models.CharField(
        max_length=256,
        null=True,
        help_text="The associated website of the publisher."
    )

# --------------------------------------------------------------------------- #
#                         2.2 Installed Software Class                        #
# --------------------------------------------------------------------------- #


class Software(DefaultFields):
    # Model to store details surrounding software installed on a device being scanned.

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the software/installation is associated with."
    )

    name = models.CharField(
        max_length=128,
        null=True,
        help_text="The name given to the software (Name)."
    )

    version = models.CharField(
        max_length=32,
        null=True,
        help_text="The version of the software installed (DisplayVersion)."
    )

    version_major = models.CharField(
        max_length=8,
        null=True,
        help_text="The major version of the software installed (VersionMajor)."
    )

    version_minor = models.CharField(
        max_length=16,
        null=True,
        help_text="The minor version of the software installed (VersionMinor)."
    )

    publisher = models.ForeignKey(
        Publisher,
        on_delete=models.CASCADE,
        help_text="The publisher that the software is associated with (Publisher)."
    )

    install_path = models.CharField(
        max_length=256,
        null=True,
        help_text="The path for the software installation (InstallSource/InstallLocation)."
    )

    install_date = models.DateField(
        null=True,
        help_text="The date that the software was originally installed (InstallDate)."
    )