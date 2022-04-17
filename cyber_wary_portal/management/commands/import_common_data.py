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

# Module/Library Import
from cyber_wary_portal.models import CPE, CWE, CVE, CVEReference
from cyber_wary_portal.models.scan_software import CVEMatches, CVEReference
from datetime import datetime
from django.core.management.base import BaseCommand
from django.db.utils import IntegrityError, OperationalError
from zipfile import ZipFile
import argparse
import gzip
import io
import json
import urllib.request
import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------- #
#                                                                             #
#                           AUTOMATED DATA IMPORTER                           #
#                                                                             #
#         Django administration command to import/update common data.         #
#                                                                             #
# --------------------------------------------------------------------------- #


class Command(BaseCommand):

    # ----------------------------------------------------------------------- #
    #                            Command Arguments                            #
    # ----------------------------------------------------------------------- #

    def add_arguments(self, parser):
        # Reference - https://ref.cyberwary.com/4z7lt
        # Define Common Platform Enumeration Flag
        parser.add_argument(
            '--cpe',
            action=argparse.BooleanOptionalAction,
            help='Update/Import Common Platform Enumeration.',
        )

        # Define Common Weakness Enumeration Flag
        parser.add_argument(
            '--cwe',
            action=argparse.BooleanOptionalAction,
            help='Update/Import Common Weakness Enumeration.',
        )

        # Define Common Vulnerabilities and Exposures Flag
        parser.add_argument(
            '--cve',
            action=argparse.BooleanOptionalAction,
            help='Update/Import Common Vulnerabilities and Exposures.',
        )

        # Define CVE Target Year
        parser.add_argument(
            '--cve-year',
            action='append',
            type=int,
            help="Define specific year for CVE import/update."
        )

    # ----------------------------------------------------------------------- #
    #                            Command Execution                            #
    # ----------------------------------------------------------------------- #

    def handle(self, *args, **options):
        if(options['cpe']):
            # If CPE flag set, import CPE data.

            # Get set of cpe-item's in the GZipped XML file from NIST.
            # Reference - https://ref.cyberwary.com/17rnd
            # Reference - https://ref.cyberwary.com/ps5a7
            cpe_database = ET.parse(
                gzip.GzipFile(
                    fileobj=io.BytesIO(
                        urllib.request.urlopen(
                            "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
                        ).read()
                    )
                )
            ).findall("{http://cpe.mitre.org/dictionary/2.0}cpe-item")

            for cpe in cpe_database:
                # For each CPE item in the downloaded dataset.

                try:
                    # Create CPE object.
                    CPE.objects.create(
                        identifier=cpe.find(
                            '{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item'
                        ).get('name'),  # Get name from tag.
                        title=cpe.find(
                            '{http://cpe.mitre.org/dictionary/2.0}title'
                        ).text  # Get text content from inside tag.
                    )

                except (IntegrityError, OperationalError):
                    # Already imported / conflict on CPE identifier.

                    # Try-except used instead of get_or_create due to significant performance difference.
                    continue

        if(options['cwe']):
            # If CWE flag set, import CWE data.

            # Get set of weaknesses in the XML file contained within the ZIP file from MITRE.
            # Reference - https://ref.cyberwary.com/ifz5h
            # Reference - https://ref.cyberwary.com/hkkla
            cwe_database = ET.parse(
                ZipFile(
                    io.BytesIO(
                        urllib.request.urlopen(
                            "https://cwe.mitre.org/data/xml/views/677.xml.zip"
                        ).read()
                    )
                ).open(
                    "677.xml"
                )
            ).findall(
                "{http://cwe.mitre.org/cwe-6}Weaknesses"
            )[0].findall(
                "{http://cwe.mitre.org/cwe-6}Weakness"
            )

            for cwe in cwe_database:
                # For weakness in dataset.

                try:
                    CWE.objects.create(
                        identifier=cwe.get('ID'),
                        name=cwe.get('Name'),
                        description=" ".join(
                            cwe.find('{http://cwe.mitre.org/cwe-6}Description').text.split())
                    )

                except IntegrityError:
                    # Already imported / conflict on CWE ID.

                    # Try-except used instead of get_or_create due to significant performance difference.
                    continue

        if(options['cve']):
            # If CVE flag set, import CVE data.

            if(options['cve_year'] is not None):
                # Command has year specified - only import/update data from that year.
                self.import_cve(options['cve_year'][0])

            else:
                for year in range(2002, datetime.now().year + 1):
                    # For year ranging from 2002 to the current year, import data from that year.

                    self.import_cve(year)

    # ----------------------------------------------------------------------- #
    #                           Import CVE Function                           #
    # ----------------------------------------------------------------------- #

    def import_cve(self, year):
        # Import CVE data from the year request.

        # Get set of CVEs in the GZipped json file from NIST.
        cve_database = json.load(
            gzip.GzipFile(
                fileobj=io.BytesIO(
                    urllib.request.urlopen(
                        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" +
                        str(year) + ".json.gz"
                    ).read()
                )
            )
        )

        for cve in cve_database['CVE_Items']:
            # For each CVE included in the dataset.

            if('baseMetricV3' in cve['impact']):
                # If CVSS Version 3
                cvss = cve['impact']['baseMetricV3']['cvssV3']['vectorString']

            elif('baseMetricV2' in cve['impact']):
                # If CVSS Version 2
                cvss = cve['impact']['baseMetricV2']['cvssV2']['vectorString']

            else:
                # Missing any CVSS Vector
                cvss = None

            try:
                # Create CVE record
                created_cve = CVE.objects.create(
                    identifier=cve['cve']['CVE_data_meta']['ID'],
                    assigner=cve['cve']['CVE_data_meta'].get('ASSIGNER'),
                    description=cve['cve']['description']['description_data'][0]['value'],
                    cvss=cvss,
                    published=cve['publishedDate']
                )

            except IntegrityError:
                # Already imported / conflict on CVE ID.
                continue

            for reference in cve['cve']['references']['reference_data']:
                # For each reference/url associated with the reference

                # Create reference.
                CVEReference.objects.create(
                    cve=created_cve,
                    url=reference['url'],
                    name=reference['name'],
                    source=reference['refsource'],
                    tags=', '.join(reference['tags'])
                )

            if(len(cve['configurations']['nodes']) > 0):
                # If the CVE is associated with at least one CPE.

                for match in cve['configurations']['nodes'][0]['cpe_match']:
                    # For each CPE that the CVE is associated with.

                    try:
                        # Create CVEMatch to the CPE.
                        CVEMatches.objects.create(
                            cve=created_cve,
                            cpe=CPE.objects.get(
                                identifier=match['cpe23Uri']
                            )
                        )

                    except CPE.DoesNotExist:
                        # CPE listed in the record does not currently exist in the imported dataset.
                        pass
