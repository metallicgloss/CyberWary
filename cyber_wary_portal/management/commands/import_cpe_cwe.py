import argparse
from django.core.management.base import BaseCommand
from cyber_wary_portal.models import CPE, CWE, CVE, CVEReference
import urllib.request
import io
import gzip
import xml.etree.ElementTree as ET
from zipfile import ZipFile
from datetime import datetime
import json

from cyber_wary_portal.models.scan_software import CVEMatches, CVEReference

class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            '--cpe',
            action=argparse.BooleanOptionalAction,
            help='Update/Import Common Platform Enumeration.',
        )
        parser.add_argument(
            '--cwe',
            action=argparse.BooleanOptionalAction,
            help='Update/Import Common Weakness Enumeration.',
        )
        parser.add_argument(
            '--cve',
            action=argparse.BooleanOptionalAction,
            help='Update/Import Common Vulnerabilities and Exposures.',
        )
        parser.add_argument(
            '--cve-year',
            action='append',
            type=int,
            help="Define specific year for CVE import/update."
        )

    def handle(self, *args, **options):
        if(options['cpe']):
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
                CPE.objects.get_or_create(
                    identifier = cpe.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').get('name'),
                    title = cpe.find('{http://cpe.mitre.org/dictionary/2.0}title').text
                )

    
        if(options['cwe']):
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
            ).findall("{http://cwe.mitre.org/cwe-6}Weaknesses")[0].findall("{http://cwe.mitre.org/cwe-6}Weakness")

            for cwe in cwe_database:
                CWE.objects.get_or_create(
                    identifier = cwe.get('ID'),
                    name = cwe.get('Name'),
                    description = " ".join(cwe.find('{http://cwe.mitre.org/cwe-6}Description').text.split())
                )

        
        if(options['cve']):
            if(options['cve_year'] is not None):
                self.import_cve(options['cve_year'][0])
            else:
                for year in range(2002, datetime.now().year + 1):
                    self.import_cve(year)

    def import_cve(self, year):
        cve_database = json.load(
            gzip.GzipFile(
                fileobj=io.BytesIO(
                    urllib.request.urlopen(
                        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + str(year) + ".json.gz"
                    ).read()
                )
            )
        )

        for cve in cve_database['CVE_Items']:
            if('baseMetricV3' in cve['impact']):
                base = "baseMetricV3"
                type = "cvssV3"
            else:
                base = "baseMetricV2"
                type = "cvssV2"

            created_cve = CVE.objects.get_or_create(
                identifier = cve['cve']['CVE_data_meta']['ID'],
                assigner = cve['cve']['CVE_data_meta'].get('ASSIGNER'),
                description = cve['cve']['description']['description_data'][0]['value'],
                cvss = cve['impact'][base][type]['vectorString'],
                published = cve['publishedDate']
            )[0]

            for reference in cve['cve']['references']['reference_data']:
                CVEReference.objects.get_or_create(
                    cve = created_cve,
                    url = reference['url'],
                    name = reference['name'],
                    source = reference['refsource'],
                    tags = ', '.join(reference['tags'])
                )

            for match in cve['configurations']['nodes'][0]['cpe_match']:
                try:
                    CVEMatches.objects.get_or_create(
                        cve = created_cve,
                        cpe = CPE.objects.get(
                            identifier=match['cpe23Uri']
                        )
                    )
                except CPE.DoesNotExist:
                    pass