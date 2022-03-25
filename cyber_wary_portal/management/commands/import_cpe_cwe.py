from django.core.management.base import BaseCommand
from cyber_wary_portal.models import CPE, CWE
import urllib.request
import io
import gzip
import xml.etree.ElementTree as ET
from zipfile import ZipFile

class Command(BaseCommand):
    def handle(self, *args, **options):
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
            CPE.objects.create(
                identifier = cpe.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').get('name'),
                title = cpe.find('{http://cpe.mitre.org/dictionary/2.0}title').text
            )


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
            CWE.objects.create(
                identifier = cwe.get('ID'),
                name = cwe.get('Name'),
                description = " ".join(cwe.find('{http://cwe.mitre.org/cwe-6}Description').text.split())
            )