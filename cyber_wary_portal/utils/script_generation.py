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

from django.conf import settings

if(settings.DEBUG):
    url = "http://localhost:8000"
else:
    url = "https://www.cyberwary.com"


def get_data(command_action, request_url, data_identifier, command_payload):
    return '# ' + command_action + '\r\nStart-Job { Invoke-WebRequest -Uri \'' + url + '/portal/api/v1/' + request_url + '\' -Method POST -Headers @{ Authorization = $using:apiKey} -Body @{ device_id = $using:deviceID; scan_key = $using:scanKey; ' + data_identifier + ' = $(' + command_payload + ') }} | Out-Null\r\n\r\n'


def generate_script(generation_type, payload, api_key):
    if(generation_type == "preview"):
        scan_key = "GENERATED AFTER SCAN FULLY INITIALISED"
    else:
        scan_key = payload['scan_key']

    script_contents = '$apiKey = "Token ' + api_key + '"\r\n'
    script_contents += '$scanKey = "' + scan_key + '"\r\n'
    script_contents += '$deviceID = Get-ItemProperty HKLM:SOFTWARE\Microsoft\SQMClient | Select -ExpandProperty MachineID\r\n\r\n'
    script_contents += get_data(
        'Capture Basic System Information',
        'start_scan',
        'system_information',
        'Get-ComputerInfo | ConvertTo-Json'
    )

    if(payload['network_adapters']):
        script_contents += get_data(
            'Capture List of Network Adapters',
            'network_adapters',
            'system_information',
            'Get-NetAdapter -Name * -IncludeHidden | ConvertTo-Json'
        )

    if(payload['network_firewall_rules']):
        script_contents += get_data(
            'Capture List of Firewall Rules',
            'firewall_rules',
            'rules',
            'Get-NetFirewallRule | ConvertTo-Json'
        )

    if(payload['startup_applications']):
        script_contents += get_data(
            'Capture List of Applications Configured on Startup',
            'applications/startup',
            'applications',
            'Get-CimInstance Win32_StartupCommand | ConvertTo-Json'
        )

    if(payload['installed_applications']):
        script_contents += get_data(
            'Capture List of Installed Applications',
            'applications/installed',
            'applications',
            'Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | ConvertTo-Json'
            # Alt Command - TBC - Get-WmiObject -Class Win32_Product | ConvertTo-Json
        )

    if(payload['installed_patches']):
        script_contents += get_data(
            'Capture List of Pending Updates',
            'patches/pending',
            'patches',
            '$UpdateSession = New-Object -ComObject Microsoft.Update.Session; @($UpdateSession.CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates) | ConvertTo-Json'
        )
        script_contents += get_data(
            'Capture List of Installed Updates',
            'patches/installed',
            'patches',
            'Install-Module -Name PSWindowsUpdate -Force; Get-WUHistory -MaxDate (Get-Date).AddDays(-180) -Last 500 | ConvertTo-Json'
        )

    if(payload['installed_antivirus']):
        script_contents += get_data(
            'Capture the System Antivirus Status',
            'antivirus/status',
            'status',
            'Get-MpComputerStatus | ConvertTo-Json'
        )
        script_contents += get_data(
            'Capture the System Antivirus Settings',
            'antivirus/settings',
            'settings',
            'Get-MpPreference | ConvertTo-Json'
        )
        script_contents += get_data(
            'Capture the Recent Threat Detection History',
            'antivirus/detections',
            'detections',
            'Get-MpThreatDetection | ConvertTo-Json'
        )

    if(payload['system_users']):
        script_contents += get_data(
            'Capture List of System Users',
            'system_users',
            'users',
            'Get-LocalUser | ConvertTo-Json'
        )

    if(payload['system_services']):
        script_contents += get_data(
            'Capture List of System Services',
            'services/system',
            'services',
            'Get-Service | ConvertTo-Json'
        )
        script_contents += get_data(
            'Capture List of System Services Registered to Microsoft',
            'services/microsoft',
            'services',
            'Get-WmiObject Win32_Service -Property * | Select DisplayName, PathName | %{ Try { if([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$($_.PathName.ToString().Split("-")[0].Split("/")[0])").LegalCopyright -like "*Microsoft*") {"$($_.DisplayName)"}} catch {}} | ConvertTo-Json'
        )
        script_contents += get_data(
            'Capture List of Non-Default System Services',
            'services/non_default',
            'services',
            'Get-wmiobject win32_service | where { $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch "OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client" -and $_.DisplayName -notmatch "NetSetupSvc" -and $_.Caption -notmatch "Windows" -and $_.PathName -notmatch "Windows" } | ConvertTo-Json'
        )

    if(payload['browser_passwords']):
        script_contents += '# Capture List of Credentials Stored in Browsers\r\n'
        script_contents += '$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider\r\n'
        script_contents += '$utf8 = New-Object -TypeName System.Text.UTF8Encoding\r\n'
        script_contents += '# Temporarily download WebBrowserPassView - Developed & Copyright by Nir Sofer.\r\n'
        script_contents += 'wget ' + url + \
            '/static/downloads/WebBrowserPassView.exe -OutFile WebBrowserPassView.exe\r\n'
        script_contents += '# Capture credentials from Chrome, Firefox, Edge, IE, Opera and Safari.\r\n'
        script_contents += '.\\WebBrowserPassView.exe /scomma credentials.csv\r\n'
        script_contents += get_data(
            'Capture List of Hashed Passwords. Hashes will not be stored, and will only be used in checks for breaches.',
            'browser_passwords',
            'hashes',
            '(Import-Csv \'.\credentials.csv\' -Delimiter \',\') | ForEach-Object { if ($_.Password -ne \'\') { $_.Password = ([System.BitConverter]::ToString($using:sha1.ComputeHash($using:utf8.GetBytes($_.Password))).Replace(\'-\', \'\')) } $_ } | Export-Csv \'.\credentials.csv\' -Delimiter \',\' -NoType | ConvertTo-Json'
        )
        script_contents += 'Remove-Item .\WebBrowserPassView.exe; Remove-Item .\credentials.csv # Cleanup\r\n'

    return script_contents
