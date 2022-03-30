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
    return '# ' + command_action + '\r\nInvoke-WebRequest -Uri \'' + url + '/portal/api/v1/' + request_url + '\' -Method POST -Headers @{ Authorization = $apiKey } -Body ( @{ device_id = $deviceID; scan_key = $scanKey; ' + data_identifier + ' = $(' + command_payload + ') } | ConvertTo-Json ) -ContentType "application/json" | Out-Null\r\n\r\n'


def generate_script(generation_type, payload, api_key):
    if(generation_type == "preview"):
        scan_key = "GENERATED AFTER SCAN FULLY INITIALISED"
    else:
        scan_key = payload['scan_key']

    script_contents = '$apiKey = "Token ' + api_key + '"\r\n'
    script_contents += '$scanKey = "' + scan_key + '"\r\n'
    script_contents += '$deviceID = Get-ItemProperty HKLM:SOFTWARE\Microsoft\SQMClient | Select -ExpandProperty MachineID\r\n\r\n'

    if(payload['network_firewall_rules'] or payload['installed_patches']):
        script_contents += '# Script requires administrator permissions; verify correct access.\r\n'
        script_contents += '$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())\r\n'
        script_contents += 'if ( $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false ) { Add-Type -AssemblyName System.Windows.Forms;[System.Windows.Forms.MessageBox]::Show("Please re-launch powershell as Administrator.", "CyberWary", "Ok", "Error");stop-process -Id $PID }\r\n\r\n'

    script_contents += get_data(
        'Capture Basic System Information',
        'start_scan',
        'system_information',
        'Get-ComputerInfo'
    )

    if(payload['network_firewall_rules']):
        script_contents += get_data(
            'Capture List of Firewall Rules',
            'firewall/rules',
            'rules',
            '(Get-NetFirewallRule | ConvertTo-Json) -replace("$([char]0x00AE)", "")'
        )
        script_contents += get_data(
            'Capture List of Applications Associated With Rules',
            'firewall/applications',
            'applications',
            'Get-NetFirewallApplicationFilter'
        )
        script_contents += get_data(
            'Capture List of IP Addresses With Rules',
            'firewall/ips',
            'ips',
            'Get-NetFirewallAddressFilter'
        )
        script_contents += get_data(
            'Capture List of Ports Associated With Rules',
            'firewall/ports',
            'ports',
            'Get-NetFirewallPortFilter'
        )

    if(payload['installed_applications']):
        script_contents += '# Generate List of Installed Applications on the Device \r\n'
        script_contents += '$software = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\r\n'
        script_contents += '$software += Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\r\n'
        script_contents += get_data(
            'Capture List of Installed Applications Without Registered Symbol',
            'applications_installed',
            'applications',
            '($software | ConvertTo-Json) -replace("$([char]0x00AE)", "")'
        )

    if(payload['installed_patches']):
        script_contents += get_data(
            'Capture List of Pending Updates',
            'patches/pending',
            'patches',
            '$UpdateSession = New-Object -ComObject Microsoft.Update.Session; @($UpdateSession.CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | ConvertTo-Json)'
        )
        script_contents += '# Temporarily enable PowerShell modules that are signed\r\n'
        script_contents += 'Set-ExecutionPolicy AllSigned -force\r\n\r\n'
        script_contents += get_data(
            'Capture List of Installed Updates',
            'patches/installed',
            'patches',
            'Install-Module -Name PSWindowsUpdate -Force; Import-Module PSWindowsUpdate; Get-WUHistory -MaxDate (Get-Date).AddDays(-180) -Last 500'
        )
        script_contents += '# Set the execution of scripts to restricted\r\n'
        script_contents += 'Set-ExecutionPolicy Restricted -force\r\n\r\n'

    if(payload['installed_antivirus']):
        script_contents += get_data(
            'Capture the System Antivirus Status',
            'antivirus/status',
            'status',
            'Get-MpComputerStatus'
        )
        script_contents += get_data(
            'Capture the System Antivirus Settings',
            'antivirus/preferences',
            'preferences',
            'Get-MpPreference'
        )
        script_contents += get_data(
            'Capture the Recent Threat Detection History',
            'antivirus/detections',
            'detections',
            'Get-MpThreatDetection'
        )

    if(payload['system_users']):
        script_contents += get_data(
            'Capture List of System Users',
            'system_users',
            'users',
            'Get-LocalUser'
        )

    if(payload['browser_passwords']):
        script_contents += '# Capture List of Credentials Stored in Browsers\r\n'
        script_contents += '$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider\r\n'
        script_contents += '$utf8 = New-Object -TypeName System.Text.UTF8Encoding\r\n\r\n'
        script_contents += '# Temporarily download WebBrowserPassView - Developed & Copyright by Nir Sofer.\r\n'
        script_contents += '# Convert plain-text passwords discovered to SHA1 hashes.\r\n'
        script_contents += 'wget ' + url + \
            '/static/downloads/WebBrowserPassView.exe -OutFile WebBrowserPassView.exe; .\\WebBrowserPassView.exe /scomma credentials.csv; Start-Sleep 1; (Import-Csv ".\credentials.csv" -Delimiter ",") | ForEach-Object { if ($_.Password -ne "") { $_.Password = ([System.BitConverter]::ToString($sha1.ComputeHash($utf8.GetBytes($_.Password))).Replace("-", "")) } $_ } | Export-Csv ".\credentials.csv" -Delimiter "," -NoType; $credentials = (Import-Csv ".\credentials.csv" -Delimiter ",")\r\n\r\n'
        script_contents += get_data(
            'Capture list of hashed passwords; hashes will not be saved.',
            'browser_passwords',
            'credentials',
            '$credentials'
        )
        script_contents += 'Remove-Item .\WebBrowserPassView.exe; Remove-Item .\credentials.csv # Cleanup\r\n\r\n'

    script_contents += get_data(
        'Mark Scan Completion',
        'end_scan',
        'completed',
        '"completed"'
    )
    script_contents += "stop-process -Id $PID"

    return script_contents
