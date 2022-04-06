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
from django.conf import settings

# --------------------------------------------------------------------------- #
#                                                                             #
#                              SCRIPT GENERATION                              #
#                                                                             #
#  Generate the PowerShell script provided to users based on scan components. #
#                                                                             #
# --------------------------------------------------------------------------- #

if(settings.DEBUG):
    # If in debug mode, target localhost connection.
    url = "http://localhost:8000"

else:
    # Else, target web host
    url = "https://www.cyberwary.com"


# --------------------------------------------------------------------------- #
#                        Generate API Request Command                         #
# --------------------------------------------------------------------------- #

def get_data(command_action, request_url, data_identifier, command_payload):
    # Format parameters into comment and Invoke Web Request.
    return '# ' + command_action + '\r\nInvoke-WebRequest -Uri \'' + url + '/portal/api/v1/' + request_url + '\' -Method POST -Headers @{ Authorization = $apiKey } -Body ( @{ device_id = $deviceID; scan_key = $scanKey; ' + data_identifier + ' = $(' + command_payload + ') } | ConvertTo-Json ) -ContentType "application/json" | Out-Null\r\n\r\n'


# --------------------------------------------------------------------------- #
#                               Generate Script                               #
# --------------------------------------------------------------------------- #

def generate_script(generation_type, payload, api_key):

    # ----------------------------------------------------------------------- #
    #                         Setup Script Parameters                         #
    # ----------------------------------------------------------------------- #
    if(generation_type == "preview"):
        # Generation is preview - currently being configured.
        scan_key = "GENERATED AFTER SCAN FULLY INITIALISED"

    else:
        # Created scan group - display scan key.
        scan_key = payload['scan_key']

    # User API Token
    script_contents = '$apiKey = "Token ' + api_key + '"\r\n'
    # Scan Group Key
    script_contents += '$scanKey = "' + scan_key + '"\r\n'

    # Get device ID from system.
    script_contents += '$deviceID = Get-ItemProperty HKLM:SOFTWARE\Microsoft\SQMClient | Select -ExpandProperty MachineID\r\n\r\n'

    # ----------------------------------------------------------------------- #
    #                            Admin Requirement                            #
    # ----------------------------------------------------------------------- #

    # Default the requirement for admin to be False
    admin = False

    if(payload['network_firewall_rules'] or payload['installed_patches'] or payload['installed_antivirus']):
        # If firewalls or patches included in the scan group - require admin permissions.

        # Set admin status to true.
        admin = True

        # Comment informing user
        script_contents += '# Script requires administrator permissions; verify correct access.\r\n'
        # Get the current admin status for user
        script_contents += '$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())\r\n'
        # If not user, launch popup box.
        script_contents += 'if ( $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false ) { Add-Type -AssemblyName System.Windows.Forms;[System.Windows.Forms.MessageBox]::Show("Please re-launch powershell as Administrator.", "CyberWary", "Ok", "Error");stop-process -Id $PID }\r\n\r\n'

    # ----------------------------------------------------------------------- #
    #              Setup Scan Record / Capture System Information             #
    # ----------------------------------------------------------------------- #

    script_contents += get_data(
        'Capture Basic System Information',
        'start_scan',
        'system_information',
        'Get-ComputerInfo'
    )

    # ----------------------------------------------------------------------- #
    #                         Installed Applications                          #
    # ----------------------------------------------------------------------- #

    if(payload['installed_applications']):
        # Comment to inform the user of the additional variables.
        script_contents += '# Generate List of Installed Applications on the Device \r\n'

        # Get list of software installed on the Local Machine (All Users)
        script_contents += '$software = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\r\n'

        # Get list of software installed for the Current User
        script_contents += '$software += Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\r\n'

        script_contents += get_data(
            'Capture List of Installed Applications Without Registered Symbol',
            'applications_installed',
            'applications',
            '($software | ConvertTo-Json) -replace("$([char]0x00AE)", "")'
        )

    # ----------------------------------------------------------------------- #
    #                            Browser Passwords                            #
    # ----------------------------------------------------------------------- #

    if(payload['browser_passwords']):
        # Comment to inform user of what the script is doing.
        script_contents += '# Setup formatting and hashing objects to ensure safe transmission.\r\n'

        # Define SHA-1 Hash Object
        script_contents += '$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider\r\n'

        # Define UTF-8 Encoding Object
        script_contents += '$utf8 = New-Object -TypeName System.Text.UTF8Encoding\r\n\r\n'

        # Provide comment on application being temporarily downloaded.
        script_contents += '# Temporarily download WebBrowserPassView - Developed & Copyright by Nir Sofer.\r\n'

        # Comment to inform user what the loop is doing.
        script_contents += '# Convert plain-text passwords discovered to SHA1 hashes.\r\n'

        if(admin):
            # If executed as admin, change directory out of system32 (default) to the root directory.
            script_contents += 'cd /;'

        # Downloaded developer copy of WebBrowserPassView
        script_contents += 'wget ' + url + '/static/downloads/WebBrowserPassView.exe -OutFile WebBrowserPassView.exe'

        # Generate CSV containing all credentials on the system.
        script_contents += '.\\WebBrowserPassView.exe /scomma credentials.csv;'

        # Wait for 1 second to allow for disk writing for CSV to complete
        script_contents += 'Start-Sleep 1;'
        
        # Loop through each line in the CSV file; if password isn't blank, replace and override with SHA1 hash.
        script_contents += '(Import-Csv ".\credentials.csv" -Delimiter ",") | ForEach-Object { if ($_.Password -ne "") { $_.Password = ([System.BitConverter]::ToString($sha1.ComputeHash($utf8.GetBytes($_.Password))).Replace("-", "")) } $_ } | Export-Csv ".\credentials.csv" -Delimiter "," -NoType; $credentials = (Import-Csv ".\credentials.csv" -Delimiter ",")\r\n\r\n'

        script_contents += get_data(
            'Capture list of hashed passwords; hashes will not be saved.',
            'browser_passwords',
            'credentials',
            '$credentials'
        )

        # Remove downloaded file and generated CSV file.
        script_contents += 'Remove-Item .\WebBrowserPassView.exe; Remove-Item .\credentials.csv # Cleanup\r\n\r\n'

    # ----------------------------------------------------------------------- #
    #                             Windows Update                              #
    # ----------------------------------------------------------------------- #

    if(payload['installed_patches']):
        script_contents += get_data(
            'Capture List of Pending Updates',
            'patches/pending',
            'patches',
            '$UpdateSession = New-Object -ComObject Microsoft.Update.Session; @($UpdateSession.CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | ConvertTo-Json)'
        )

        # Comment to inform user what the script is doing.
        script_contents += '# Temporarily enable PowerShell modules\r\n'
        
        # Enable execution of remote scripts to allow for PSWindowsUpdate to execute correctly.
        script_contents += 'Set-ExecutionPolicy Unrestricted -force\r\n\r\n'

        script_contents += get_data(
            'Capture List of Installed Updates',
            'patches/installed',
            'patches',
            'Install-Module -Name PSWindowsUpdate -Force; Get-WUHistory -MaxDate (Get-Date).AddDays(-180) -Last 500'
        )
        
        # Comment to inform user what the script is doing.
        script_contents += '# Set the execution of scripts to restricted\r\n'
        
        # Disable the execution of scripts - should remain restricted by default.
        script_contents += 'Set-ExecutionPolicy Restricted -force\r\n\r\n'

    # ----------------------------------------------------------------------- #
    #                            Firewall Component                           #
    # ----------------------------------------------------------------------- #

    if(payload['network_firewall_rules']):
        # If firewall rules component enabled in the scan.

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

    # ----------------------------------------------------------------------- #
    #                            Windows Defender                             #
    # ----------------------------------------------------------------------- #

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

    # ----------------------------------------------------------------------- #
    #                              System Users                               #
    # ----------------------------------------------------------------------- #

    if(payload['system_users']):
        script_contents += get_data(
            'Capture List of System Users',
            'system_users',
            'users',
            'Get-LocalUser'
        )

    # ----------------------------------------------------------------------- #
    #                         Mark Scan as Completed                          #
    # ----------------------------------------------------------------------- #

    script_contents += get_data(
        'Mark Scan Completion',
        'end_scan',
        'completed',
        '"completed"'
    )

    # Close PowerShell Window
    script_contents += "stop-process -Id $PID\r\n"

    return script_contents
