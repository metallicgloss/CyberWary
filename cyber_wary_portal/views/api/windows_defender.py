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
from cyber_wary_portal.models import *
from cyber_wary_portal.utils.data_import import *
from django.http.response import HttpResponse
from rest_framework.decorators import api_view


# --------------------------------------------------------------------------- #
#                                                                             #
#                          WINDOWS DEFENDER API VIEWS                         #
#                                                                             #
#            Views associated with the Windows Defender API calls.            #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Firewall Actions                                  #
#                            1.1 Firewall Rules                               #
#                            1.2 Firewall Applications                        #
#                            1.3 Firewall IP Addresses                        #
#                            1.4 Firewall Ports                               #
#                        2. Antivirus Actions                                 #
#                            2.1 Antivirus Status                             #
#                            2.2 Antivirus Settings                           #
#                            2.3 Antivirus Detections                         #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                             1. Firewall Actions                             #
# --------------------------------------------------------------------------- #
#                              1.1 Firewall Rules                             #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def firewall_rules(request):
    # Store the current firewall rules currently configured in Windows Defender Firewall

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'firewall/rules',
        'rules'
    )

    if(check_existing(scan, scan_record, FirewallRules)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Define empty list for new objects to be appended to for mass creation.
    rules = []

    for rule in data:
        # For each firewall rule defined.
        try:
            # Define an object for each firewall and append to list for mass creation.
            rules.append(
                FirewallRules(
                    scan_record=scan_record,
                    rule_id=rule['InstanceID'],
                    name=rule['DisplayName'],
                    description=rule['Description'],
                    group=rule['Group'],
                    enabled=rule['Enabled'],
                    lsm=rule['LSM'],
                    direction=rule['Direction'],
                    action=rule['Action']
                )
            )

        except KeyError:
            # Missing / Malformed data that differs to the default Windows output. Skip record.
            pass

    # Bulk create defined objects.
    FirewallRules.objects.bulk_create(rules)

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                          1.2 Firewall Applications                          #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def firewall_applications(request):
    # Update existing records to include any associated applications defined.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'firewall/applications',
        'applications'
    )

    # Check for any existing imports associated with the same scan record.
    existing_import = FirewallRules.objects.filter(
        scan_record=scan_record,
    ).exists()

    if(False in [scan, scan_record, existing_import]):
        # If scan group or scan record cannot be found, or there are no existing firewall rules
        return bad_request(api_request)

    for application in data:
        # For each application included in the payload.
        try:
            # Get the associated Firewall Rule.
            firewall_rule = FirewallRules.objects.get(
                scan_record=scan_record,
                rule_id=application['InstanceID']
            )

            # Update the firewall rule to include a path/program target.
            firewall_rule.file_path = application['Program']
            firewall_rule.save()

        except (FirewallRules.DoesNotExist, KeyError):
            # Missing / Malformed data that differs to the default Windows output; skip record.
            pass

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                          1.3 Firewall IP Addresses                          #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def firewall_ips(request):
    # Update existing records to include any associated IP addresses defined.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'firewall/ips',
        'ips'
    )

    # Check for any existing imports associated with the same scan record.
    existing_import = FirewallRules.objects.filter(
        scan_record=scan_record,
    ).exists()

    if(False in [scan, scan_record, existing_import]):
        # If scan group or scan record cannot be found, or there are no existing firewall rules
        return bad_request(api_request)

    for ip_address in data:
        # For each IP address defined in the payload.
        try:
            # Get the associated Firewall Rule.
            firewall_rule = FirewallRules.objects.get(
                scan_record=scan_record,
                rule_id=ip_address['InstanceID']
            )

            # Update the firewall rule to include any associated IP address configurations.
            firewall_rule.local_address = ip_address['LocalAddress']
            firewall_rule.local_ip = ip_address['LocalIP']
            firewall_rule.remote_address = ip_address['RemoteAddress']
            firewall_rule.remote_ip = ip_address['RemoteIP']
            firewall_rule.save()

        except (FirewallRules.DoesNotExist, KeyError):
            # Missing / Malformed data that differs to the default Windows output; skip record.
            pass

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                              1.4 Firewall Ports                             #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def firewall_ports(request):
    # Update existing records to include any associated ports defined.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'firewall/ports',
        'ports'
    )

    # Check for any existing imports associated with the same scan record.
    existing_import = FirewallRules.objects.filter(
        scan_record=scan_record,
    ).exists()

    if(False in [scan, scan_record, existing_import]):
        # If scan group or scan record cannot be found, or there are no existing firewall rules
        return bad_request(api_request)

    for port in data:
        # For each port defined in the payload.
        try:
            # Get the associated Firewall Rule.
            firewall_rule = FirewallRules.objects.get(
                scan_record=scan_record,
                rule_id=port['InstanceID']
            )

            # Update the firewall rule to include any associated IP address configurations.
            firewall_rule.local_port = port['LocalPort']
            firewall_rule.remote_port = port['RemotePort']

            if(port['Protocol'] == "TCP"):
                # Default UDP - update to TCP if protocol matches.
                firewall_rule.protocol = FirewallRules.Protocol.TCP

            firewall_rule.save()

        except (FirewallRules.DoesNotExist, KeyError):
            # Missing / Malformed data that differs to the default Windows output; skip record.
            pass

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                             2. Antivirus Actions                            #
# --------------------------------------------------------------------------- #
#                             2.1 Antivirus Status                            #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def antivirus_status(request):
    # Store the current status of Windows Defender returned during the scan.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'antivirus/status',
        'status'
    )

    if(check_existing(scan, scan_record, DefenderStatus)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    try:
        # Create an object to store the current status of the Windows Defender on the device.
        DefenderStatus.objects.create(
            scan_record=scan_record,
            behavior_monitoring=data['BehaviorMonitorEnabled'],
            tamper_protection=data['IsTamperProtected'],
            realtime_protection=data['RealTimeProtectionEnabled'],
            reboot_required=data['RebootRequired'],
            access_protection=data['OnAccessProtectionEnabled'],
            download_protection=data['IoavProtectionEnabled'],
            virtual_machine=data['IsVirtualMachine'],
            full_scan_required=data['FullScanRequired'],
            full_scan_overdue=data['FullScanOverdue'],
            full_scan_last=convert_unix_to_dt(data['FullScanEndTime']),
            quick_scan_overdue=data['QuickScanOverdue'],
            quick_scan_last=convert_unix_to_dt(data['QuickScanEndTime']),
            as_enabled=data['AntispywareEnabled'],
            as_signature_update=convert_unix_to_dt(
                data['AntispywareSignatureLastUpdated']),
            as_signature_version=data['AntispywareSignatureVersion'],
            av_enabled=data['AntivirusEnabled'],
            av_signature_update=convert_unix_to_dt(
                data['AntivirusSignatureLastUpdated']),
            av_signature_version=data['AntivirusSignatureVersion'],
            nri_enabled=data['NISEnabled'],
            nri_signature_update=convert_unix_to_dt(data['NISSignatureLastUpdated']),
            nri_signature_version=data['NISSignatureVersion']
        )

    except KeyError:
        # Missing / Malformed data that differs to the default Windows output. Fail request; return error.
        return bad_request(api_request)

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                            2.2 Antivirus Settings                           #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def antivirus_preferences(request):
    # Store the current settings and preferences configured for Windows Defender.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'antivirus/preferences',
        'preferences'
    )

    if(check_existing(scan, scan_record, DefenderPreference)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    try:
        # Store an object containing the list of the settings configured on the device.
        preferences = DefenderPreference.objects.create(
            scan_record=scan_record,
            check_for_signatures_before_running_scan=data['CheckForSignaturesBeforeRunningScan'],
            disable_archive_scanning=data['DisableArchiveScanning'],
            disable_auto_exclusions=data['DisableAutoExclusions'],
            disable_behavior_monitoring=data['DisableBehaviorMonitoring'],
            disable_block_at_first_seen=data['DisableBlockAtFirstSeen'],
            disable_cpu_throttle_on_idle_scans=data['DisableCpuThrottleOnIdleScans'],
            disable_datagram_processing=data['DisableDatagramProcessing'],
            disable_dns_over_tcp_parsing=data['DisableDnsOverTcpParsing'],
            disable_dns_parsing=data['DisableDnsParsing'],
            disable_email_scanning=data['DisableEmailScanning'],
            disable_ftp_parsing=data['DisableFtpParsing'],
            disable_gradual_release=data['DisableGradualRelease'],
            disable_http_parsing=data['DisableHttpParsing'],
            disable_inbound_connection_filtering=data['DisableInboundConnectionFiltering'],
            disable_ioav_protection=data['DisableIOAVProtection'],
            disable_privacy_mode=data['DisablePrivacyMode'],
            disable_rdp_parsing=data['DisableRdpParsing'],
            disable_realtime_monitoring=data['DisableRealtimeMonitoring'],
            disable_removable_drive_scanning=data['DisableRemovableDriveScanning'],
            disable_restore_point=data['DisableRestorePoint'],
            disable_scanning_mapped_network_drives_for_full_scan=data[
                'DisableScanningMappedNetworkDrivesForFullScan'],
            disable_scanning_network_files=data['DisableScanningNetworkFiles'],
            disable_script_scanning=data['DisableScriptScanning'],
            disable_ssh_parsing=data['DisableSshParsing'],
            disable_tls_parsing=data['DisableTlsParsing'],
            controlled_folder_access=data['EnableControlledFolderAccess'],
            dns_sinkhole=data['EnableDnsSinkhole'],
            file_hash_computation=data['EnableFileHashComputation'],
            full_scan_on_battery_power=data['EnableFullScanOnBatteryPower'],
            randomize_schedule_task_times=data['RandomizeScheduleTaskTimes'],
            avg_load=data['ScanAvgCPULoadFactor'],
            only_if_idle=data['ScanOnlyIfIdleEnabled'],
            ui_lockdown=data['UILockdown']
        )

    except KeyError:
        # Missing / Malformed data that differs to the default Windows output. Fail request; return error.
        return bad_request(api_request)

    # For each type of exclusion, process the applicable exclusions currently configured.
    import_exclusions(
        data['ExclusionIpAddress'],
        DefenderExclusion.ExclusionType.IP_ADDRESS,
        DefenderExclusion.ExclusionMethod.SCAN,
        preferences
    )
    import_exclusions(
        data['ExclusionExtension'],
        DefenderExclusion.ExclusionType.EXTENSION,
        DefenderExclusion.ExclusionMethod.SCAN,
        preferences
    )
    import_exclusions(
        data['ExclusionPath'],
        DefenderExclusion.ExclusionType.PATH,
        DefenderExclusion.ExclusionMethod.SCAN,
        preferences
    )
    import_exclusions(
        data['ExclusionProcess'],
        DefenderExclusion.ExclusionType.PROCESS,
        DefenderExclusion.ExclusionMethod.SCAN,
        preferences
    )
    import_exclusions(
        data['ControlledFolderAccessAllowedApplications'],
        DefenderExclusion.ExclusionType.PATH,
        DefenderExclusion.ExclusionMethod.CONTROLLED_ACCESS,
        preferences
    )

    return HttpResponse('Success')


# --------------------------------------------------------------------------- #
#                           2.3 Antivirus Detections                          #
# --------------------------------------------------------------------------- #

@api_view(['POST', ])  # API Call - Accept POST method only.
def antivirus_detections(request):
    # Store past malware detections that has been identified by Windows Defender.

    # Initialise API request
    api_request, device, scan, scan_record, data = setup_request(
        request,
        'antivirus/detections',
        'detections'
    )

    if(check_existing(scan, scan_record, DefenderDetection)):
        # If scan or scan_record aren't valid, or an existing import exists.
        return bad_request(api_request)

    # Define empty list for new objects to be appended to for mass creation.
    detections = []

    for detection in data:
        # For each detection in the payload.
        try:
            # Define detection and append to list for mass creation.
            detections.append(
                DefenderDetection(
                    scan_record=scan_record,
                    action_success=detection['ActionSuccess'],
                    av_version=detection['AMProductVersion'],
                    reseponse_type=detection['CleaningActionID'],
                    threat_execution_status=detection['CurrentThreatExecutionStatusID'],
                    detection_identifier=detection['DetectionID'],
                    active_user=detection['DomainUser'],
                    detection_time=convert_unix_to_dt(
                        detection['InitialDetectionTime']),
                    remediation_time=convert_unix_to_dt(
                        detection['RemediationTime']),
                    last_threat_status_change_time=convert_unix_to_dt(
                        detection['LastThreatStatusChangeTime']),
                    detection_process=detection['ProcessName'],
                    detected_resources=detection['Resources'].replace(
                        "file:_",
                        "",
                        1
                    ).split(" file:_")
                )
            )

        except KeyError:
            # Missing / Malformed data that differs to the default Windows output. Skip record.
            pass

    # Bulk create defined objects.
    DefenderDetection.objects.bulk_create(detections)

    return HttpResponse('Success')
