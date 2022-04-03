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
from cyber_wary_portal.models.core import *
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


# --------------------------------------------------------------------------- #
#                                                                             #
#                           WINDOWS DEFENDER MODELS                           #
#                                                                             #
#         Models associated the Windows Defender component of a scan.         #
#                                                                             #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#                                   CONTENTS                                  #
# --------------------------------------------------------------------------- #
#                                                                             #
#                        1. Windows Defender                                  #
#                            1.1 Defender Status                              #
#                            1.2 Defender Settings                            #
#                            1.3 Defender Exclusions                          #
#                            1.4 Defender Detections                          #
#                        2. Windows Firewall                                  #
#                            2.1 Firewall Rules                               #
#                                                                             #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#                             1. Windows Defender                             #
# --------------------------------------------------------------------------- #
#                          1.1 Defender Status Class                          #
# --------------------------------------------------------------------------- #

class DefenderStatus(DefaultFields):
    # Model to store the current status of Windows Defender on a device being scanned.

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender status record is associated with."
    )

    behavior_monitoring = models.BooleanField(
        default=False,
        help_text="The flag associated with status of behaviour monitoring (BehaviorMonitorEnabled)."
    )

    tamper_protection = models.BooleanField(
        default=False,
        help_text="The flag associated with status of tamper protection (IsTamperProtected)."
    )

    realtime_protection = models.BooleanField(
        default=False,
        help_text="The flag associated with status of realtime protection (RealTimeProtectionEnabled)."
    )

    reboot_required = models.BooleanField(
        default=False,
        help_text="The flag associated with the requirement for a restart to implement security updates (RebootRequired)."
    )

    access_protection = models.BooleanField(
        default=False,
        help_text="The flag associated with status of account protection (OnAccessProtectionEnabled)."
    )

    download_protection = models.BooleanField(
        default=False,
        help_text="The flag associated with status of download scanning (IoavProtectionEnabled)."
    )

    virtual_machine = models.BooleanField(
        default=False,
        help_text="The flag associated with the detection of the machine being virtualised by Windows Defender (IsVirtualMachine)."
    )

    full_scan_required = models.BooleanField(
        default=False,
        help_text="The flag associated with the requirement for a full scan to be completed (FullScanRequired)."
    )

    full_scan_overdue = models.BooleanField(
        default=False,
        help_text="The flag associated with the full scan of a system being overdue and being required to be performed (FullScanOverdue)."
    )

    full_scan_last = models.DateTimeField(
        null=True,
        help_text="The date/time of the last time that a full scan has been performed on the system (FullScanEndTime)."
    )

    quick_scan_overdue = models.BooleanField(
        default=False,
        help_text="The flag associated with status of a quick scan being marked as overdue (QuickScanOverdue)."
    )

    quick_scan_last = models.DateTimeField(
        null=True,
        help_text="The date/time of the last time that a quick scan has been performed on the system (QuickScanEndTime)."
    )

    as_enabled = models.BooleanField(
        default=False,
        help_text="The flag associated with status of the Anti-Spyware settings in Windows Defender (AntispywareEnabled)."
    )

    as_signature_update = models.DateTimeField(
        null=True,
        help_text="The date/time of the last time that the anti-spyware signature set was updated (AntispywareSignatureLastUpdated)."
    )

    as_signature_version = models.CharField(
        max_length=16,
        null=True,
        help_text="The version of the current anti-spyware dataset currently running on the device (AntispywareSignatureVersion)."
    )

    av_enabled = models.BooleanField(
        default=False,
        help_text="The flag associated with status of anti-virus/malware monitoring (AntivirusEnabled)."
    )

    av_signature_update = models.DateTimeField(
        null=True,
        help_text="The date/time of the last signature update for the antivirus set (AntivirusSignatureLastUpdated)."
    )

    av_signature_version = models.CharField(
        max_length=16,
        null=True,
        help_text="The current version of anti-virus signatures currently running on the device (AntivirusSignatureVersion)."
    )

    nri_enabled = models.BooleanField(
        default=False,
        help_text="The flag associated with status of the network realtime inspection service (NISEnabled)."
    )

    nri_signature_update = models.DateTimeField(
        null=True,
        help_text="The date/time of the last signature update for the NRI service (NISSignatureLastUpdated)."
    )

    nri_signature_version = models.CharField(
        max_length=16,
        null=True,
        help_text="The current version of the NRI signature set currently running on the device (NISSignatureVersion)."
    )


# --------------------------------------------------------------------------- #
#                         1.2 Defender Settings Class                         #
# --------------------------------------------------------------------------- #

class DefenderPreference(DefaultFields):
    # Model to store the current preferences and settings configured for Windows Defender on a device being scanned.

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender preferences are associated with."
    )

    check_for_signatures_before_running_scan = models.BooleanField(
        default=False,
        help_text="The flag associated with the automated check for signature updates before a scan is performed (CheckForSignaturesBeforeRunningScan)."
    )

    disable_archive_scanning = models.BooleanField(
        default=False,
        help_text="The flag to identify if archive (zip, rar, cab) scanning has been disabled (DisableArchiveScanning)."
    )

    disable_auto_exclusions = models.BooleanField(
        default=False,
        help_text="The flag to identify if automatic exclusions has been disabled (DisableAutoExclusions)."
    )

    disable_behavior_monitoring = models.BooleanField(
        default=False,
        help_text="The flag to identify if behaviour monitoring has been disabled (DisableBehaviorMonitoring)."
    )

    disable_block_at_first_seen = models.BooleanField(
        default=False,
        help_text="The flag to identify if the automated blocking at initial occurrence has been disabled (DisableBlockAtFirstSeen)."
    )

    disable_cpu_throttle_on_idle_scans = models.BooleanField(
        default=False,
        help_text="The flag to identify if CPU throttling during idle scans has been disabled (DisableCpuThrottleOnIdleScans)."
    )

    disable_datagram_processing = models.BooleanField(
        default=False,
        help_text="The flag to identify if UDP inspection has been disabled (DisableDatagramProcessing)."
    )

    disable_dns_over_tcp_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if DNS over TCP inspection has been disabled (DisableDnsOverTcpParsing)."
    )

    disable_dns_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if DNS over UDP inspection has been disabled (DisableDnsParsing)."
    )

    disable_email_scanning = models.BooleanField(
        default=False,
        help_text="The flag to identify if email (mailbox, mail files) scanning has been disabled (DisableEmailScanning)."
    )

    disable_ftp_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if FTP inspection has been disabled (DisableFtpParsing)."
    )

    disable_gradual_release = models.BooleanField(
        default=False,
        help_text="The flag to identify if the gradual rollout of updates through monthly and daily patches has been disabled (DisableGradualRelease)."
    )

    disable_http_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if HTTP traffic inspection has been disabled (DisableHttpParsing)."
    )

    disable_inbound_connection_filtering = models.BooleanField(
        default=False,
        help_text="The flag to identify if inbound inspections has been disabled (DisableInboundConnectionFiltering)."
    )

    disable_ioav_protection = models.BooleanField(
        default=False,
        help_text="The flag to identify if the inspection of all downloaded files and attachments has been disabled (DisableIOAVProtection)."
    )

    disable_privacy_mode = models.BooleanField(
        default=False,
        help_text="The flag to identify if privacy mode has been disabled, allowing for threat history to be hidden (DisablePrivacyMode)."
    )

    disable_rdp_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if RDP traffic inspection has been disabled (DisableRdpParsing)."
    )

    disable_realtime_monitoring = models.BooleanField(
        default=False,
        help_text="The flag to identify if realtime monitoring has been disabled (DisableRealtimeMonitoring)."
    )

    disable_removable_drive_scanning = models.BooleanField(
        default=False,
        help_text="The flag to identify if scanning external devices (such as USBs) for malware has been disabled (DisableRemovableDriveScanning)."
    )

    disable_restore_point = models.BooleanField(
        default=False,
        help_text="The flag to identify if restore points have been disabled (DisableRestorePoint)."
    )

    disable_scanning_mapped_network_drives_for_full_scan = models.BooleanField(
        default=False,
        help_text="The flag to identify if the inclusion of mapped network drives in scans has been disabled (DisableScanningMappedNetworkDrivesForFullScan)."
    )

    disable_scanning_network_files = models.BooleanField(
        default=False,
        help_text="The flag to identify if the scanning of files on network drives has been disabled (DisableScanningNetworkFiles)."
    )

    disable_script_scanning = models.BooleanField(
        default=False,
        help_text="The flag to identify if the scanning of scripts has been disabled (DisableScriptScanning)."
    )

    disable_ssh_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if SSH traffic inspection has been disabled (DisableSshParsing)."
    )

    disable_tls_parsing = models.BooleanField(
        default=False,
        help_text="The flag to identify if TLS traffic inspection been disabled (DisableTlsParsing)."
    )

    controlled_folder_access = models.BooleanField(
        default=False,
        help_text="The flag to identify if controlled folder access (ransomware protection) has been enabled (EnableControlledFolderAccess)."
    )

    dns_sinkhole = models.BooleanField(
        default=False,
        help_text="The flag to identify if DNS sinkhole on malicous traffic detection has been enabled (EnableDnsSinkhole)."
    )

    file_hash_computation = models.BooleanField(
        default=False,
        help_text="The flag to identify if file hash computation has been enabled (EnableFileHashComputation)."
    )

    full_scan_on_battery_power = models.BooleanField(
        default=False,
        help_text="The flag to identify if full CPU performance while on battery power has been enabled (EnableFullScanOnBatteryPower)."
    )

    randomize_schedule_task_times = models.BooleanField(
        default=False,
        help_text="The flag to identify if scheduled tasks and scans are randomised (RandomizeScheduleTaskTimes)."
    )

    avg_load = models.IntegerField(
        default=0,
        help_text="The target average CPU load during a scan (ScanAvgCPULoadFactor)."
    )

    only_if_idle = models.BooleanField(
        default=False,
        help_text="The flag to control if a scan only activates while the CPU is idle (ScanOnlyIfIdleEnabled)."
    )

    ui_lockdown = models.BooleanField(
        default=False,
        help_text="The flag to state if the UI is locked during a scan (UILockdown)."
    )


# --------------------------------------------------------------------------- #
#                        1.3 Defender Exclusions Class                        #
# --------------------------------------------------------------------------- #

class DefenderExclusion(DefaultFields):
    # Model to record any exclusions configured in Windows Defender.

    # The type of exclusion that has been defined.
    class ExclusionType(models.IntegerChoices):
        EXTENSION = 1
        IP_ADDRESS = 2
        PATH = 3
        PROCESS = 4

    # The type of exclusion set.
    class ExclusionMethod(models.IntegerChoices):
        SCAN = 1  # Excluded from malware scanning.
        # Excluded from controlled folder access (ransomware) protection.
        CONTROLLED_ACCESS = 2

    preference = models.ForeignKey(
        DefenderPreference,
        on_delete=models.CASCADE,
        help_text="The set of preferences that the exclusion is associated with."
    )

    type = models.IntegerField(
        choices=ExclusionType.choices,
        default=ExclusionType.EXTENSION,
        validators=[
            MaxValueValidator(4),
            MinValueValidator(1)
        ],
        help_text="The type of exclusion."
    )

    method = models.IntegerField(
        choices=ExclusionMethod.choices,
        default=ExclusionMethod.SCAN,
        validators=[
            MaxValueValidator(2),
            MinValueValidator(1)
        ],
        help_text="The method that the exclusion is applied."
    )

    value = models.CharField(
        max_length=128,
        null=True,
        help_text="The value/contents of the exclusion."
    )


# --------------------------------------------------------------------------- #
#                        1.3 Defender Detections Class                        #
# --------------------------------------------------------------------------- #

class DefenderDetection(DefaultFields):
    # Model to record any detections that a device has recently flagged.

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender detection is associated with."
    )

    action_success = models.BooleanField(
        default=False,
        help_text="The status of the action processing (ActionSuccess)."
    )

    av_version = models.CharField(
        max_length=16,
        null=True,
        help_text="The signature version used to detect the incident (AMProductVersion)."
    )

    reseponse_type = models.IntegerField(
        default=0,
        help_text="The type of response that was taken to the threat detection (CleaningActionID)."
    )

    threat_execution_status = models.IntegerField(
        default=0,
        help_text="The status of the any outstanding threats (CurrentThreatExecutionStatusID)."
    )

    detection_identifier = models.CharField(
        max_length=48,
        null=True,
        help_text="The unique identifier given to the detection (DetectionID)."
    )

    active_user = models.CharField(
        max_length=48,
        null=True,
        help_text="The user currently active at the time of detection (DomainUser)."
    )

    detection_time = models.DateTimeField(
        null=True,
        help_text="The date/time of the detection of the threat (InitialDetectionTime)."
    )

    remediation_time = models.DateTimeField(
        null=True,
        help_text="The date/time of the resolution of the threat incident (RemediationTime)."
    )

    last_threat_status_change_time = models.DateTimeField(
        null=True,
        help_text="The date/time of the last time that the status changed of the threat incident (LastThreatStatusChangeTime)."
    )

    detection_process = models.CharField(
        max_length=64,
        null=True,
        help_text="The process that was involved in detecting the threat (ProcessName)."
    )

    detected_resources = models.CharField(
        max_length=256,
        null=True,
        help_text="The associated files, extensions or resources that are deemed to be a threat (Resources)."
    )


# --------------------------------------------------------------------------- #
#                             2. Windows Firewall                             #
# --------------------------------------------------------------------------- #
#                              2.1 Firewall Rules                             #
# --------------------------------------------------------------------------- #

class FirewallRules(DefaultFields):
    # Model to record all firewall rules configured on a scanned system.

    # The protocol that the rule applies to.
    class Protocol(models.IntegerChoices):
        UDP = 1
        TCP = 2

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the firewall rule is associated with."
    )

    rule_id = models.TextField(
        null=True,
        help_text="The instance ID associated with the firewall rule (ID/InstanceID)."
    )

    name = models.TextField(
        null=True,
        help_text="The display name of the firewall rule (DisplayName)."
    )

    description = models.TextField(
        null=True,
        help_text="The description given to the rule (Description)."
    )

    group = models.CharField(
        max_length=256,
        null=True,
        help_text="The group that the firewall rule is associated with (Group)."
    )

    enabled = models.IntegerField(
        default=0,
        help_text="The enabled status of the rule (Enabled)."
    )

    lsm = models.BooleanField(
        default=False,
        help_text="The flag to identify if the firewall rule is managed by the Local Session Manager (LSM)."
    )

    direction = models.IntegerField(
        default=0,
        help_text="The direction that the rule is targetting (inbound/outbound) (Direction)."
    )

    action = models.IntegerField(
        default=0,
        help_text="The configured action to apply to the rule (Action)."
    )

    file_path = models.CharField(
        max_length=256,
        null=True,
        help_text="The file path/program that is applied to the rule (Program)."
    )

    local_address = models.CharField(
        max_length=64,
        null=True,
        help_text="The local address that the rule applies to (LocalAddress)."
    )

    local_ip = models.CharField(
        max_length=128,
        null=True,
        help_text="The local numerical IP address that the rule applies to (LocalIP)."
    )

    local_port = models.CharField(
        max_length=8,
        null=True,
        help_text="The local port number that the rule targets (LocalPort)."
    )

    remote_address = models.CharField(
        max_length=64,
        null=True,
        help_text="The remote address that the rule applies to (RemoteAddress)."
    )

    remote_ip = models.CharField(
        max_length=128,
        null=True,
        help_text="The remote numerical IP address that the rule applies to (RemoteIP)."
    )

    remote_port = models.CharField(
        max_length=8,
        null=True,
        help_text="The remote port number that the rule targets (RemotePort)."
    )

    protocol = models.IntegerField(
        choices=Protocol.choices,
        default=Protocol.UDP,
        validators=[
            MaxValueValidator(2),
            MinValueValidator(1)
        ],
        help_text="The protocol that the rule targets (Protocol)."
    )
