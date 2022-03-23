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
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from hashlib import md5

# --------------------------------------------------------------------------- #
#                        1.1 Default Fields Class                             #
# --------------------------------------------------------------------------- #


class DefaultFields(models.Model):
    # Default parameters to track creation date, last updated date and status.
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)

    # Define abstract class as true - all child classes to inherit fields.
    class Meta:
        abstract = True


# --------------------------------------------------------------------------- #
#                        1.2 System User Class                                #
# --------------------------------------------------------------------------- #

class SystemUser(AbstractUser):
    def get_gravatar_image(self):
        return 'http://www.gravatar.com/avatar/{}'.format(md5(self.email.encode()).hexdigest())


# --------------------------------------------------------------------------- #
#                        1.3 Scan Class                                       #
# --------------------------------------------------------------------------- #

class Scan(DefaultFields):
    class ScanTypes(models.TextChoices):
        BLUE = 'B'
        RED = 'R'

    # Foreign key to the user that owns the scan.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )

    type = models.CharField(
        max_length=1,
        choices=ScanTypes.choices,
        default=ScanTypes.BLUE,
        null=False,
        help_text="Type of scan being performed (red - offensive / blue - defensive)."
    )

    title = models.CharField(
        max_length=32,
        null=True,
        help_text="A user-defined identifier for a scan."
    )

    comment = models.TextField(
        max_length=2048,
        null=True,
        help_text="Comments or additional details related to a scan."
    )

    max_devices = models.IntegerField(
        default=1,
        validators=[
            MaxValueValidator(10),
            MinValueValidator(1)
        ],
        null=False,
        help_text="The number of devices that can be attached to a single scan request."
    )

    scan_key = models.CharField(
        max_length=32,
        null=False,
        help_text="A unique key associated with the scan."
    )

    completed = models.DateTimeField(
        null=True,
        help_text="The date/time that the scan completed."
    )

    expiry = models.DateTimeField(
        null=True,
        help_text="The expiry date/time that new data can be submitted for a scan."
    )

    system_users = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include system users."
    )

    browser_passwords = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include browser passwords stored on the system."
    )

    network_adapters = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include network adapter settings."
    )

    network_exposure = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include network exposure (log4j)."
    )

    network_firewall_rules = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include firewall rules."
    )

    startup_applications = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include startup applications."
    )

    installed_applications = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include installed applications."
    )

    installed_patches = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include installed OS updates and patches."
    )

    installed_antivirus = models.BooleanField(
        default=False,
        help_text="The flag for the scan to include check of anti-virus product installation."
    )


class ApiRequest(DefaultFields):
    class RequestMethod(models.IntegerChoices):
        GET = 1
        POST = 2
        PATCH = 3
        PUT = 4
        DELETE = 5

    # Foreign key to the user that owns the scan.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        help_text="The system user that is associated with the api request call.",
    )

    type = models.CharField(
        max_length=32,
        null=True,
        help_text="The name/type of the request made."
    )

    payload = models.TextField(
        null=True,
        help_text="The raw request payload data."
    )

    method = models.IntegerField(
        choices=RequestMethod.choices,
        default=RequestMethod.GET,
        null=False,
        help_text="The method of the request that was used."
    )

    response = models.CharField(
        default="200",
        max_length=8,
        null=True,
        help_text="The response code issued to the request."
    )

    def get_payload_size(self):
        return len(self.payload)


class Language(DefaultFields):
    string = models.CharField(
        max_length=32,
        null=True,
        help_text="The readable name of the language"
    )

    locale = models.CharField(
        max_length=5,
        null=True,
        help_text="The locale identifier of the language."
    )


class OperatingSystem(DefaultFields):
    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The readable name of the operating system."
    )

    version = models.CharField(
        max_length=32,
        null=True,
        help_text="The version of the operating system."
    )


class OperatingSystemInstall(DefaultFields):
    os = models.ForeignKey(
        OperatingSystem,
        on_delete=models.CASCADE,
        help_text="The operating system version that the installation is associated with."
    )

    serial = models.CharField(
        max_length=64,
        null=True,
        help_text="The serial number issued to the operating system installation."
    )

    timezone = models.CharField(
        max_length=48,
        null=True,
        help_text="The timezone configured on the system."
    )

    install_date = models.DateField(
        null=True,
        help_text="The date that the version of the OS was installed."
    )

    keyboard = models.ForeignKey(
        Language,
        on_delete=models.SET_DEFAULT,
        default="en-GB"
    )

    owner = models.CharField(
        max_length=32,
        null=True,
        help_text="The username of the configured operating system owner."
    )

    logon_server = models.CharField(
        max_length=32,
        null=True,
        help_text="The configured logon server."
    )

    installed_memory = models.CharField(
        max_length=32,
        null=True,
        help_text="The configured/installed physical system memory."
    )

    domain = models.BooleanField(
        default=False,
        help_text="The status for the device being connected to a domain."
    )

    portable = models.BooleanField(
        default=False,
        help_text="The status for the OS being mounted in a portable mode."
    )

    virtual_machine = models.BooleanField(
        default=False,
        help_text="The VM/Virtualised environment status."
    )

    debug_mode = models.BooleanField(
        default=False,
        help_text="The status for the device being configured in debug mode."
    )


class OperatingSystemInstalledLanguages(DefaultFields):
    os_install = models.ForeignKey(
        OperatingSystemInstall,
        on_delete=models.CASCADE,
        help_text="The operating system install that the installed language is associated with."
    )

    language = models.ForeignKey(
        Language,
        on_delete=models.CASCADE,
        help_text="The language that is installed."
    )


class Bios(DefaultFields):
    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The name of the BIOS."
    )

    version = models.CharField(
        max_length=16,
        null=True,
        help_text="The version / revision of the BIOS"
    )

    manufacturer = models.CharField(
        max_length=32,
        null=True,
        help_text="The manufacturer of the BIOS."
    )

    release_date = models.DateField(
        null=True,
        help_text="The date of the BIOS installed on the device was released."
    )


class BiosInstall(DefaultFields):
    bios = models.ForeignKey(
        Bios,
        on_delete=models.CASCADE,
        help_text="The version of the BIOS that the install is associated with."
    )

    install_date = models.DateField(
        null=True,
        help_text="The date of the BIOS installed on the device."
    )

    status = models.CharField(
        max_length=16,
        null=True,
        help_text="The status of the BIOS."
    )

    primary = models.BooleanField(
        default=True,
        help_text="The flag for the OS being the primary installed."
    )


class ScanRecord(DefaultFields):
    class ScanStatus(models.IntegerChoices):
        PENDING = 1
        IN_PROGRESS = 2
        PARTIALLY_COMPLETED = 3
        COMPLETED = 4
        NODATA = 5

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        help_text="The scan that the record is associated with."
    )

    device_id = models.CharField(
        max_length=48,
        null=True,
        help_text="The unique system ID assigned to the system."
    )

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The name of the device being scanned."
    )

    os_install = models.ForeignKey(
        OperatingSystemInstall,
        on_delete=models.CASCADE,
        help_text="The Operating System install that the record is associated with."
    )

    bios_install = models.ForeignKey(
        BiosInstall,
        on_delete=models.CASCADE,
        help_text="The BIOS install that the record is associated with."
    )

    boot_time = models.DateTimeField(
        null=True,
        help_text="The date/time that the system was last powered on."
    )

    current_user = models.CharField(
        max_length=48,
        null=True,
        help_text="The name of the user performing the scan."
    )

    public_ip = models.CharField(
        max_length=16,
        null=True,
        help_text="The public IP of the scanned device."
    )

    city = models.CharField(
        max_length=16,
        null=True,
        help_text="The location of the scanned device."
    )

    country = models.CharField(
        max_length=2,
        null=True,
        help_text="The country of the scanned device."
    )

    progress = models.IntegerField(
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ],
        help_text="The current progress/status of a scan."
    )


class CredentialScan(DefaultFields):
    class ScanStatus(models.IntegerChoices):
        PENDING = 1
        IN_PROGRESS = 2
        PARTIALLY_COMPLETED = 3
        COMPLETED = 4

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the credential scan group is associated with."
    )

    progress = models.IntegerField(
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ],
        help_text="The current progress/status of the credential processing."
    )


class Browser(DefaultFields):
    name = models.CharField(
        max_length=64,
        null=True,
        help_text="The name of the browser"
    )


class Credential(DefaultFields):
    class SecurityRating(models.IntegerChoices):
        VERY_WEAK = 1
        WEAK = 2
        MEDIUM = 3
        STRONG = 4
        VERY_STRONG = 5

    credential_scan = models.ForeignKey(
        CredentialScan,
        on_delete=models.CASCADE,
        help_text="The credential scan group that the credential is associated with."
    )

    url = models.CharField(
        max_length=128,
        null=True,
        help_text="The URL that the credential is associated with."
    )

    browser = models.ForeignKey(
        Browser,
        on_delete=models.CASCADE,
        help_text="The browser that the credential has been captured from."
    )

    storage = models.DateTimeField(
        null=True,
        help_text="The date/time that the credential was created/stored."
    )

    username = models.CharField(
        max_length=64,
        null=True,
        help_text="The username/email address associated with the credential."
    )

    password_strength = models.IntegerField(
        choices=SecurityRating.choices,
        default=SecurityRating.MEDIUM,
        validators=[
            MaxValueValidator(5),
            MinValueValidator(1)
        ],
        help_text="The strength of the password associated with the credential."
    )

    filename = models.CharField(
        max_length=128,
        null=True,
        help_text="The filename on the system that the credential was captured from."
    )

    compromised = models.BooleanField(
        default=False,
        help_text="The flag to identify if the password has appeared in a data breach."
    )

    occurrence = models.IntegerField(
        default=0,
        help_text="The number of times that the password has been seen in a data breach."
    )


class User(DefaultFields):
    class AccountType(models.IntegerChoices):
        LOCAL = 1
        MICROSOFT = 2

    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the user is associated with."
    )

    name = models.CharField(
        max_length=32,
        null=True,
        help_text="The username of the user account (Name)."
    )

    full_name = models.CharField(
        max_length=32,
        null=True,
        help_text="The full readable name of the user account (FullName)."
    )

    description = models.CharField(
        max_length=128,
        null=True,
        help_text="The description of the user account (Description)."
    )

    sid = models.CharField(
        max_length=48,
        null=True,
        help_text="The security identifier of the user account (SID/AccountDomainSid)."
    )

    source = models.IntegerField(
        choices=AccountType.choices,
        default=AccountType.LOCAL,
        validators=[
            MaxValueValidator(2),
            MinValueValidator(1)
        ],
        help_text="The type of user account (Microsoft or Local) (PrincipalSource)."
    )

    enabled = models.BooleanField(
        default=False,
        help_text="The status of the user account within the system (Enabled)."
    )

    last_logon = models.DateTimeField(
        null=True,
        help_text="The last logon date for the user account (LastLogon)."
    )

    password_changeable = models.DateTimeField(
        null=True,
        help_text="The date/time that the password is required to be changed by (PasswordChangeableDate)."
    )

    password_expiry = models.DateTimeField(
        null=True,
        help_text="The date/time that the current password defined on the user account will expire (PasswordExpires)."
    )

    password_permission = models.BooleanField(
        default=False,
        help_text="The flag to identify if the account is able to change its password (UserMayChangePassword)."
    )

    password_required = models.BooleanField(
        default=False,
        help_text="The flag to identify if a password reset is required on the account (PasswordRequired)."
    )

    password_last_set = models.DateTimeField(
        null=True,
        help_text="The date/time of the last time the password for the account was updated or changed (PasswordLastSet)."
    )

class DefenderStatus(DefaultFields):
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


class DefenderPreference(DefaultFields):
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


class DefenderExclusion(DefaultFields):
    class ExclusionType(models.IntegerChoices):
        EXTENSION = 1
        IP_ADDRESS = 2
        PATH = 3
        PROCESS = 4

    class ExclusionMethod(models.IntegerChoices):
        SCAN = 1
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


class DefenderDetection(DefaultFields):
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


class UpdatePending(DefaultFields):
    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender detection is associated with."
    )

    title = models.CharField(
        max_length=256,
        null=True,
        help_text="The title of an update (Title)."
    )

    description = models.CharField(
        max_length=1024,
        null=True,
        help_text="The description that accompanies the update (Description)."
    )

    install_deadline = models.DateTimeField(
        null=True,
        help_text="The date/time that the install is required to be installed by (Deadline)."
    )

    eula_accepted = models.BooleanField(
        default=False,
        help_text="The flag to confirm that the EULA has been accepted by the user (EulaAccepted)."
    )

    beta = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is in BETA (IsBeta)."
    )

    downloaded = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update has been already downloaded (IsDownloaded)."
    )

    hidden = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is hidden from the end user (IsHidden)."
    )

    mandatory = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is mandatory to be installed (IsMandatory)."
    )

    uninstallable = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update is able to be individually uninstalled (IsMandatory)."
    )

    reboot_required = models.BooleanField(
        default=False,
        help_text="The flag to indicate that the update will require a restart to install (RebootRequired)."
    )

    date_check = models.DateTimeField(
        null=True,
        help_text="The date/time that the update was last checked (LastDeploymentChangeTime)."
    )

    download_size = models.IntegerField(
        default=0,
        null=True,
        help_text="The maximum download/install size for the update (MaxDownloadSize)."
    )

    security_rating = models.CharField(
        max_length=32,
        null=True,
        help_text="The security severity rating for the update (MsrcSeverity)."
    )

    cves = models.CharField(
        max_length=128,
        null=True,
        help_text="The list of CVEs associated with the update (CveIDs)."
    )

    driver_date = models.CharField(
        max_length=128,
        null=True,
        help_text="The date that the driver/update was released (DriverVerDate)."
    )

    driver_manufacturer = models.CharField(
        max_length=128,
        null=True,
        help_text="The software developer of the driver/update (DriverProvider)."
    )

    driver_model = models.CharField(
        max_length=128,
        null=True,
        help_text="The device that the update/firmware/driver is for (DriverModel)."
    )


class UpdateInstalled(DefaultFields):
    scan_record = models.ForeignKey(
        ScanRecord,
        on_delete=models.CASCADE,
        help_text="The scan record that the Windows Defender detection is associated with."
    )

    date = models.DateTimeField(
        null=True,
        help_text="The date/time that the update was installed (Date)."
    )

    title = models.CharField(
        max_length=256,
        null=True,
        help_text="The title of an update (Title)."
    )

    description = models.CharField(
        max_length=1024,
        null=True,
        help_text="The description that accompanies the update (Description)."
    )

    kb = models.CharField(
        max_length=16,
        null=True,
        help_text="The microsoft KB identifier (KB)."
    )

    result = models.CharField(
        max_length=16,
        null=True,
        help_text="The status of the installation (Result)."
    )

    