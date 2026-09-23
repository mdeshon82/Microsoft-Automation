# =====================================================================
# WINDOWS DOMAIN WORKSTATION SECURITY BASELINE
#
# Target:
#   Windows 10 / Windows 11 domain-joined user workstations
#
# Run:
#   Elevated PowerShell on a Domain Controller or management server
#   with ActiveDirectory and GroupPolicy modules installed.
#
# Creates:
#   SEC - Workstations - Security Baseline
#   SEC - Workstations - Defender ASR
#   SEC - Workstations - Windows Firewall
#
# Creates OU if missing:
#   OU=Workstations,<domain>
#
# DOES NOT MOVE COMPUTERS INTO THE OU.
#
# Includes:
#   LSASS Protected Process
#   Defender ASR
#   Defender Network Protection
#   SmartScreen
#   SMB signing
#   SMBv1 disablement
#   LDAP client signing
#   Windows Firewall
#   LLMNR disablement
#   PowerShell logging
#   RDP NLA
#   Corporate legal warning
#   15 minute idle lock
#   Windows LAPS if AD schema is already prepared
# =====================================================================

$ErrorActionPreference = "Stop"

# =====================================================================
# CONFIGURATION
# =====================================================================

$WorkstationOUName = "Workstations"

# Corporate inactivity timeout
$InactivityTimeoutSeconds = 900

# LSA Protection
$EnableLSAProtection = $true

# Optional Credential Guard.
#
# Leave FALSE initially if you have legacy authentication,
# VPN software, old smart-card middleware, or older hardware.
#
# Change to TRUE after validation.
$EnableCredentialGuard = $false

# NTLMv2-only mode.
#
# This can break old NAS appliances, printers, scanners, etc.
# Leave false until legacy equipment is validated.
$EnableNTLMv2Only = $false

# Legal banner
$ApplyLegalBanner = $true

$LogonTitle = "WARNING"

$LogonMessage = @"
You are accessing a secured corporate system. This system is restricted to authorized users only. All activities, communications, and data transactions on this server may be monitored, recorded, and audited. Unauthorized access or use may result in criminal prosecution, civil penalties, and immediate disciplinary action. By continuing, you consent to these monitoring terms. Disconnect immediately if you are not an authorized user.
"@

# ASR actions
#
# 0 = Disabled
# 1 = Block
# 2 = Audit
# 6 = Warn on supported rules

$ASRBlock = "1"
$ASRAudit = "2"


# =====================================================================
# VERIFY ADMINISTRATOR
# =====================================================================

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "PowerShell must be run as Administrator."
}


# =====================================================================
# MODULES
# =====================================================================

Write-Host ""
Write-Host "Loading Active Directory and Group Policy modules..." `
    -ForegroundColor Cyan

Import-Module ActiveDirectory
Import-Module GroupPolicy


# =====================================================================
# DOMAIN INFORMATION
# =====================================================================

$Domain = Get-ADDomain

$DomainDNS  = $Domain.DNSRoot
$DomainDN   = $Domain.DistinguishedName
$DomainMode = $Domain.DomainMode

$WorkstationOU = "OU=$WorkstationOUName,$DomainDN"

Write-Host ""
Write-Host "Domain:       $DomainDNS" -ForegroundColor Green
Write-Host "Domain Mode:  $DomainMode"
Write-Host "Target OU:    $WorkstationOU"
Write-Host ""


# =====================================================================
# CREATE WORKSTATIONS OU IF NEEDED
# =====================================================================

$ExistingOU = Get-ADOrganizationalUnit `
    -Identity $WorkstationOU `
    -ErrorAction SilentlyContinue

if (-not $ExistingOU) {

    Write-Host "Creating Workstations OU..." -ForegroundColor Cyan

    New-ADOrganizationalUnit `
        -Name $WorkstationOUName `
        -Path $DomainDN `
        -ProtectedFromAccidentalDeletion $true

    Write-Host "Created: $WorkstationOU" -ForegroundColor Green
}
else {

    Write-Host "Workstations OU already exists." `
        -ForegroundColor DarkGray
}


# =====================================================================
# BACKUP ALL CURRENT GPOs
# =====================================================================

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$BackupRoot = "C:\AD-GPO-Backup"
$BackupPath = "$BackupRoot\WorkstationBaseline-$Timestamp"

New-Item `
    -Path $BackupPath `
    -ItemType Directory `
    -Force | Out-Null

Write-Host ""
Write-Host "Backing up all current GPOs..." -ForegroundColor Cyan

Backup-GPO `
    -All `
    -Path $BackupPath `
    -Domain $DomainDNS | Out-Null

Write-Host "Backup complete: $BackupPath" -ForegroundColor Green


# =====================================================================
# HELPER FUNCTIONS
# =====================================================================

function Ensure-GPO {

    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Comment
    )

    $GPO = Get-GPO `
        -Name $Name `
        -Domain $DomainDNS `
        -ErrorAction SilentlyContinue

    if (-not $GPO) {

        Write-Host "Creating GPO: $Name" -ForegroundColor Cyan

        $GPO = New-GPO `
            -Name $Name `
            -Comment $Comment `
            -Domain $DomainDNS
    }
    else {

        Write-Host "GPO already exists: $Name" `
            -ForegroundColor DarkGray
    }

    return $GPO
}


function Ensure-GPOLink {

    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Target
    )

    $Existing = (Get-GPInheritance -Target $Target).GpoLinks |
        Where-Object DisplayName -eq $Name

    if (-not $Existing) {

        Write-Host "Linking $Name -> $Target" -ForegroundColor Cyan

        New-GPLink `
            -Name $Name `
            -Target $Target `
            -LinkEnabled Yes | Out-Null
    }
    else {

        Write-Host "Already linked: $Name" `
            -ForegroundColor DarkGray
    }
}


function Set-GPODword {

    param(
        [string]$GPO,
        [string]$Key,
        [string]$ValueName,
        [int]$Value
    )

    Set-GPRegistryValue `
        -Name $GPO `
        -Domain $DomainDNS `
        -Key $Key `
        -ValueName $ValueName `
        -Type DWord `
        -Value $Value | Out-Null
}


function Set-GPOString {

    param(
        [string]$GPO,
        [string]$Key,
        [string]$ValueName,
        [string]$Value
    )

    Set-GPRegistryValue `
        -Name $GPO `
        -Domain $DomainDNS `
        -Key $Key `
        -ValueName $ValueName `
        -Type String `
        -Value $Value | Out-Null
}


function Set-GPOMultiString {

    param(
        [string]$GPO,
        [string]$Key,
        [string]$ValueName,
        [string[]]$Value
    )

    Set-GPRegistryValue `
        -Name $GPO `
        -Domain $DomainDNS `
        -Key $Key `
        -ValueName $ValueName `
        -Type MultiString `
        -Value $Value | Out-Null
}


# =====================================================================
#
# GPO 1
#
# WORKSTATION SECURITY BASELINE
#
# =====================================================================

$BaselineGPO = "SEC - Workstations - Security Baseline"

Ensure-GPO `
    -Name $BaselineGPO `
    -Comment "Security baseline for Windows 10 and Windows 11 domain-joined workstations."

Ensure-GPOLink `
    -Name $BaselineGPO `
    -Target $WorkstationOU


# =====================================================================
# INTERACTIVE LOGON LEGAL WARNING
# =====================================================================

if ($ApplyLegalBanner) {

    Set-GPOString `
        -GPO $BaselineGPO `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -ValueName "LegalNoticeCaption" `
        -Value $LogonTitle

    Set-GPOString `
        -GPO $BaselineGPO `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -ValueName "LegalNoticeText" `
        -Value $LogonMessage
}


# =====================================================================
# AUTOMATIC WORKSTATION LOCK
#
# Interactive logon: Machine inactivity limit
# 900 seconds = 15 minutes
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "InactivityTimeoutSecs" `
    -Value $InactivityTimeoutSeconds


# =====================================================================
# DO NOT DISPLAY LAST LOGGED-ON USER
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DontDisplayLastUserName" `
    -Value 1


# =====================================================================
# REQUIRE CTRL+ALT+DELETE
#
# DisableCAD = 0 means CTRL+ALT+DELETE IS required.
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableCAD" `
    -Value 0


# =====================================================================
# UAC
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "EnableLUA" `
    -Value 1

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "PromptOnSecureDesktop" `
    -Value 1

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "EnableInstallerDetection" `
    -Value 1


# =====================================================================
# LSASS PROTECTED PROCESS
#
# RunAsPPL = 1
#
# Enables LSA protection using UEFI protection.
# Requires reboot.
# =====================================================================

if ($EnableLSAProtection) {

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "RunAsPPL" `
        -Value 1
}


# =====================================================================
# CREDENTIAL GUARD
#
# OPTIONAL.
#
# Enabled WITHOUT UEFI lock so it can be remotely disabled later.
#
# Requires compatible hardware, virtualization support and reboot.
# =====================================================================

if ($EnableCredentialGuard) {

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -ValueName "EnableVirtualizationBasedSecurity" `
        -Value 1

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -ValueName "LsaCfgFlags" `
        -Value 2

    Write-Warning "Credential Guard is ENABLED. Validate VPN, authentication, and virtualization compatibility."
}
else {

    Write-Host "Credential Guard left unconfigured for initial rollout." `
        -ForegroundColor Yellow
}


# =====================================================================
# DISABLE WDigest CREDENTIAL CACHING
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -ValueName "UseLogonCredential" `
    -Value 0


# =====================================================================
# DO NOT STORE LAN MANAGER HASH
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "NoLMHash" `
    -Value 1


# =====================================================================
# BLANK PASSWORD RESTRICTION
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LimitBlankPasswordUse" `
    -Value 1


# =====================================================================
# ANONYMOUS ACCESS RESTRICTIONS
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymous" `
    -Value 1

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymousSAM" `
    -Value 1

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "EveryoneIncludesAnonymous" `
    -Value 0


# =====================================================================
# OPTIONAL NTLMv2 ONLY
# =====================================================================

if ($EnableNTLMv2Only) {

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "LmCompatibilityLevel" `
        -Value 5
}
else {

    Write-Warning "NTLMv2-only enforcement is not enabled yet. Validate legacy NAS/printers/scanners first."
}


# =====================================================================
# DISABLE LLMNR
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" `
    -Value 0


# =====================================================================
# SMB HARDENING
# =====================================================================

# Require outbound SMB signing

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" `
    -Value 1


# Require inbound SMB signing

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RequireSecuritySignature" `
    -Value 1


# Disable insecure guest SMB authentication

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
    -ValueName "AllowInsecureGuestAuth" `
    -Value 0


# Disable SMBv1 server

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" `
    -Value 0


# Disable SMBv1 client driver

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
    -ValueName "Start" `
    -Value 4


# Remove SMBv1 driver dependency

Set-GPOMultiString `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" `
    -ValueName "DependOnService" `
    -Value @(
        "Bowser",
        "MRxSmb20",
        "NSI"
    )


# =====================================================================
# LDAP CLIENT SIGNING
#
# LDAPClientIntegrity = 2
# Require Signing
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" `
    -ValueName "LDAPClientIntegrity" `
    -Value 2


# =====================================================================
# RDP SECURITY
# =====================================================================

# Require Network Level Authentication

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "UserAuthentication" `
    -Value 1


# Prevent RDP password saving

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "DisablePasswordSaving" `
    -Value 1


# =====================================================================
# POWERSHELL LOGGING
# =====================================================================

# Script Block Logging

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" `
    -Value 1


# Module Logging

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -ValueName "EnableModuleLogging" `
    -Value 1

Set-GPOString `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -ValueName "*" `
    -Value "*"


# =====================================================================
# DISABLE ALWAYS INSTALL ELEVATED
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -ValueName "AlwaysInstallElevated" `
    -Value 0


# =====================================================================
# DISABLE AUTORUN
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoDriveTypeAutoRun" `
    -Value 255

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoAutorun" `
    -Value 1


# =====================================================================
# WINDOWS DEFENDER SMARTSCREEN
# =====================================================================

Set-GPODword `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
    -ValueName "EnableSmartScreen" `
    -Value 1

Set-GPOString `
    -GPO $BaselineGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
    -ValueName "ShellSmartScreenLevel" `
    -Value "Block"


# =====================================================================
#
# GPO 2
#
# MICROSOFT DEFENDER + ASR
#
# =====================================================================

$DefenderGPO = "SEC - Workstations - Defender ASR"

Ensure-GPO `
    -Name $DefenderGPO `
    -Comment "Microsoft Defender, Network Protection and ASR baseline for Windows workstations."

Ensure-GPOLink `
    -Name $DefenderGPO `
    -Target $WorkstationOU


# =====================================================================
# DEFENDER REAL-TIME PROTECTION
# =====================================================================

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableRealtimeMonitoring" `
    -Value 0

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableBehaviorMonitoring" `
    -Value 0

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableIOAVProtection" `
    -Value 0

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableScriptScanning" `
    -Value 0


# =====================================================================
# POTENTIALLY UNWANTED APPLICATION PROTECTION
# =====================================================================

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -ValueName "PUAProtection" `
    -Value 1


# =====================================================================
# MICROSOFT CLOUD PROTECTION / MAPS
# =====================================================================

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -ValueName "SpynetReporting" `
    -Value 2

# Send safe samples automatically

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -ValueName "SubmitSamplesConsent" `
    -Value 1


# =====================================================================
# DEFENDER NETWORK PROTECTION
#
# Block malicious domains / IPs
# =====================================================================

Set-GPODword `
    -GPO $DefenderGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
    -ValueName "EnableNetworkProtection" `
    -Value 1


# =====================================================================
# ATTACK SURFACE REDUCTION
# =====================================================================

$ASRKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"


# ---------------------------------------------------------------------
# BLOCK LSASS CREDENTIAL THEFT
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK VULNERABLE SIGNED DRIVERS
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "56a863a9-875e-4185-98a7-b882c64b5ce5" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK OFFICE CHILD PROCESSES
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "d4f940ab-401b-4efc-aadc-ad5f3c50688a" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK OFFICE FROM CREATING EXECUTABLE CONTENT
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "3b576869-a4ec-4529-8536-b80a7769e899" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK OFFICE CODE INJECTION
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK OUTLOOK / OFFICE COMMUNICATION CHILD PROCESSES
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "26190899-1602-49e8-8b27-eb1d0a1ce869" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK EXECUTABLE CONTENT FROM EMAIL / WEBMAIL
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK OBFUSCATED SCRIPTS
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "5beb7efe-fd9a-4556-801d-275e5ffc04cc" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK JAVASCRIPT / VBS FROM LAUNCHING DOWNLOADED EXECUTABLES
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "d3e037e1-3eb8-44c8-a917-57927947596d" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK WIN32 API CALLS FROM OFFICE MACROS
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# ADVANCED RANSOMWARE PROTECTION
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "c1db55ab-c21a-4637-bb3f-a12568109d35" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK UNSIGNED / UNTRUSTED USB EXECUTION
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# BLOCK ADOBE READER FROM CREATING CHILD PROCESSES
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" `
    -Value $ASRBlock


# ---------------------------------------------------------------------
# PSEXEC / WMI PROCESS CREATION
#
# AUDIT ONLY initially.
#
# Important for IT environments because blocking this can interfere
# with administrative automation and endpoint management software.
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "d1e49aac-8f56-4280-b9ba-993a6d77406c" `
    -Value $ASRAudit


# ---------------------------------------------------------------------
# WMI EVENT SUBSCRIPTION PERSISTENCE
#
# AUDIT initially in case legitimate management software uses it.
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "e6db77e5-3df2-4cf1-b95a-636979351e5b" `
    -Value $ASRAudit


# ---------------------------------------------------------------------
# UNTRUSTED EXECUTABLE PREVALENCE / AGE RULE
#
# AUDIT FIRST.
#
# This is a strong rule but can block new internal applications,
# scripts packaged as executables, and low-prevalence LOB software.
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $DefenderGPO `
    -Key $ASRKey `
    -ValueName "01443614-cd74-433a-b99e-2ecdc07bfc25" `
    -Value $ASRAudit


# =====================================================================
#
# GPO 3
#
# WINDOWS FIREWALL
#
# =====================================================================

$FirewallGPO = "SEC - Workstations - Windows Firewall"

Ensure-GPO `
    -Name $FirewallGPO `
    -Comment "Windows Defender Firewall baseline for domain-joined workstations."

Ensure-GPOLink `
    -Name $FirewallGPO `
    -Target $WorkstationOU


$FirewallProfiles = @(
    "DomainProfile",
    "PrivateProfile",
    "PublicProfile"
)

foreach ($Profile in $FirewallProfiles) {

    $Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$Profile"

    # Enable firewall

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $Key `
        -ValueName "EnableFirewall" `
        -Value 1


    # Block unsolicited inbound connections

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $Key `
        -ValueName "DefaultInboundAction" `
        -Value 1


    # Allow outbound connections

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $Key `
        -ValueName "DefaultOutboundAction" `
        -Value 0


    # Preserve local firewall rules for existing software.
    #
    # This can be tightened to 0 later after central firewall
    # rules are fully defined.

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $Key `
        -ValueName "AllowLocalPolicyMerge" `
        -Value 1
}


# =====================================================================
#
# WINDOWS LAPS
#
# If Windows LAPS schema is already present, configure it.
#
# If schema has NOT been extended, skip it rather than creating
# a broken client configuration.
#
# =====================================================================

Write-Host ""
Write-Host "Checking Windows LAPS readiness..." -ForegroundColor Cyan

$SchemaNC = (Get-ADRootDSE).SchemaNamingContext

$LAPSSchema = Get-ADObject `
    -SearchBase $SchemaNC `
    -LDAPFilter "(lDAPDisplayName=msLAPS-PasswordExpirationTime)" `
    -ErrorAction SilentlyContinue

if ($LAPSSchema) {

    Write-Host "Windows LAPS schema detected." -ForegroundColor Green

    $LAPSKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

    # Backup password to on-prem AD

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key $LAPSKey `
        -ValueName "BackupDirectory" `
        -Value 2


    # Rotate every 30 days

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key $LAPSKey `
        -ValueName "PasswordAgeDays" `
        -Value 30


    # Strong 20-character local admin password

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key $LAPSKey `
        -ValueName "PasswordLength" `
        -Value 20


    # Upper/lower/numeric/special

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key $LAPSKey `
        -ValueName "PasswordComplexity" `
        -Value 4


    # Enforce expiration

    Set-GPODword `
        -GPO $BaselineGPO `
        -Key $LAPSKey `
        -ValueName "PasswordExpirationProtectionEnabled" `
        -Value 1


    # Encrypt LAPS passwords when domain functional level supports it

    if ($DomainMode -eq "Windows2016Domain") {

        Set-GPODword `
            -GPO $BaselineGPO `
            -Key $LAPSKey `
            -ValueName "ADPasswordEncryptionEnabled" `
            -Value 1

        Write-Host "LAPS AD password encryption enabled." `
            -ForegroundColor Green
    }


    # Configure SELF permissions on the workstation OU when the
    # Windows LAPS management cmdlets are available.

    if (Get-Command Set-LapsADComputerSelfPermission `
        -ErrorAction SilentlyContinue) {

        try {

            Set-LapsADComputerSelfPermission `
                -Identity $WorkstationOU

            Write-Host "LAPS computer SELF permissions configured." `
                -ForegroundColor Green
        }
        catch {

            Write-Warning "LAPS policy was created, but automatic OU permission configuration failed: $($_.Exception.Message)"
        }
    }
    else {

        Write-Warning "Windows LAPS schema exists but Set-LapsADComputerSelfPermission is unavailable. Verify LAPS OU permissions manually."
    }
}
else {

    Write-Warning "Windows LAPS schema not detected. LAPS policy was NOT enabled."

    Write-Warning "Prepare Windows LAPS separately before enabling LAPS backup to Active Directory."
}


# =====================================================================
# FINISHED
# =====================================================================

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "WORKSTATION SECURITY BASELINE COMPLETE" `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host ""
Write-Host "Target OU:" -ForegroundColor Cyan
Write-Host "  $WorkstationOU"

Write-Host ""
Write-Host "GPO backup:" -ForegroundColor Cyan
Write-Host "  $BackupPath"

Write-Host ""
Write-Host "Created / Updated:" -ForegroundColor Cyan
Write-Host "  $BaselineGPO"
Write-Host "  $DefenderGPO"
Write-Host "  $FirewallGPO"

Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow

Write-Host @"

  No computers were moved into the Workstations OU.

  Move ONLY a few test workstations into:

      $WorkstationOU

  first.

  LSASS protection requires a reboot.

  SMBv1 client disablement requires a reboot.

  LDAP CLIENT signing is REQUIRED.

  SMB signing is REQUIRED.

  PsExec/WMI ASR is AUDIT ONLY.

  Low-prevalence executable ASR is AUDIT ONLY.

  WMI persistence ASR is AUDIT ONLY.

"@


# =====================================================================
# DISPLAY LINKS
# =====================================================================

Write-Host "Workstation OU GPO links:" -ForegroundColor Cyan

(Get-GPInheritance -Target $WorkstationOU).GpoLinks |
    Select-Object DisplayName,Enabled,Enforced,Order |
    Format-Table -AutoSize


Write-Host ""
Write-Host "Security GPOs:" -ForegroundColor Cyan

Get-GPO -All |
    Where-Object DisplayName -Like "SEC - Workstations -*" |
    Select-Object DisplayName,Id,GpoStatus |
    Format-Table -AutoSize


Write-Host ""
Write-Host "Pilot workstation validation commands:" `
    -ForegroundColor Yellow

Write-Host @'

gpupdate /force

gpresult /h C:\gpresult.html

Get-NetFirewallProfile |
    Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction

Get-SmbClientConfiguration |
    Select RequireSecuritySignature

Get-SmbServerConfiguration |
    Select EnableSMB1Protocol,RequireSecuritySignature

Get-MpPreference |
    Select EnableNetworkProtection,
           PUAProtection,
           AttackSurfaceReductionRules_Ids,
           AttackSurfaceReductionRules_Actions

Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name RunAsPPL

Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' `
    -Name LDAPClientIntegrity

Get-ItemProperty `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
    -Name EnableSmartScreen,ShellSmartScreenLevel

Start-Process C:\gpresult.html

'@

Write-Host ""
Write-Host "A reboot of the pilot workstation is recommended." `
    -ForegroundColor Yellow

Write-Host ""
Write-Host "Done." -ForegroundColor Green
