# =====================================================================
# ACTIVE DIRECTORY / WINDOWS SERVER 2016 SECURITY BASELINE
#
# Creates separate GPOs rather than modifying:
#   Default Domain Policy
#   Default Domain Controllers Policy
#
# Includes:
#   - Server security baseline
#   - LSASS Protected Process (RunAsPPL)
#   - Microsoft Defender hardening
#   - Attack Surface Reduction rules
#   - SMB signing
#   - SMBv1 disablement
#   - LDAP client/server signing
#   - LDAP channel binding
#   - LLMNR disablement
#   - RDP NLA
#   - PowerShell logging
#   - UAC
#   - Windows Firewall
#   - Corporate interactive logon warning
#   - GPO backup before modifications
#
# Designed around Windows Server 2016-era AD.
# =====================================================================

$ErrorActionPreference = "Stop"

# =====================================================================
# CONFIGURATION
# =====================================================================

# LDAP:
# 0 = Never
# 1 = When Supported        <-- recommended initial setting
# 2 = Always / Required     <-- use after validating LDAPS applications
$LDAPChannelBindingLevel = 1

# Require LDAP signing on Domain Controllers
$RequireLDAPSigning = $true

# Require LDAP signing from Windows LDAP clients
$RequireLDAPClientSigning = $true

# ASR settings
#
# 1 = Block
# 2 = Audit
#
# Most selected rules will be Block.
# PsExec/WMI is Audit because it can interfere with legitimate
# administration / automation tools.
$ASRBlockMode = 1
$ASRAuditMode = 2


# =====================================================================
# LEGAL LOGON BANNER
# =====================================================================

$LogonTitle = "WARNING"

$LogonMessage = @"
You are accessing a secured corporate system. This system is restricted to authorized users only. All activities, communications, and data transactions on this server may be monitored, recorded, and audited. Unauthorized access or use may result in criminal prosecution, civil penalties, and immediate disciplinary action. By continuing, you consent to these monitoring terms. Disconnect immediately if you are not an authorized user.
"@


# =====================================================================
# VERIFY ADMIN RIGHTS
# =====================================================================

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "PowerShell must be run as Administrator."
}


# =====================================================================
# LOAD MODULES
# =====================================================================

Write-Host ""
Write-Host "Loading Active Directory and Group Policy modules..." `
    -ForegroundColor Cyan

Import-Module ActiveDirectory
Import-Module GroupPolicy


# =====================================================================
# DISCOVER DOMAIN
# =====================================================================

$Domain = Get-ADDomain

$DomainDNS = $Domain.DNSRoot
$DomainDN  = $Domain.DistinguishedName
$DCOU      = $Domain.DomainControllersContainer
$PDC       = $Domain.PDCEmulator

Write-Host ""
Write-Host "Domain:             $DomainDNS" -ForegroundColor Green
Write-Host "Domain DN:          $DomainDN"
Write-Host "Domain Controllers: $DCOU"
Write-Host "PDC Emulator:       $PDC"
Write-Host ""


# =====================================================================
# BACK UP EXISTING GPOs
# =====================================================================

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$BackupRoot = "C:\AD-GPO-Backup"
$BackupPath = "$BackupRoot\$Timestamp"

New-Item `
    -Path $BackupPath `
    -ItemType Directory `
    -Force | Out-Null

Write-Host "Backing up ALL existing GPOs..." -ForegroundColor Cyan
Write-Host "Backup path: $BackupPath" -ForegroundColor Yellow

Backup-GPO `
    -All `
    -Path $BackupPath `
    -Domain $DomainDNS | Out-Null

Write-Host "GPO backup complete." -ForegroundColor Green


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

    $Inheritance = Get-GPInheritance -Target $Target

    $Existing = $Inheritance.GpoLinks |
        Where-Object { $_.DisplayName -eq $Name }

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
        [Parameter(Mandatory)]
        [string]$GPO,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName,

        [Parameter(Mandatory)]
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
        [Parameter(Mandatory)]
        [string]$GPO,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName,

        [Parameter(Mandatory)]
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
        [Parameter(Mandatory)]
        [string]$GPO,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName,

        [Parameter(Mandatory)]
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
# GPO 1 - DOMAIN COMPUTER SECURITY
#
# =====================================================================

$ComputerGPO = "SEC - Domain Computers - Basic Security"

Ensure-GPO `
    -Name $ComputerGPO `
    -Comment "General Windows domain computer security baseline."

Ensure-GPOLink `
    -Name $ComputerGPO `
    -Target $DomainDN


# ---------------------------------------------------------------------
# DISABLE LLMNR
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" `
    -Value 0


# ---------------------------------------------------------------------
# REQUIRE SMB CLIENT SIGNING
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" `
    -Value 1


# ---------------------------------------------------------------------
# REQUIRE SMB SERVER SIGNING
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RequireSecuritySignature" `
    -Value 1


# ---------------------------------------------------------------------
# DISABLE SMB INSECURE GUEST AUTHENTICATION
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
    -ValueName "AllowInsecureGuestAuth" `
    -Value 0


# ---------------------------------------------------------------------
# DISABLE SMBv1 SERVER
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" `
    -Value 0


# ---------------------------------------------------------------------
# DISABLE SMBv1 CLIENT DRIVER
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
    -ValueName "Start" `
    -Value 4


# Remove SMB1 client driver dependency while retaining SMB2/SMB3

Set-GPOMultiString `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" `
    -ValueName "DependOnService" `
    -Value @(
        "Bowser",
        "MRxSmb20",
        "NSI"
    )


# ---------------------------------------------------------------------
# LDAP CLIENT SIGNING
# ---------------------------------------------------------------------

if ($RequireLDAPClientSigning) {

    # 2 = Require Signing

    Set-GPODword `
        -GPO $ComputerGPO `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" `
        -ValueName "LDAPClientIntegrity" `
        -Value 2
}


# ---------------------------------------------------------------------
# DISABLE WDigest CLEAR-TEXT CREDENTIAL STORAGE
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -ValueName "UseLogonCredential" `
    -Value 0


# ---------------------------------------------------------------------
# PREVENT LM PASSWORD HASH STORAGE
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "NoLMHash" `
    -Value 1


# ---------------------------------------------------------------------
# RESTRICT ANONYMOUS SAM ENUMERATION
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymousSAM" `
    -Value 1


# ---------------------------------------------------------------------
# RESTRICT ADDITIONAL ANONYMOUS ACCESS
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymous" `
    -Value 1


# ---------------------------------------------------------------------
# DO NOT ADD ANONYMOUS USERS TO EVERYONE
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "EveryoneIncludesAnonymous" `
    -Value 0


# ---------------------------------------------------------------------
# RESTRICT BLANK PASSWORDS TO CONSOLE
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LimitBlankPasswordUse" `
    -Value 1


# ---------------------------------------------------------------------
# REQUIRE RDP NETWORK LEVEL AUTHENTICATION
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "UserAuthentication" `
    -Value 1


# ---------------------------------------------------------------------
# POWERSHELL SCRIPT BLOCK LOGGING
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" `
    -Value 1


# ---------------------------------------------------------------------
# POWERSHELL MODULE LOGGING
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -ValueName "EnableModuleLogging" `
    -Value 1

Set-GPOString `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -ValueName "*" `
    -Value "*"


# ---------------------------------------------------------------------
# DISABLE ALWAYS INSTALL ELEVATED
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -ValueName "AlwaysInstallElevated" `
    -Value 0


# ---------------------------------------------------------------------
# DISABLE AUTORUN / AUTOPLAY
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoDriveTypeAutoRun" `
    -Value 255

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoAutorun" `
    -Value 1


# ---------------------------------------------------------------------
# UAC
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "EnableLUA" `
    -Value 1

Set-GPODword `
    -GPO $ComputerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "PromptOnSecureDesktop" `
    -Value 1


# =====================================================================
#
# GPO 2 - WINDOWS FIREWALL
#
# =====================================================================

$FirewallGPO = "SEC - Windows Firewall - Baseline"

Ensure-GPO `
    -Name $FirewallGPO `
    -Comment "Windows Defender Firewall security baseline."

Ensure-GPOLink `
    -Name $FirewallGPO `
    -Target $DomainDN


$FirewallProfiles = @(
    "DomainProfile",
    "PrivateProfile",
    "PublicProfile"
)

foreach ($Profile in $FirewallProfiles) {

    $FirewallKey =
        "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$Profile"

    # Enable Firewall

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $FirewallKey `
        -ValueName "EnableFirewall" `
        -Value 1

    # Block inbound by default

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $FirewallKey `
        -ValueName "DefaultInboundAction" `
        -Value 1

    # Allow outbound by default

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $FirewallKey `
        -ValueName "DefaultOutboundAction" `
        -Value 0

    # Allow local firewall rule merge

    Set-GPODword `
        -GPO $FirewallGPO `
        -Key $FirewallKey `
        -ValueName "AllowLocalPolicyMerge" `
        -Value 1
}


# =====================================================================
#
# GPO 3 - SERVER SECURITY BASELINE
#
# Currently linked to Domain Controllers OU.
#
# If you later create a Member Servers OU, link this same GPO there.
#
# =====================================================================

$ServerGPO = "SEC - Servers - Security Baseline"

Ensure-GPO `
    -Name $ServerGPO `
    -Comment "Security baseline for Windows Servers including LSASS protection, Defender and legal logon notice."

Ensure-GPOLink `
    -Name $ServerGPO `
    -Target $DCOU


# =====================================================================
# INTERACTIVE LOGON WARNING
# =====================================================================

Set-GPOString `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "LegalNoticeCaption" `
    -Value $LogonTitle

Set-GPOString `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "LegalNoticeText" `
    -Value $LogonMessage


# =====================================================================
# LSASS PROTECTED PROCESS
#
# RunAsPPL = 1
# Enables LSA protection using the supported Server 2016-era mechanism.
#
# REBOOT REQUIRED.
# =====================================================================

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RunAsPPL" `
    -Value 1


# ---------------------------------------------------------------------
# LSA PLUGIN AUDITING
#
# Helps identify authentication packages / plugins that may conflict
# with LSA protection.
# ---------------------------------------------------------------------

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" `
    -ValueName "AuditLevel" `
    -Value 8


# =====================================================================
# MICROSOFT DEFENDER HARDENING
# =====================================================================

# Real-Time Protection enabled

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableRealtimeMonitoring" `
    -Value 0


# Behavior monitoring enabled

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableBehaviorMonitoring" `
    -Value 0


# Scan downloaded files and attachments

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableIOAVProtection" `
    -Value 0


# Script scanning enabled

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableScriptScanning" `
    -Value 0


# Potentially unwanted applications

Set-GPODword `
    -GPO $ServerGPO `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -ValueName "PUAProtection" `
    -Value 1


# =====================================================================
# ATTACK SURFACE REDUCTION
# =====================================================================

$ASRKey =
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"


# ---------------------------------------------------------------------
# BLOCK CREDENTIAL STEALING FROM LSASS
#
# GUID:
# 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# BLOCK OFFICE APPLICATIONS FROM CREATING CHILD PROCESSES
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "d4f940ab-401b-4efc-aadc-ad5f3c50688a" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# BLOCK OFFICE APPLICATIONS FROM CREATING EXECUTABLE CONTENT
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "3b576869-a4ec-4529-8536-b80a7769e899" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# BLOCK OFFICE CODE INJECTION
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# BLOCK EXECUTABLE CONTENT FROM EMAIL / WEBMAIL
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# BLOCK OBFUSCATED SCRIPTS
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "5beb7efe-fd9a-4556-801d-275e5ffc04cc" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# ADVANCED RANSOMWARE PROTECTION
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "c1db55ab-c21a-4637-bb3f-a12568109d35" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# BLOCK UNTRUSTED / UNSIGNED PROCESSES FROM USB
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" `
    -Value "$ASRBlockMode"


# ---------------------------------------------------------------------
# PSEXEC / WMI PROCESS CREATION
#
# AUDIT initially because this can break administration systems,
# monitoring software, SCCM, automation, etc.
#
# Change $ASRAuditMode to 1 for this individual rule after testing.
# ---------------------------------------------------------------------

Set-GPOString `
    -GPO $ServerGPO `
    -Key $ASRKey `
    -ValueName "d1e49aac-8f56-4280-b9ba-993a6d77406c" `
    -Value "$ASRAuditMode"


# =====================================================================
#
# GPO 4 - DOMAIN CONTROLLER LDAP SECURITY
#
# =====================================================================

$DCGPO = "SEC - Domain Controllers - LDAP Security"

Ensure-GPO `
    -Name $DCGPO `
    -Comment "Domain Controller LDAP signing, channel binding and LDAP security auditing."

Ensure-GPOLink `
    -Name $DCGPO `
    -Target $DCOU


# =====================================================================
# LDAP INTERFACE EVENT LOGGING
# =====================================================================

Set-GPODword `
    -GPO $DCGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
    -ValueName "16 LDAP Interface Events" `
    -Value 2


# =====================================================================
# REQUIRE LDAP SERVER SIGNING
#
# 2 = Require signing
# =====================================================================

if ($RequireLDAPSigning) {

    Set-GPODword `
        -GPO $DCGPO `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -ValueName "LDAPServerIntegrity" `
        -Value 2
}


# =====================================================================
# LDAP CHANNEL BINDING
#
# 0 = Never
# 1 = When Supported
# 2 = Always
# =====================================================================

Set-GPODword `
    -GPO $DCGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -ValueName "LdapEnforceChannelBinding" `
    -Value $LDAPChannelBindingLevel


# =====================================================================
# COMPLETE
# =====================================================================

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "ACTIVE DIRECTORY SECURITY BASELINE COMPLETE" `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green


Write-Host ""
Write-Host "Created / Updated GPOs:" -ForegroundColor Cyan

Write-Host "  $ComputerGPO"
Write-Host "  $FirewallGPO"
Write-Host "  $ServerGPO"
Write-Host "  $DCGPO"


Write-Host ""
Write-Host "GPO Backup:" -ForegroundColor Cyan
Write-Host "  $BackupPath"


Write-Host ""
Write-Host "Important:" -ForegroundColor Yellow

Write-Host "  LSASS RunAsPPL requires a reboot."
Write-Host "  SMBv1 client disablement requires a reboot."
Write-Host "  LDAP signing is being REQUIRED."
Write-Host "  LDAP channel binding is set to WHEN SUPPORTED."
Write-Host "  PsExec/WMI ASR rule is AUDIT only."


Write-Host ""
Write-Host "Domain Controller GPO Links:" -ForegroundColor Cyan

(Get-GPInheritance -Target $DCOU).GpoLinks |
    Select-Object DisplayName,Enabled,Enforced,Order |
    Format-Table -AutoSize


Write-Host ""
Write-Host "Security GPOs:" -ForegroundColor Cyan

Get-GPO -All |
    Where-Object DisplayName -Like "SEC -*" |
    Select-Object DisplayName,Id,GpoStatus |
    Format-Table -AutoSize


Write-Host ""
Write-Host "NEXT:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Run:"
Write-Host "    gpupdate /force"
Write-Host ""
Write-Host "Then reboot the Domain Controller during an approved maintenance window."
Write-Host ""

Write-Host "After reboot verify:" -ForegroundColor Yellow

Write-Host @"

    Get-SmbServerConfiguration |
        Select EnableSMB1Protocol,RequireSecuritySignature

    Get-SmbClientConfiguration |
        Select RequireSecuritySignature

    Get-MpPreference |
        Select AttackSurfaceReductionRules_Ids,
               AttackSurfaceReductionRules_Actions

    Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name RunAsPPL

    Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
        -Name LDAPServerIntegrity,LdapEnforceChannelBinding

    gpresult /h C:\gpresult.html

"@

Write-Host "Done." -ForegroundColor Green