#requires -Version 5.1

<#
.SYNOPSIS
    Microsoft Purview Information Protection Scanner guided installation.

.DESCRIPTION
    This portion of the script:

    1. Verifies Windows PowerShell and administrator elevation.
    2. Defines the helper functions used by later sections.
    3. Detects an existing MPIP client installation.
    4. Opens the official MPIP client download page when needed.
    5. Pauses while the customer installs the GA EXE.
    6. Refreshes PSModulePath without closing PowerShell.
    7. Imports the PurviewInformationProtection module.
    8. Validates the scanner PowerShell commands.
    9. Stops immediately before the Configure Trusted Sites section.

.NOTES
    Run this script using Windows PowerShell 5.1 as Administrator.

    Do not run it using PowerShell 7. The Microsoft Purview Information
    Protection PowerShell module does not currently support PowerShell 7.

    Windows PowerShell ISE can be used for development, but the normal
    Windows PowerShell console is recommended for customer execution.
#>

[CmdletBinding()]
param(
    [switch]$SkipMPIPDownloadPage
)

# ==========================================
# Start Logging
# ==========================================

$LogFolder = "C:\Logs"

if (-not (Test-Path $LogFolder))
{
    New-Item `
        -Path $LogFolder `
        -ItemType Directory `
        -Force | Out-Null
}

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$TranscriptLog = Join-Path `
    $LogFolder `
    "PurviewScannerInstall-$TimeStamp.log"

Start-Transcript `
    -Path $TranscriptLog `
    -Append `
    -Force

Write-Host ""
Write-Host "Transcript Log:" -ForegroundColor Cyan
Write-Host $TranscriptLog -ForegroundColor Green
Write-Host ""

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Enable TLS 1.2 for later Microsoft service connections.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor `
    [Net.SecurityProtocolType]::Tls12


# ==========================================
# Helper Functions
# ==========================================

function Write-Step
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""
}


function Write-Ok
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[OK] $Message" -ForegroundColor Green
}


function Write-Info
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}


function Write-WarnMessage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}


function Test-IsAdministrator
{
    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $CurrentPrincipal = New-Object `
        Security.Principal.WindowsPrincipal($CurrentIdentity)

    return $CurrentPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


function Get-InstalledMPIPModule
{
    <#
        First checks normal PowerShell module discovery.

        If the current PowerShell process was opened before the MPIP
        installation, this function also checks the documented MPIP
        installation folders directly.
    #>

    $DiscoveredModule = Get-Module `
        -ListAvailable `
        -Name "PurviewInformationProtection" `
        -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if ($DiscoveredModule)
    {
        return $DiscoveredModule
    }

    $ModuleSearchRoots = @(
        "${env:ProgramFiles(x86)}\Microsoft Purview Information Protection",
        "$env:ProgramFiles\Microsoft Purview Information Protection",
        "${env:ProgramFiles(x86)}\PurviewInformationProtection",
        "$env:ProgramFiles\PurviewInformationProtection"
    ) |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } |
    Select-Object -Unique

    foreach ($SearchRoot in $ModuleSearchRoots)
    {
        if (-not (Test-Path -LiteralPath $SearchRoot))
        {
            continue
        }

        $ModuleManifest = Get-ChildItem `
            -LiteralPath $SearchRoot `
            -Filter "PurviewInformationProtection.psd1" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($ModuleManifest)
        {
            return $ModuleManifest
        }
    }

    return $null
}


function Update-CurrentPSModulePath
{
    <#
        A running PowerShell process does not automatically inherit
        environment-variable changes made after the process started.

        Rebuilding PSModulePath lets the existing session discover the
        module without closing PowerShell or restarting the script.
    #>

    $MachineModulePath = [Environment]::GetEnvironmentVariable(
        "PSModulePath",
        "Machine"
    )

    $UserModulePath = [Environment]::GetEnvironmentVariable(
        "PSModulePath",
        "User"
    )

    $ProcessModulePaths = @(
        $env:PSModulePath
        $MachineModulePath
        $UserModulePath
    ) |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } |
    ForEach-Object {
        $_ -split ";"
    } |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } |
    Select-Object -Unique

    $env:PSModulePath = $ProcessModulePaths -join ";"
}


function Import-MPIPModule
{
    Remove-Module `
        -Name "PurviewInformationProtection" `
        -Force `
        -ErrorAction SilentlyContinue

    Update-CurrentPSModulePath

    $ModuleResult = Get-InstalledMPIPModule

    if (-not $ModuleResult)
    {
        return $false
    }

    try
    {
        if ($ModuleResult -is [System.IO.FileInfo])
        {
            Import-Module `
                -Name $ModuleResult.FullName `
                -Force `
                -ErrorAction Stop
        }
        else
        {
            Import-Module `
                -Name "PurviewInformationProtection" `
                -Force `
                -ErrorAction Stop
        }

        return $true
    }
    catch
    {
        Write-WarnMessage "The MPIP module was found but could not be imported."
        Write-WarnMessage $_.Exception.Message
        return $false
    }
}


function Test-MPIPScannerCommands
{
    $RequiredCommands = @(
        "Install-Scanner",
        "Set-Authentication",
        "Get-ScanStatus",
        "Get-ScannerRepository",
        "Start-Scan"
    )

    $MissingCommands = @()

    foreach ($CommandName in $RequiredCommands)
    {
        $Command = Get-Command `
            -Name $CommandName `
            -ErrorAction SilentlyContinue

        if ($Command)
        {
            Write-Ok "Detected command: $CommandName"
        }
        else
        {
            $MissingCommands += $CommandName
            Write-WarnMessage "Command not detected: $CommandName"
        }
    }

    return $MissingCommands
}


function Show-MPIPInstallLogs
{
    $InstallLogs = Get-ChildItem `
        -Path $env:TEMP `
        -Filter "*MSIP.Setup.Main.msi.log" `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 3

    if ($InstallLogs)
    {
        Write-Host ""
        Write-Host "Recent MPIP installation logs:" -ForegroundColor Yellow

        foreach ($Log in $InstallLogs)
        {
            Write-Host "  $($Log.FullName)"
        }
    }
    else
    {
        Write-Host ""
        Write-Host "No recent MPIP installation log was found under:" `
            -ForegroundColor Yellow
        Write-Host "  $env:TEMP"
    }
}


# ==========================================
# Initial PowerShell Validation
# ==========================================

Clear-Host

Write-Step "Microsoft Purview Information Protection Scanner Setup"

Write-Host "This script will guide the customer through installing and"
Write-Host "configuring the Microsoft Purview Information Protection scanner."
Write-Host ""

if ($PSVersionTable.PSEdition -ne "Desktop")
{
    throw @"
This script must be run using Windows PowerShell 5.1.

Do not run it using PowerShell 7 or pwsh.exe.

Open Windows PowerShell as Administrator and run the script again.
"@
}

if ($PSVersionTable.PSVersion -lt [version]"5.1")
{
    throw @"
Windows PowerShell 5.1 or later is required.

Detected version: $($PSVersionTable.PSVersion)
"@
}

Write-Ok "Windows PowerShell version $($PSVersionTable.PSVersion) detected."

if (-not (Test-IsAdministrator))
{
    throw @"
This script must be run as Administrator.

Close this PowerShell window, open Windows PowerShell by using
Run as administrator, and then run the script again.
"@
}

Write-Ok "PowerShell is running with administrator privileges."

if ($Host.Name -match "ISE")
{
    Write-Host ""
    Write-WarnMessage "Windows PowerShell ISE was detected."
    Write-WarnMessage "The script can continue, but the standard Windows PowerShell"
    Write-WarnMessage "console is recommended for customer deployments."
}

Write-Host ""
Write-Info "Current Windows identity: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Info "Computer name: $env:COMPUTERNAME"


# ==========================================
# Detect Existing MPIP Client
# ==========================================

Write-Step "Checking for the MPIP Client"

$ExistingMPIPModule = Get-InstalledMPIPModule

if ($ExistingMPIPModule)
{
    Write-Ok "An existing MPIP PowerShell module installation was detected."

    $Imported = Import-MPIPModule

    if ($Imported)
    {
        $LoadedMPIPModule = Get-Module `
            -Name "PurviewInformationProtection" `
            -ErrorAction SilentlyContinue

        if ($LoadedMPIPModule)
        {
            Write-Ok "MPIP module version $($LoadedMPIPModule.Version) loaded."
        }
        else
        {
            Write-Ok "MPIP module imported successfully."
        }
    }
    else
    {
        Write-WarnMessage "The existing module could not be loaded."
        Write-WarnMessage "The interactive installation workflow will be offered."
        $ExistingMPIPModule = $null
    }
}


# ==========================================
# Install MPIP Client When Missing
# ==========================================

if (-not $ExistingMPIPModule)
{
    Write-Step "Microsoft Purview Information Protection Client Installation"

    Write-Host "The Microsoft Purview Information Protection client was not detected."
    Write-Host ""
    Write-Host "A browser window will now open to the official Microsoft"
    Write-Host "download page."
    Write-Host ""
    Write-Host "Download and install:" -ForegroundColor Green
    Write-Host ""
    Write-Host "   PurviewInfoProtection.exe" -ForegroundColor Green
    Write-Host ""
    Write-Host "Do not select:" -ForegroundColor Red
    Write-Host ""
    Write-Host "   PurviewInfoProtection_Preview.exe"
    Write-Host "   PurviewInfoProtection.msi"
    Write-Host "   PurviewInfoProtection_Preview.msi"
    Write-Host ""
    Write-Host "Complete the interactive installation."
    Write-Host ""
    Write-Host "When installation is complete:"
    Write-Host ""
    Write-Host "   1. Close the installation wizard."
    Write-Host "   2. Return to this PowerShell window."
    Write-Host "   3. Press ENTER to continue."
    Write-Host ""

    if (-not $SkipMPIPDownloadPage)
    {
        try
        {
            Start-Process "https://aka.ms/aipclient"
        }
        catch
        {
            Write-WarnMessage "The browser could not be opened automatically."
            Write-WarnMessage "Open the MPIP client download page manually."
        }
    }

    $MPIPDetected = $false

    Read-Host "Press ENTER after MPIP installation is complete"

Write-Host ""
Write-Host "Refreshing PowerShell module cache..." -ForegroundColor Yellow

$env:PSModulePath =
    [Environment]::GetEnvironmentVariable("PSModulePath","Machine") + ";" +
    [Environment]::GetEnvironmentVariable("PSModulePath","User")

$MPIPModule = Get-Module -ListAvailable PurviewInformationProtection

if (-not $MPIPModule)
{
    throw @"
The MPIP client was not detected.

If you just installed the MPIP client:

1. Close PowerShell.
2. Open a new Administrator PowerShell window.
3. Rerun this script.

The MPIP module may not be visible in PowerShell sessions
that were opened before installation.
"@
}

Write-Ok "MPIP client detected."
Write-Ok "Version: $($MPIPModule.Version)"
}

# ==========================================
# Configure Trusted Sites
# ==========================================

$ConfigureTrustedSites = Read-Host `
    "Add Microsoft authentication URLs to Trusted Sites? (Recommended) Y/N"

if ($ConfigureTrustedSites -match '^(Y|YES)$')

{
    # Add sites
}

Write-Step "Configuring Microsoft Authentication Trusted Sites"

$TrustedSites = @(
    "login.microsoftonline.com",
    "login.live.com",
    "aadcdn.msauth.net",
    "aadcdn.msftauth.net",
    "device.login.microsoftonline.com",
    "account.activedirectory.windowsazure.com"
    "https://login.microsoftonline.com"
    "https://aadcdn.msauth.net"
)

foreach ($Site in $TrustedSites)
{
    try
    {
        $DomainParts = $Site.Split('.')

        if ($DomainParts.Count -ge 2)
        {
            $Domain = "$($DomainParts[$DomainParts.Count - 2]).$($DomainParts[$DomainParts.Count - 1])"

            $SubDomain = ($DomainParts[0..($DomainParts.Count - 3)] -join '.')

            $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$Domain"

            if ($SubDomain)
            {
                $RegistryPath = Join-Path $RegistryPath $SubDomain
            }

            New-Item -Path $RegistryPath -Force | Out-Null

            New-ItemProperty `
                -Path $RegistryPath `
                -Name "https" `
                -Value 2 `
                -PropertyType DWord `
                -Force | Out-Null

            Write-Host "[OK] Added $Site" -ForegroundColor Green
        }
    }
    catch
    {
        Write-Warning "Failed to add $Site to Trusted Sites."
    }
}

Write-Host ""
Write-Host "Trusted Sites added successfully." -ForegroundColor Green
Write-Host ""

Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host ""
Write-Host "If the MPIP client login window was opened before Trusted Sites were added:"
Write-Host ""
Write-Host "1. Close the MPIP client login window"
Write-Host "2. Close File Explorer"
Write-Host "3. Reopen File Explorer"
Write-Host "4. Launch the MPIP client again"
Write-Host ""

# ==========================================
# Validate MPIP Authentication
# ==========================================

Write-Step "Validate MPIP Authentication"

$MPIPTestFile = Join-Path `
    $env:PUBLIC `
    "Documents\MPIP-Validation.txt"

@"
Microsoft Purview Information Protection validation file.

This file was created by the deployment script and
may be deleted after validation completes.
"@ | Set-Content `
    -Path $MPIPTestFile `
    -Encoding UTF8 `
    -Force

Write-Ok "Created MPIP validation file."

$Shell = New-Object -ComObject Shell.Application

$FolderPath = Split-Path $MPIPTestFile
$FileName   = Split-Path $MPIPTestFile -Leaf

$Folder = $Shell.Namespace($FolderPath)
$Item   = $Folder.ParseName($FileName)

Write-Host ""
Write-Host "Launching Microsoft Purview Information Protection File Labeler..." `
    -ForegroundColor Cyan
Write-Host ""

$Item.InvokeVerb("Microsoft.Azip.RightClick")

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "VALIDATION REQUIRED" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Sign in if prompted."
Write-Host "2. Confirm that sensitivity labels are displayed."
Write-Host "3. Close the Information Protection File Labeler."
Write-Host ""

$MPIPValidation = Read-Host `
"Did the Information Protection File Labeler open successfully and display labels? (Y/N)"

if ($MPIPValidation -notmatch '^(Y|YES)$')
{
    throw @"
MPIP validation was unsuccessful.

Resolve MPIP authentication issues before continuing.
"@
}

Write-Ok "MPIP File Labeler validated successfully."

# Create Scripts Folder

$ScriptFolder = "C:\Scripts"

if (-not (Test-Path $ScriptFolder))
{
    New-Item `
        -Path $ScriptFolder `
        -ItemType Directory `
        -Force | Out-Null
}

# Create MPIP Launcher Script

$LauncherScript = @'
$TestFile = "$env:TEMP\MPIP-Launcher.txt"

if (-not (Test-Path $TestFile))
{
    "Microsoft Purview Information Protection Launcher" |
        Set-Content $TestFile
}

$Shell = New-Object -ComObject Shell.Application

$FolderPath = Split-Path $TestFile
$FileName   = Split-Path $TestFile -Leaf

$Folder = $Shell.Namespace($FolderPath)
$Item   = $Folder.ParseName($FileName)

$Item.InvokeVerb("Microsoft.Azip.RightClick")
'@

$LauncherScript |
    Set-Content `
    -Path "C:\Scripts\Launch-MPIP.ps1" `
    -Encoding UTF8

# Create Desktop Shortcut

$Desktop = [Environment]::GetFolderPath("Desktop")

$WshShell = New-Object -ComObject WScript.Shell

$Shortcut = $WshShell.CreateShortcut(
    "$Desktop\Microsoft Purview Information Protection Client.lnk"
)

$Shortcut.TargetPath = "powershell.exe"

$Shortcut.Arguments =
'-ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Scripts\Launch-MPIP.ps1"'

$Shortcut.IconLocation =
"C:\Program Files (x86)\Microsoft Purview Information Protection\MSIP.Viewer.exe,0"

$Shortcut.Save()

Write-Host ""
Write-Host "MPIP shortcut created successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Desktop shortcut:"
Write-Host "Microsoft Purview Information Protection"

# ==========================================
# Install Scanner
# ==========================================


Write-Step "Install Microsoft Purview Information Protection Scanner"

Write-Host ""
Write-Host "The scanner installation requires:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  • SQL Server Instance"
Write-Host "  • Scanner Cluster Name"
Write-Host ""
Write-Host "Examples:"
Write-Host ""
Write-Host "  For a default SQL Instance : SQLSERVER1"
Write-Host "  For a named SQL Instance : SQLSERVER1\SCANNER"
Write-Host "  For SQL EXPRESS : SQLSERVER1\SQLEXPRESS"
Write-Host "  Cluster Name : CentralUS"
Write-Host ""

$SQLInstance = Read-Host "Enter SQL Server Instance"

$ClusterName = Read-Host "Enter Scanner Cluster Name"

Write-Host ""
Write-Host "SQL Instance : $SQLInstance"
Write-Host "Cluster Name : $ClusterName"
Write-Host ""

$Confirm = Read-Host "Continue? (Y/N)"

if ($Confirm -notmatch '^(Y|YES)$')
{
    throw "Scanner installation cancelled by user."
}

Write-Host ""
Write-Host "Running Install-Scanner..." -ForegroundColor Cyan
Write-Host ""

Install-Scanner `
    -SqlServerInstance $SQLInstance `
    -Cluster $ClusterName

    Get-Service `
    "Microsoft Purview Information Protection Scanner" `
    -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Scanner installation command completed." `
    -ForegroundColor Green

# ==========================================
# Create Scanner Entra App Registration
# ==========================================

Write-Host ""
Write-Host "PREREQUISITE CHECK" -ForegroundColor Yellow
Write-Host ""
Write-Host "Does the account running this script have permission to:"
Write-Host ""
Write-Host "  - Create Application Registrations"
Write-Host "  - Create Client Secrets"
Write-Host "  - Grant Admin Consent"
Write-Host ""

$CanCreateAppReg = Read-Host `
"Can this account create App Registrations and Grant Admin Consent? (Y/N)"

if ($CanCreateAppReg -notmatch "^(Y|YES)$")
{
    throw @"

An Entra Administrator must complete the App Registration
requirements before scanner authentication can be configured.

Required outputs:

- Application (Client) ID
- Tenant ID
- Client Secret

After those values are available, rerun the script.

"@
}
Write-Host ""
Write-Host "OPTIONAL CONFIGURATION" -ForegroundColor Yellow
Write-Host ""
Write-Host "Should the scanner be configured for RMS Super User access?"
Write-Host ""
Write-Host "Use this if the scanner must:"
Write-Host ""
Write-Host "  - Inspect protected files"
Write-Host "  - Relabel protected files"
Write-Host "  - Reprotect files it does not own"
Write-Host ""
Write-Host "This requires additional Rights Management configuration."
Write-Host ""


function Write-Step
{
    param([string]$Message)

    Write-Host ""
    Write-Host "===================================================" `
        -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "===================================================" `
        -ForegroundColor Cyan
    Write-Host ""
}

function Write-Ok
{
    param([string]$Message)

    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnMessage
{
    param([string]$Message)

    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

Write-Step "Create Scanner Microsoft Entra App Registration"

$ScannerAppName = "InformationProtectionScanner"

Write-Host "This section will:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. Connect to Microsoft Graph"
Write-Host "  2. Create or reuse $ScannerAppName"
Write-Host "  3. Configure http://localhost as a Web redirect URI"
Write-Host "  4. Add the required application permissions"
Write-Host "  5. Attempt to grant tenant-wide admin consent"
Write-Host "  6. Create a client secret that expires in one year"
Write-Host "  7. Run Set-Authentication"
Write-Host ""

Write-Host ""
Write-Host "IMPORTANT" -ForegroundColor Yellow
Write-Host ""
Write-Host "When prompted with:"
Write-Host ""
Write-Host '  "Sign in to all apps and websites on this device?"'
Write-Host ""
Write-Host "Select:"
Write-Host ""
Write-Host '  "No, sign in to this app only"'
Write-Host ""

[void](Read-Host "Press ENTER to continue")


# ==========================================
# Validate Microsoft Graph Module
# ==========================================

Write-Host ""
Write-Host "Checking Microsoft Graph PowerShell..." `
    -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication))
{
    Write-Host ""
    Write-Host "Microsoft.Graph.Authentication is not installed."
    Write-Host "Installing the module..." -ForegroundColor Yellow
    Write-Host ""

    try
    {
        Install-Module `
            -Name Microsoft.Graph.Authentication `
            -Scope AllUsers `
            -Force `
            -AllowClobber `
            -ErrorAction Stop
    }
    catch
    {
        throw @"
The Microsoft.Graph.Authentication module could not be installed.

Error:
$($_.Exception.Message)
"@
    }
}

Import-Module Microsoft.Graph.Authentication -Force

Write-Ok "Microsoft Graph Authentication module loaded."


# ==========================================
# Connect to Microsoft Graph
# ==========================================

$GraphScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.Read.All"
)

Write-Host ""
Write-Host "A Microsoft sign-in window will open." `
    -ForegroundColor Yellow
Write-Host ""

try
{
    Connect-MgGraph `
        -Scopes $GraphScopes `
        -NoWelcome `
        -ErrorAction Stop
}
catch
{
    throw @"
Microsoft Graph authentication failed.

Error:
$($_.Exception.Message)
"@
}

$GraphContext = Get-MgContext

if (-not $GraphContext.TenantId)
{
    throw "Microsoft Graph did not return a tenant ID."
}

$TenantId = [string]$GraphContext.TenantId

Write-Ok "Connected to Microsoft Graph."
Write-Ok "Tenant ID: $TenantId"


# ==========================================
# Helper: Find Service Principal by App Role
# ==========================================

function Find-ServicePrincipalByAppRoles
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$RequiredRoleValues,

        [string[]]$PreferredDisplayNames
    )

    foreach ($DisplayName in $PreferredDisplayNames)
    {
        $EscapedDisplayName = $DisplayName.Replace("'", "''")

        $Uri = (
            "https://graph.microsoft.com/v1.0/servicePrincipals" +
            "?`$filter=displayName eq '$EscapedDisplayName'" +
            "&`$select=id,appId,displayName,appRoles"
        )

        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $Uri

        foreach ($ServicePrincipal in @($Response.value))
        {
            $AvailableRoles = @(
                $ServicePrincipal.appRoles |
                ForEach-Object { $_.value }
            )

            $MissingRoles = @(
                $RequiredRoleValues |
                Where-Object { $_ -notin $AvailableRoles }
            )

            if ($MissingRoles.Count -eq 0)
            {
                return $ServicePrincipal
            }
        }
    }

    # Fallback: Search tenant service principals by required role values.
    $NextUri = (
        "https://graph.microsoft.com/v1.0/servicePrincipals" +
        "?`$select=id,appId,displayName,appRoles&`$top=999"
    )

    do
    {
        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $NextUri

        foreach ($ServicePrincipal in @($Response.value))
        {
            $AvailableRoles = @(
                $ServicePrincipal.appRoles |
                ForEach-Object { $_.value }
            )

            $MissingRoles = @(
                $RequiredRoleValues |
                Where-Object { $_ -notin $AvailableRoles }
            )

            if ($MissingRoles.Count -eq 0)
            {
                return $ServicePrincipal
            }
        }

        $NextUri = $Response.'@odata.nextLink'
    }
    while ($NextUri)

    throw (
        "Could not locate a Microsoft service principal exposing: " +
        ($RequiredRoleValues -join ", ")
    )
}


# ==========================================
# Helper: Build Azure RMS Role List
# ==========================================

function Get-ScannerRmsAppRoles
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$IncludeSuperUser
    )

    $RmsAppRoles = @(
        "Content.DelegatedReader",
        "Content.DelegatedWriter"
    )

    if ($IncludeSuperUser)
    {
        $RmsAppRoles += "Content.SuperUser"

        Write-Ok "Optional RMS permission selected: Content.SuperUser"
    }
    else
    {
        Write-Host ""
        Write-Host "Content.SuperUser was not selected." `
            -ForegroundColor Yellow
        Write-Host "Continuing with the standard scanner permissions."
    }

    return $RmsAppRoles
}

$EnableSuperUser = Read-Host `
"Configure Super User support? (Y/N)"

$IncludeContentSuperUser = (
    $EnableSuperUser -match "^(Y|YES)$"
)

$RmsAppRoleValues = Get-ScannerRmsAppRoles `
    -IncludeSuperUser $IncludeContentSuperUser

Write-Host ""
Write-Host "Azure Rights Management application permissions:" `
    -ForegroundColor Cyan

foreach ($RoleValue in $RmsAppRoleValues)
{
    Write-Host "  - $RoleValue"
}

Write-Host ""
# ==========================================
# Helper: Build Required Resource Access
# ==========================================

function New-RequiredResourceAccessEntry
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $ResourceServicePrincipal,

        [Parameter(Mandatory)]
        [string[]]$RoleValues
    )

    $ResourceAccess = @()

    foreach ($RoleValue in $RoleValues)
    {
        $AppRole = @(
            $ResourceServicePrincipal.appRoles |
            Where-Object {
                $_.value -eq $RoleValue -and
                $_.allowedMemberTypes -contains "Application"
            }
        ) | Select-Object -First 1

        if (-not $AppRole)
        {
            throw (
                "Application role '$RoleValue' was not found on " +
                "'$($ResourceServicePrincipal.displayName)'."
            )
        }

        $ResourceAccess += @{
            id   = $AppRole.id
            type = "Role"
        }
    }

    return @{
        resourceAppId  = $ResourceServicePrincipal.appId
        resourceAccess = $ResourceAccess
    }
}


# ==========================================
# Helper: Grant Application Role
# ==========================================

function Grant-ApplicationRole
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClientServicePrincipalId,

        [Parameter(Mandatory)]
        $ResourceServicePrincipal,

        [Parameter(Mandatory)]
        [string]$RoleValue
    )

    $AppRole = @(
        $ResourceServicePrincipal.appRoles |
        Where-Object {
            $_.value -eq $RoleValue -and
            $_.allowedMemberTypes -contains "Application"
        }
    ) | Select-Object -First 1

    if (-not $AppRole)
    {
        throw "Application role '$RoleValue' was not found."
    }

    $ExistingAssignments = Invoke-MgGraphRequest `
        -Method GET `
        -Uri (
            "https://graph.microsoft.com/v1.0/servicePrincipals/" +
            "$ClientServicePrincipalId/appRoleAssignments"
        )

    $ExistingAssignment = @(
        $ExistingAssignments.value |
        Where-Object {
            $_.resourceId -eq $ResourceServicePrincipal.id -and
            $_.appRoleId -eq $AppRole.id
        }
    )

    if ($ExistingAssignment.Count -eq 0)
    {
        $AssignmentBody = @{
            principalId = $ClientServicePrincipalId
            resourceId  = $ResourceServicePrincipal.id
            appRoleId   = $AppRole.id
        } | ConvertTo-Json

        Invoke-MgGraphRequest `
            -Method POST `
            -Uri (
                "https://graph.microsoft.com/v1.0/servicePrincipals/" +
                "$ClientServicePrincipalId/appRoleAssignments"
            ) `
            -Body $AssignmentBody `
            -ContentType "application/json" |
            Out-Null
    }

    Write-Ok (
        "Permission granted: " +
        "$($ResourceServicePrincipal.displayName) / $RoleValue"
    )
}


# ==========================================
# Find Required Microsoft Service Principals
# ==========================================

Write-Host ""
Write-Host "Locating required Microsoft service principals..." `
    -ForegroundColor Cyan

$RmsServicePrincipal = Find-ServicePrincipalByAppRoles `
    -RequiredRoleValues $RmsAppRoleValues `
    -PreferredDisplayNames @(
        "Azure Rights Management Services",
        "Azure Rights Management Service"
    )

Write-Ok (
    "Located: $($RmsServicePrincipal.displayName)"
)

$MipSyncServicePrincipal = Find-ServicePrincipalByAppRoles `
    -RequiredRoleValues @(
        "UnifiedPolicy.Tenant.Read"
    ) `
    -PreferredDisplayNames @(
        "Microsoft Information Protection Sync Service"
    )

Write-Ok (
    "Located: $($MipSyncServicePrincipal.displayName)"
)


# ==========================================
# Create or Reuse Scanner Application
# ==========================================

$EscapedAppName = $ScannerAppName.Replace("'", "''")

$ExistingApps = Invoke-MgGraphRequest `
    -Method GET `
    -Uri (
        "https://graph.microsoft.com/v1.0/applications" +
        "?`$filter=displayName eq '$EscapedAppName'" +
        "&`$select=id,appId,displayName,web,requiredResourceAccess"
    )

$ScannerApplication = @($ExistingApps.value) |
    Select-Object -First 1

if ($ScannerApplication)
{
    Write-Host ""
    Write-WarnMessage (
        "An application named '$ScannerAppName' already exists."
    )

    $ReuseApplication = Read-Host `
        "Reuse the existing application? (Y/N)"

    if ($ReuseApplication -notmatch "^(Y|YES)$")
    {
        throw (
            "Application creation stopped to avoid creating a duplicate."
        )
    }

    Write-Ok (
        "Reusing application ID: $($ScannerApplication.appId)"
    )
}
else
{
    $ApplicationBody = @{
        displayName    = $ScannerAppName
        signInAudience = "AzureADMyOrg"
        web            = @{
            redirectUris = @(
                "http://localhost"
            )
        }
    } | ConvertTo-Json -Depth 8

    $ScannerApplication = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/applications" `
        -Body $ApplicationBody `
        -ContentType "application/json"

    Write-Ok "Created application: $ScannerAppName"
    Write-Ok "Application ID: $($ScannerApplication.appId)"
}

$ApplicationId = [string]$ScannerApplication.appId


# ==========================================
# Configure Required API Permissions
# ==========================================

$RequiredResourceAccess = @(
    (New-RequiredResourceAccessEntry `
        -ResourceServicePrincipal $RmsServicePrincipal `
        -RoleValues $RmsAppRoleValues
    ),

    (New-RequiredResourceAccessEntry `
        -ResourceServicePrincipal $MipSyncServicePrincipal `
        -RoleValues @(
            "UnifiedPolicy.Tenant.Read"
        )
    )
)

$PermissionBody = @{
    web = @{
        redirectUris = @(
            "http://localhost"
        )
    }
    requiredResourceAccess = $RequiredResourceAccess
} | ConvertTo-Json -Depth 12

Invoke-MgGraphRequest `
    -Method PATCH `
    -Uri (
        "https://graph.microsoft.com/v1.0/applications/" +
        $ScannerApplication.id
    ) `
    -Body $PermissionBody `
    -ContentType "application/json" |
    Out-Null

Write-Ok "Required API permissions added to the application."


# ==========================================
# Create or Locate Enterprise Application
# ==========================================

$EnterpriseAppResponse = Invoke-MgGraphRequest `
    -Method GET `
    -Uri (
        "https://graph.microsoft.com/v1.0/servicePrincipals" +
        "?`$filter=appId eq '$ApplicationId'" +
        "&`$select=id,appId,displayName"
    )

$ScannerEnterpriseApp = @($EnterpriseAppResponse.value) |
    Select-Object -First 1

if (-not $ScannerEnterpriseApp)
{
    $EnterpriseAppBody = @{
        appId = $ApplicationId
    } | ConvertTo-Json

    $ScannerEnterpriseApp = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
        -Body $EnterpriseAppBody `
        -ContentType "application/json"

    Write-Ok "Created the corresponding enterprise application."
}
else
{
    Write-Ok "Corresponding enterprise application detected."
}


# ==========================================
# Grant Admin Consent
# ==========================================

Write-Host ""
Write-Host "Attempting to grant admin consent..." `
    -ForegroundColor Cyan

try
{
    foreach ($RmsRoleValue in $RmsAppRoleValues)
    {
        Grant-ApplicationRole `
            -ClientServicePrincipalId $ScannerEnterpriseApp.id `
            -ResourceServicePrincipal $RmsServicePrincipal `
            -RoleValue $RmsRoleValue
    }

    Grant-ApplicationRole `
        -ClientServicePrincipalId $ScannerEnterpriseApp.id `
        -ResourceServicePrincipal $MipSyncServicePrincipal `
        -RoleValue "UnifiedPolicy.Tenant.Read"

    Write-Ok "All selected application permissions have admin consent."
}
catch
{
    Write-Host ""
    Write-WarnMessage "Automatic admin consent did not complete."
    Write-WarnMessage $_.Exception.Message
    Write-Host ""
    Write-Host "The Microsoft Entra admin center will open."
    Write-Host ""
    Write-Host "Open the application and select:"
    Write-Host ""
    Write-Host "  API permissions"
    Write-Host "  Grant admin consent"
    Write-Host ""

    Start-Process (
        "https://entra.microsoft.com/#view/" +
        "Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/" +
        "~/CallAnAPI/appId/$ApplicationId/isMSAApp~/false"
    )

    Read-Host `
        "Admin consent in Entra, then press ENTER to retry"

    foreach ($RmsRoleValue in $RmsAppRoleValues)
    {
        Grant-ApplicationRole `
            -ClientServicePrincipalId $ScannerEnterpriseApp.id `
            -ResourceServicePrincipal $RmsServicePrincipal `
            -RoleValue $RmsRoleValue
    }

    Grant-ApplicationRole `
        -ClientServicePrincipalId $ScannerEnterpriseApp.id `
        -ResourceServicePrincipal $MipSyncServicePrincipal `
        -RoleValue "UnifiedPolicy.Tenant.Read"

    Write-Ok "Required admin consent verified."
}

if ($IncludeContentSuperUser)
{
    Write-Host ""
    Write-Host "ADDITIONAL RMS CONFIGURATION REQUIRED" `
        -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Content.SuperUser was added to the app registration."
    Write-Host ""
    Write-Host "The Azure Rights Management super-user feature must also"
    Write-Host "be enabled, and the delegated scanner account must be"
    Write-Host "assigned as an RMS super user."
    Write-Host ""
    Write-Host "This is separate from app-registration admin consent."
    Write-Host ""
}

# ==========================================
# Create One-Year Client Secret
# ==========================================

Write-Host ""
Write-Host "Creating one-year client secret..." `
    -ForegroundColor Cyan

$SecretExpiration = (Get-Date).ToUniversalTime().AddYears(1)

$SecretBody = @{
    passwordCredential = @{
        displayName = (
            "MPIP scanner secret created " +
            (Get-Date -Format "yyyy-MM-dd")
        )
        endDateTime = $SecretExpiration.ToString("o")
    }
} | ConvertTo-Json -Depth 5

$SecretResponse = Invoke-MgGraphRequest `
    -Method POST `
    -Uri (
        "https://graph.microsoft.com/v1.0/applications/" +
        "$($ScannerApplication.id)/addPassword"
    ) `
    -Body $SecretBody `
    -ContentType "application/json"

$ClientSecret = [string]$SecretResponse.secretText

if ([string]::IsNullOrWhiteSpace($ClientSecret))
{
    throw "Microsoft Graph did not return the client secret value."
}

Write-Host ""
Write-Host "CLIENT SECRET CREATED" -ForegroundColor Yellow
Write-Host ""
Write-Host "Store this secret in the customer's approved password vault."
Write-Host ""
Write-Host "Application ID : $ApplicationId"
Write-Host "Tenant ID      : $TenantId"
Write-Host "Secret expires : $($SecretExpiration.ToString('u'))"
Write-Host "Secret value   : $ClientSecret" -ForegroundColor Yellow
Write-Host ""

[void](Read-Host `
    "After securely storing the secret, press ENTER to continue")

# ==========================================
# Configure Scanner Authentication
# ==========================================

Write-Step "Configure Scanner Authentication"

# Confirm that required values from the app-registration section exist.
$RequiredAuthenticationVariables = @{
    ApplicationId = $ApplicationId
    TenantId      = $TenantId
    ClientSecret  = $ClientSecret
}

foreach ($RequiredVariable in $RequiredAuthenticationVariables.GetEnumerator())
{
    if ([string]::IsNullOrWhiteSpace([string]$RequiredVariable.Value))
    {
        throw (
            "Required authentication value is missing: " +
            $RequiredVariable.Key
        )
    }
}

# Collect the Windows identity used by the MIPScanner service.
$ScannerWindowsAccount = Read-Host `
    "Enter the scanner service account in DOMAIN\username format"

if ($ScannerWindowsAccount -notmatch "^[^\\]+\\[^\\]+$")
{
    throw @"
The scanner service account must use DOMAIN\username format.

Examples:
CONTOSO\svc_purviewscanner
CONTOSO\POCaaS

Do not enter the email address or Entra UPN here.
"@
}

# Collect the synchronized Microsoft Entra identity.
$DelegatedUser = Read-Host `
    "Enter the scanner account Entra UPN, such as scanner@contoso.com"

if ($DelegatedUser -notmatch "^[^@\s]+@[^@\s]+\.[^@\s]+$")
{
    throw @"
The delegated scanner identity must use UPN format.

Example:
scanner@contoso.com
"@
}

Write-Host ""
Write-Host "Scanner authentication information:" `
    -ForegroundColor Cyan
Write-Host ""
Write-Host "Windows service account : $ScannerWindowsAccount"
Write-Host "Entra delegated user    : $DelegatedUser"
Write-Host "Application ID          : $ApplicationId"
Write-Host "Tenant ID               : $TenantId"
Write-Host ""
Write-Host "The client secret will not be displayed again or written" 
Write-Host "to the installation summary." 
Write-Host ""

# Determine whether the script is already running as the scanner identity.
$CurrentWindowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

Write-Host "Current Windows identity : $CurrentWindowsIdentity"
Write-Host ""

$UseOnBehalfOf = $CurrentWindowsIdentity -ine $ScannerWindowsAccount

if ($UseOnBehalfOf)
{
    Write-Host "The current Windows identity is different from the" `
        -ForegroundColor Yellow
    Write-Host "scanner service account." `
        -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Set-Authentication will use the -OnBehalfOf parameter." `
        -ForegroundColor Yellow
    Write-Host ""
    Write-Host "When prompted, enter the password for:" 
    Write-Host ""
    Write-Host "  $ScannerWindowsAccount" -ForegroundColor Green
    Write-Host ""

    $ScannerCredential = Get-Credential `
        -UserName $ScannerWindowsAccount `
        -Message "Enter the scanner service account password"

    if (-not $ScannerCredential)
    {
        throw "Scanner service account credentials were not provided."
    }
}
else
{
    Write-Ok (
        "The script is running as the scanner service account. " +
        "OnBehalfOf is not required."
    )
}

Write-Host ""
Write-Host "Running Set-Authentication..." `
    -ForegroundColor Cyan
Write-Host ""

try
{
    if ($UseOnBehalfOf)
    {
        Set-Authentication `
            -AppId $ApplicationId `
            -AppSecret $ClientSecret `
            -TenantId $TenantId `
            -DelegatedUser $DelegatedUser `
            -OnBehalfOf $ScannerCredential `
            -ErrorAction Stop
    }
    else
    {
        Set-Authentication `
            -AppId $ApplicationId `
            -AppSecret $ClientSecret `
            -TenantId $TenantId `
            -DelegatedUser $DelegatedUser `
            -ErrorAction Stop
    }

    Write-Ok "Set-Authentication completed successfully."
}
catch
{
    throw @"
Set-Authentication failed.

Verify the following:

1. The Application ID is correct.
2. The Tenant ID is correct.
3. The client secret VALUE was used, not the secret ID.
4. Admin consent was granted for all required application permissions.
5. The delegated Entra user has a published sensitivity-label policy.
6. The Windows service account was entered as DOMAIN\username.
7. PowerShell is running as Administrator.

Error:
$($_.Exception.Message)
"@
}
finally
{
    $ScannerCredential = $null
}

# ==========================================
# Configure Azure RMS Super User
# ==========================================

if ($IncludeContentSuperUser)
{
    Write-Step "Configure Azure Rights Management Super User"

    Write-Host "Content.SuperUser was added to the scanner app registration."
    Write-Host ""
    Write-Host "The script will now:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Connect to the Azure Rights Management service"
    Write-Host "  2. Check the RMS Super User feature status"
    Write-Host "  3. Enable the feature if it is disabled"
    Write-Host "  4. Add the scanner delegated user as an RMS Super User"
    Write-Host ""

    Write-Host "IMPORTANT:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "A separate administrator sign-in window may appear."
    Write-Host "Use an account authorized to administer Azure Rights Management."
    Write-Host ""

    Read-Host "Press ENTER to continue"

    # ==========================================
    # Install or Validate AIPService Module
    # ==========================================

    Write-Host ""
    Write-Host "Checking for the AIPService PowerShell module..." `
        -ForegroundColor Cyan

    $AIPServiceModule = Get-Module `
        -ListAvailable `
        -Name "AIPService" `
        -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $AIPServiceModule)
    {
        Write-Host ""
        Write-Host "AIPService is not installed." `
            -ForegroundColor Yellow
        Write-Host "Installing AIPService from the PowerShell Gallery..."
        Write-Host ""

        try
        {
            if (-not (
                Get-PackageProvider `
                    -Name "NuGet" `
                    -ErrorAction SilentlyContinue
            ))
            {
                Install-PackageProvider `
                    -Name "NuGet" `
                    -Force `
                    -Scope AllUsers `
                    -ErrorAction Stop |
                    Out-Null
            }

            Install-Module `
                -Name "AIPService" `
                -Scope AllUsers `
                -Force `
                -AllowClobber `
                -ErrorAction Stop
        }
        catch
        {
            throw @"
The AIPService PowerShell module could not be installed.

Error:
$($_.Exception.Message)
"@
        }
    }

    try
    {
        Import-Module `
            -Name "AIPService" `
            -Force `
            -ErrorAction Stop

        $LoadedAIPServiceModule = Get-Module `
            -Name "AIPService" `
            -ErrorAction Stop

        Write-Ok (
            "AIPService module version " +
            "$($LoadedAIPServiceModule.Version) loaded."
        )
    }
    catch
    {
        throw @"
The AIPService PowerShell module could not be imported.

Error:
$($_.Exception.Message)
"@
    }

    # ==========================================
    # Validate Required AIPService Commands
    # ==========================================

    $RequiredAIPServiceCommands = @(
        "Connect-AipService",
        "Get-AipServiceSuperUserFeature",
        "Enable-AipServiceSuperUserFeature",
        "Get-AipServiceSuperUser",
        "Add-AipServiceSuperUser"
    )

    foreach ($CommandName in $RequiredAIPServiceCommands)
    {
        if (-not (
            Get-Command `
                -Name $CommandName `
                -ErrorAction SilentlyContinue
        ))
        {
            throw (
                "Required AIPService command not found: " +
                $CommandName
            )
        }
    }

    Write-Ok "Required AIPService commands are available."

    # ==========================================
    # Connect to Azure Rights Management
    # ==========================================

    Write-Host ""
    Write-Host "Connecting to Azure Rights Management..." `
        -ForegroundColor Cyan
    Write-Host ""

    try
    {
        Connect-AipService -ErrorAction Stop

        Write-Ok "Connected to Azure Rights Management."
    }
    catch
    {
        throw @"
Could not connect to Azure Rights Management.

Verify the signing-in account is authorized to administer
the Azure Rights Management service.

Error:
$($_.Exception.Message)
"@
    }

    # ==========================================
    # Enable RMS Super User Feature
    # ==========================================

    try
    {
        $SuperUserFeatureStatus = Get-AipServiceSuperUserFeature `
                -ErrorAction Stop
        

        Write-Host ""
        Write-Host "Current RMS Super User feature status:" `
            -ForegroundColor Cyan
        Write-Host "  $SuperUserFeatureStatus"
        Write-Host ""

        if ($SuperUserFeatureStatus -notmatch "^Enabled$")
        {
            Write-Host "Enabling the RMS Super User feature..." `
                -ForegroundColor Yellow

            Enable-AipServiceSuperUserFeature `
                -ErrorAction Stop

            $SuperUserFeatureStatus = Get-AipServiceSuperUserFeature `
                    -ErrorAction Stop
            

            if ($SuperUserFeatureStatus -notmatch "^Enabled$")
            {
                throw (
                    "The RMS Super User feature did not return " +
                    "an Enabled status."
                )
            }

            Write-Ok "RMS Super User feature enabled."
        }
        else
        {
            Write-Ok "RMS Super User feature is already enabled."
        }
    }
    catch
    {
        throw @"
The RMS Super User feature could not be validated or enabled.

Error:
$($_.Exception.Message)
"@
    }

    # ==========================================
    # Assign Scanner Account as RMS Super User
    # ==========================================

    Write-Host ""
    Write-Host "Checking RMS Super User membership for:" `
        -ForegroundColor Cyan
    Write-Host "  $DelegatedUser"
    Write-Host ""

    try
    {
        $CurrentSuperUsers = @(
            Get-AipServiceSuperUser `
                -ErrorAction Stop
        )

        # Convert each result to text because output formatting can vary
        # between AIPService module versions.
        $ExistingSuperUser = $CurrentSuperUsers |
            Where-Object {
                ($_ | Out-String) -match
                    [regex]::Escape($DelegatedUser)
            } |
            Select-Object -First 1

        if ($ExistingSuperUser)
        {
            Write-Ok (
                "$DelegatedUser is already assigned as an " +
                "RMS Super User."
            )
        }
        else
        {
            Write-Host "Adding the scanner account as an RMS Super User..." `
                -ForegroundColor Yellow

            Add-AipServiceSuperUser `
                -EmailAddress $DelegatedUser `
                -ErrorAction Stop

            Write-Ok (
                "$DelegatedUser was added as an RMS Super User."
            )
        }

        # Final verification
        $VerifiedSuperUsers = @(
            Get-AipServiceSuperUser `
                -ErrorAction Stop
        )

        $VerifiedScannerSuperUser = $VerifiedSuperUsers |
            Where-Object {
                ($_ | Out-String) -match
                    [regex]::Escape($DelegatedUser)
            } |
            Select-Object -First 1

        if (-not $VerifiedScannerSuperUser)
        {
            throw (
                "$DelegatedUser was not found in the RMS " +
                "Super User list after assignment."
            )
        }

        Write-Ok "RMS Super User assignment verified."
    }
    catch
    {
        throw @"
The scanner account could not be added or verified as an
Azure Rights Management Super User.

atedUser contains the scanner account's
primary email address or user principal name. Email aliases
are not evaluated for this assignment.

Error:
$($_.Exception.Message)
"@
    }

    Write-Host ""
    Write-Ok "Optional RMS Super User configuration completed."
}
else
{
    Write-Host ""
    Write-Host "Skipping optional RMS Super User configuration." `
        -ForegroundColor Yellow
}

# ==========================================
# Restart Scanner Service
# ==========================================

Write-Host ""
Write-Host "Restarting the scanner service..." `
    -ForegroundColor Cyan

Restart-Service `
    -Name "MIPScanner" `
    -Force `
    -ErrorAction Stop

Start-Sleep -Seconds 10

$ScannerService = Get-Service `
    -Name "MIPScanner" `
    -ErrorAction Stop

if ($ScannerService.Status -ne "Running")
{
    throw "The MIPScanner service did not return to the Running state."
}

Write-Ok "Scanner service restarted successfully."

Write-Host ""
Write-Host "Creating desktop shortcut to Scanner Folder..." -ForegroundColor Cyan

$ScannerPath = Join-Path $env:LOCALAPPDATA "Microsoft\MSIP\Scanner"

if (-not (Test-Path $ScannerPath))
{
    New-Item -Path $ScannerPath -ItemType Directory -Force | Out-Null
}

$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "Purview Scanner Folder.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

$Shortcut.TargetPath = $ScannerPath
$Shortcut.WorkingDirectory = $ScannerPath
$Shortcut.Description = "Microsoft Purview Scanner Working Folder"


Write-Ok "Scanner folder shortcut created on desktop."

Stop-Transcript