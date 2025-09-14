<#
.SYNOPSIS
    An automated, GUI-based maintenance and repair tool for Windows 11.

.DESCRIPTION
    A comprehensive, user-friendly tool that automates system maintenance. This enhanced version features:
    - Robust Error Handling: Every major operation is wrapped in Try/Catch blocks for graceful failure.
    - External Configuration: Key settings are managed in an external 'config.json' file for easy customization without editing the script.
    - Improved UX: Includes a responsive status label, a Cancel button, and user control over the final restart.
    - Portability: Designed to be self-contained by bundling necessary PowerShell modules, removing the need for live internet installation.
    - Resilient Tool Detection: Intelligently searches for manufacturer update utilities in common directories.
    - Standardized Logging: Logs messages with severity levels (INFO, WARN, ERROR) to both the GUI and a permanent file.
#>
param (
    [switch]$Help
)

if ($Help) {
    # This shows help content from the comment block at the top of the script
    Get-Help $MyInvocation.MyCommand.Definition -Full
    exit
}

#region --- CORE FUNCTIONS ---

function Initialize-Configuration {
    [CmdletBinding()]
    param()
    $configFile = Join-Path $PSScriptRoot "config.json"
    if (-not (Test-Path $configFile)) {
        Show-MessageBox -Text "FATAL: 'config.json' not found. Please ensure it exists in the same directory as the script." -Title "Configuration Error" -Icon 'Error'
        exit 1
    }
    try {
        return Get-Content -Path $configFile | ConvertFrom-Json
    }
    catch {
        Show-MessageBox -Text "FATAL: Could not read or parse 'config.json'. Please validate its format. `n$($_.Exception.Message)" -Title "Configuration Error" -Icon 'Error'
        exit 1
    }
}

function Show-MessageBox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Text,
        [Parameter(Mandatory)] [string]$Title,
        [System.Windows.Forms.MessageBoxButtons]$Buttons = 'OK',
        [System.Windows.Forms.MessageBoxIcon]$Icon = 'None'
    )
    # Ensure the required assembly is loaded
    Add-Type -AssemblyName System.Windows.Forms
    return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

function Log-Message {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GuiControls,
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'NOTE', 'FATAL')]
        [string]$Severity = 'INFO',
        [Parameter(Mandatory)] [string]$LogFile
    )

    $colorMap = @{
        'INFO'    = 'Black'
        'WARN'    = 'OrangeRed'
        'ERROR'   = 'Red'
        'FATAL'   = 'Red'
        'SUCCESS' = 'Green'
        'NOTE'    = 'DarkBlue'
    }
    $color = $colorMap[$Severity]
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp - [$Severity] - $Message"
    $logEntry | Out-File -FilePath $LogFile -Append

    $logBox = $GuiControls.LogBox
    if ($logBox.InvokeRequired) {
        $logBox.Invoke([Action]{
            Log-Message -GuiControls $GuiControls -Message $Message -Severity $Severity -LogFile $LogFile
        })
    }
    else {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionLength = 0
        $logBox.SelectionColor = $color
        $logBox.AppendText("$(Get-Date -Format 'HH:mm:ss') - $Message`n")
        $logBox.ScrollToCaret()
    }
}

function Find-Executable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ExecutableName
    )
    $searchPaths = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)"
    )
    foreach ($path in $searchPaths) {
        $found = Get-ChildItem -Path $path -Filter $ExecutableName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }
    return $null
}

#endregion

#region --- Pre-Execution Checks & GUI Initialization ---

# Load configuration from external JSON file
$config = Initialize-Configuration

# Check for AC Power connection on laptops
$battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
if ($battery) {
    while ((Get-CimInstance -ClassName Win32_Battery).BatteryStatus -eq 1) {
        $promptResult = Show-MessageBox -Text "This script requires a constant power source. Please connect your laptop to AC power." -Title "Power Connection Required" -Buttons 'OKCancel' -Icon 'Warning'
        if ($promptResult -eq 'Cancel') { exit }
    }
}

# Initial user confirmation
$confirmParams = @{
    Text    = "This tool will perform lengthy system maintenance and will require a restart. Save all work and close all apps before proceeding.`n`nDo you want to continue?"
    Title   = "Confirmation Required"
    Buttons = 'YesNo'
    Icon    = 'Warning'
}
if ((Show-MessageBox @confirmParams) -ne 'Yes') { exit }

# Admin rights check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        Show-MessageBox -Text "This script requires administrator rights. We will now open the Company Portal so you can install them." -Title "Administrator Required" -Icon 'Information'
        Start-Process $config.CompanyPortalAppUri -ErrorAction Stop

        $instructions = @"
ACTION REQUIRED:
1. Find and 'Install' the admin rights application in Company Portal.
2. WAIT for the installation to fully complete.
3. Once 'Installed', MANUALLY RESTART your computer.
4. After restarting, run this script again.
This tool will now close.
"@
        Show-MessageBox -Text $instructions -Title "Manual Steps Required" -Icon 'Information'
    }
    catch {
        Show-MessageBox -Text "Failed to open the Company Portal. Please contact IT for assistance with getting administrator rights." -Title "Error" -Icon 'Error'
    }
    exit
}

# Create Logging Directory
$logDirectory = Join-Path -Path $env:ProgramData -ChildPath $config.LogSubdirectory
if (-not (Test-Path -Path $logDirectory)) {
    try {
        New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Show-MessageBox -Text "Failed to create log directory at '$logDirectory'. Please check permissions." -Title "Error" -Icon 'Error'
        exit
    }
}
$logFile = Join-Path -Path $logDirectory -ChildPath "SystemMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# GUI Initialization
Add-Type -AssemblyName System.Drawing, System.Windows.Forms
$form = New-Object System.Windows.Forms.Form -Property @{
    Text          = "System Maintenance Tool v2.0"
    StartPosition = "CenterScreen"
    WindowState   = "Maximized"
    MinimumSize   = New-Object System.Drawing.Size(800, 600)
}
$logLabel = New-Object System.Windows.Forms.Label -Property @{ Text = "Status Log:"; Dock = "Top" }
$logBox = New-Object System.Windows.Forms.RichTextBox -Property @{ Font = "Consolas, 10"; ReadOnly = $true; ScrollBars = "Vertical"; Dock = "Fill" }
$statusStrip = New-Object System.Windows.Forms.StatusStrip -Property @{ Dock = "Bottom" }
$progressBar = New-Object System.Windows.Forms.ToolStripProgressBar -Property @{ Style = "Continuous"; Size = New-Object System.Drawing.Size(200, 16) }
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{ Text = "Initializing..."; Spring = $true }
$cancelButton = New-Object System.Windows.Forms.Button -Property @{ Text = "Cancel"; Dock = "Bottom" }
$statusStrip.Items.AddRange(@($statusLabel, $progressBar))
$form.Controls.AddRange(@($logBox, $logLabel, $cancelButton, $statusStrip))

$guiControls = [PSCustomObject]@{
    Form        = $form
    LogBox      = $logBox
    ProgressBar = $progressBar
    StatusLabel = $statusLabel
    CancelButton = $cancelButton
}

#endregion

#region --- Background Task Definition & Execution ---

# Define the main logic to be run in the background
$maintenanceScriptBlock = {
    param($guiControls, $logFile, $config)

    #region --- Functions for Background Thread ---
    # NOTE: These functions are redefined here to be self-contained within the runspace.
    
    function Log-Message {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] $GuiControls,
            [Parameter(Mandatory)] [string]$Message,
            [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'NOTE', 'FATAL')]
            [string]$Severity = 'INFO',
            [Parameter(Mandatory)] [string]$LogFile
        )

        $colorMap = @{
            'INFO'    = 'Black'; 'WARN'    = 'OrangeRed'; 'ERROR'   = 'Red';
            'FATAL'   = 'Red'; 'SUCCESS' = 'Green';     'NOTE'    = 'DarkBlue'
        }
        $color = $colorMap[$Severity]
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry = "$timestamp - [$Severity] - $Message"
        $logEntry | Out-File -FilePath $LogFile -Append

        if ($guiControls.LogBox.InvokeRequired) {
            $guiControls.LogBox.Invoke([Action]{
                Log-Message -GuiControls $GuiControls -Message $Message -Severity $Severity -LogFile $LogFile
            })
        }
        else {
            $guiControls.LogBox.SelectionStart = $guiControls.LogBox.TextLength; $guiControls.LogBox.SelectionLength = 0
            $guiControls.LogBox.SelectionColor = $color
            $guiControls.LogBox.AppendText("$(Get-Date -Format 'HH:mm:ss') - $Message`n"); $guiControls.LogBox.ScrollToCaret()
        }
    }

    function Update-Status {
        [CmdletBinding()]
        param([Parameter(Mandatory)] $GuiControls, [Parameter(Mandatory)] [string]$StatusText)
        if ($guiControls.StatusLabel.Owner.InvokeRequired) {
            $guiControls.StatusLabel.Owner.Invoke([Action[string]]{ param($txt) Update-Status -GuiControls $GuiControls -StatusText $txt }, $StatusText)
        } else {
            $guiControls.StatusLabel.Text = $StatusText
        }
    }

    function Find-Executable {
        [CmdletBinding()]
        param([string]$ExecutableName)
        $searchPaths = @("$env:ProgramFiles", "$env:ProgramFiles(x86)")
        foreach ($path in $searchPaths) {
            $found = Get-ChildItem -Path $path -Filter $ExecutableName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { return $found.FullName }
        }
        return $null
    }

    #endregion

    # ---- START OF MAINTENANCE SEQUENCE ----
    Log-Message -GuiControls $guiControls -Message "Administrator privileges confirmed. Starting maintenance..." -Severity 'SUCCESS' -LogFile $logFile
    Log-Message -GuiControls $guiControls -Message "Log file for this session is: $logFile" -Severity 'NOTE' -LogFile $logFile
    
    # Define Maintenance Steps
    $maintenanceCommands = @(
        @{ Name = "Flushing DNS Cache";             Command = { ipconfig /flushdns } },
        @{ Name = "Forcing Group Policy Update";    Command = { gpupdate /force } },
        @{
            Name = "Importing PSWindowsUpdate Module";
            Command = {
                $modulePath = Join-Path $PSScriptRoot "Modules\PSWindowsUpdate"
                if (-not (Test-Path $modulePath)) {
                    throw "PSWindowsUpdate module not found at '$modulePath'. Please ensure it's bundled with the script."
                }
                Import-Module -Name $modulePath -Force
                Write-Output "PSWindowsUpdate module imported successfully."
            }
        },
        @{ Name = "Checking for Windows Updates";   Command = { Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Verbose } },
        @{ Name = "Resetting Winsock Catalog";      Command = { netsh winsock reset } },
        @{ Name = "Resetting TCP/IP Stack";         Command = { netsh int ip reset } },
        @{ Name = "Component Store Health Scan (DISM)"; Command = { DISM /Online /Cleanup-Image /ScanHealth } },
        @{ Name = "Component Store Restore (DISM)"; Command = { DISM /Online /Cleanup-Image /RestoreHealth } },
        @{ Name = "System File Integrity Scan (SFC)";   Command = { sfc /scannow } },
        @{ Name = "Scheduling Disk Check (C:)";       Command = { fsutil dirty set C: }; Note = "A disk check will run on the next restart." }
    )

    $guiControls.ProgressBar.Maximum = $maintenanceCommands.Count + 1 # +1 for hardware updates

    foreach ($item in $maintenanceCommands) {
        if ($script:cancelRequested) {
            Log-Message -GuiControls $guiControls -Message "Operation cancelled by user." -Severity 'WARN' -LogFile $logFile
            return
        }
        $name = $item.Name
        Update-Status -GuiControls $guiControls -StatusText "Running: $name..."
        Log-Message -GuiControls $guiControls -Message "Running: $name..." -LogFile $logFile
        
        try {
            $output = & $item.Command *>&1 | ForEach-Object { $_.ToString() }
            Log-Message -GuiControls $guiControls -Message "SUCCESS: $name completed." -Severity 'SUCCESS' -LogFile $logFile
            $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $guiControls -Message "  $_" -Severity 'INFO' -LogFile $logFile } }
            if ($item.Note) { Log-Message -GuiControls $guiControls -Message "NOTE: $($item.Note)" -Severity 'NOTE' -LogFile $logFile }
        }
        catch {
            Log-Message -GuiControls $guiControls -Message "ERROR executing '$name': $($_.Exception.Message)" -Severity 'ERROR' -LogFile $logFile
        }
        $guiControls.ProgressBar.Value++
    }

    # Hardware-specific updates
    Update-Status -GuiControls $guiControls -StatusText "Checking for hardware updates..."
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    Log-Message -GuiControls $guiControls -Message "Manufacturer detected: $manufacturer" -LogFile $logFile

    switch -Wildcard ($manufacturer) {
        "*Dell*" {
            $dcuCliPath = Find-Executable -ExecutableName "dcu-cli.exe"
            if ($dcuCliPath) {
                Log-Message -GuiControls $guiControls -Message "Dell Command | Update found. Scanning for updates..." -Severity 'NOTE' -LogFile $logFile
                try {
                    & $dcuCliPath /scan *>&1 | Out-Null
                    & $dcuCliPath /applyUpdates -reboot=enable *>&1 | Out-Null
                    Log-Message -GuiControls $guiControls -Message "Dell updates applied successfully." -Severity 'SUCCESS' -LogFile $logFile
                } catch { Log-Message -GuiControls $guiControls -Message "Failed to apply Dell updates. $_" -Severity 'ERROR' -LogFile $logFile }
            } else {
                Log-Message -GuiControls $guiControls -Message "Dell Command | Update not found. Please install it manually for driver updates." -Severity 'WARN' -LogFile $logFile
            }
        }
        "*HP*" {
            $hpiaPath = Find-Executable -ExecutableName "HPImageAssistant.exe"
            if ($hpiaPath) {
                Log-Message -GuiControls $guiControls -Message "HP Image Assistant found. Analyzing system..." -Severity 'NOTE' -LogFile $logFile
                try {
                    & $hpiaPath /Operation:Analyze /Action:Install /Silent *>&1 | Out-Null
                    Log-Message -GuiControls $guiControls -Message "HP updates applied successfully." -Severity 'SUCCESS' -LogFile $logFile
                } catch { Log-Message -GuiControls $guiControls -Message "Failed to apply HP updates. $_" -Severity 'ERROR' -LogFile $logFile }
            } else {
                Log-Message -GuiControls $guiControls -Message "HP Image Assistant not found. Please install it manually for driver updates." -Severity 'WARN' -LogFile $logFile
            }
        }
        Default {
            Log-Message -GuiControls $guiControls -Message "Please check for updates using your manufacturer's tool (e.g., Lenovo Vantage)." -Severity 'NOTE' -LogFile $logFile
        }
    }
    $guiControls.ProgressBar.Value++
    Update-Status -GuiControls $guiControls -StatusText "All tasks complete."

    # Final Restart Prompt
    Log-Message -GuiControls $guiControls -Message "All maintenance tasks are complete. A restart is required." -Severity 'NOTE' -LogFile $logFile
    $form.Invoke([Action]{
        $guiControls.CancelButton.Enabled = $false
        $result = Show-MessageBox -Text "Maintenance is complete. Your computer needs to restart to apply all changes." -Title "Restart Required" -Buttons 'YesNo' -Icon 'Question'
        if ($result -eq 'Yes') {
            Restart-Computer -Force
        } else {
            Show-MessageBox -Text "Please remember to restart your computer soon." -Title "Restart Pending" -Icon 'Information'
        }
    })
}

# Setup and start the background runspace
$script:cancelRequested = $false
$cancelButton.Add_Click({
    $script:cancelRequested = $true
    $guiControls.CancelButton.Enabled = $false
    $guiControls.CancelButton.Text = "Cancelling..."
})

$ps = [powershell]::Create().AddScript($maintenanceScriptBlock).AddParameters(@($guiControls, $logFile, $config))
$handle = $ps.BeginInvoke()

# Show form and wait for it to close
$form.ShowDialog() | Out-Null

# Cleanup
try {
    $ps.EndInvoke($handle)
}
catch {
    # This will catch errors if the job was stopped manually, which is expected.
}
finally {
    $ps.Dispose()
}

#endregion
