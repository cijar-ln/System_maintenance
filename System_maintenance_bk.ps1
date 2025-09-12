<#
.SYNOPSIS
    A verbose, GUI-based tool that runs a comprehensive suite of Windows 11 maintenance tasks.
    It intelligently guides non-admin users to gain elevation via Company Portal and automates manufacturer-specific
    driver and firmware updates, including installer downloads.
.DESCRIPTION
    (Description remains unchanged)
#>

#region --- Configuration ---

$config = @{
    LogDirectory        = Join-Path -Path $env:ProgramData -ChildPath "SystemMaintenance"
    DellUpdateCLI       = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    HPImageAssistant    = "C:\Program Files (x86)\HP\HP Image Assistant\HPImageAssistant.exe"
    CompanyPortalAppUri = "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"
    DellInstallerUrl    = "https://dl.dell.com/FOLDER13309509M/1/Dell-Command-Update-Application_PPWHH_WIN64_5.5.0_A00.EXE"
    LogFile             = Join-Path -Path $env:ProgramData -ChildPath "SystemMaintenance\SystemMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
}

# Define the sequence of maintenance commands to be executed.
# REFACTOR: Converted the PSWindowsUpdate command to a here-string for readability and added a try/catch.
$maintenanceCommands = @(
    @{ Name = "Flushing DNS Cache";             Command = { ipconfig /flushdns } },
    @{ Name = "Forcing Group Policy Update";    Command = { gpupdate /force } },
    @{ Name = "Restarting Windows Explorer";    Command = { Stop-Process -Name explorer -Force; Start-Process explorer } },
    @{
        Name = "Install/Run PSWindowsUpdate Module"
        Command = {
            $updateCommand = @"
                if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                    Write-Output 'PSWindowsUpdate module not found. Installing now...'
                    try {
                        Install-Module -Name PSWindowsUpdate -Force -AcceptLicense -Scope AllUsers -ErrorAction Stop
                    } catch {
                        Write-Error "Failed to install PSWindowsUpdate module. Please check internet connectivity. `n$($_.Exception.Message)"
                        return # Exit this specific command block on failure
                    }
                } else {
                    Write-Output 'PSWindowsUpdate module is already installed.'
                }
                
                Write-Output 'Searching for, downloading, and installing all applicable updates...'
                Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Verbose
"@
            powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $updateCommand
        }
    },
    @{ Name = "Resetting Winsock Catalog";      Command = { netsh winsock reset } },
    @{ Name = "Resetting TCP/IP Stack";         Command = { netsh int ip reset } },
    @{ Name = "Component Store Health Scan (DISM)"; Command = { DISM /Online /Cleanup-Image /ScanHealth } },
    @{ Name = "Component Store Restore (DISM)"; Command = { DISM /Online /Cleanup-Image /RestoreHealth } },
    @{ Name = "System File Integrity Scan (SFC)";   Command = { sfc /scannow } },
    @{ Name = "Scheduling Disk Check (C:)";       Command = { cmd.exe /c "echo y | chkdsk C: /f /r" }; Note = "This will run on the next restart." }
)

#endregion

#region --- Helper and GUI Functions ---

function Show-MessageBox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Text,
        [Parameter(Mandatory)] [string]$Title,
        [System.Windows.Forms.MessageBoxButtons]$Buttons = 'OK',
        [System.Windows.Forms.MessageBoxIcon]$Icon = 'None'
    )
    return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

function Initialize-GUI {
    [CmdletBinding()]
    param()
    Add-Type -AssemblyName System.Drawing, System.Windows.Forms

    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "System Maintenance Tool"
        StartPosition = "CenterScreen"
        WindowState   = "Maximized"
    }

    $label = New-Object System.Windows.Forms.Label -Property @{ Text = "Status Log:"; Dock = "Top" }
    $logBox = New-Object System.Windows.Forms.RichTextBox -Property @{ Font = "Consolas, 10"; ReadOnly = $true; ScrollBars = "Vertical"; Dock = "Fill" }
    $progressBar = New-Object System.Windows.Forms.ProgressBar -Property @{ Style = "Continuous"; Dock = "Bottom" }
    $form.Controls.AddRange(@($logBox, $label, $progressBar))

    # Return a custom object containing the GUI controls.
    return [PSCustomObject]@{
        Form        = $form
        LogBox      = $logBox
        ProgressBar = $progressBar
    }
}

#endregion

#region --- Core Maintenance Logic ---
# REFACTOR: All logic functions are now in the main script scope for better organization and readability.

function Log-Message {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GuiControls,
        [Parameter(Mandatory)] [string]$Message,
        [System.Drawing.Color]$Color = 'Black',
        [Parameter(Mandatory)] [string]$LogFile
    )
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" | Out-File -FilePath $LogFile -Append

    $logBox = $GuiControls.LogBox
    if ($logBox.InvokeRequired) {
        $logBox.Invoke([Action[string, System.Drawing.Color]]{
            param([string]$msg, [System.Drawing.Color]$c)
            # Recursively call this function on the GUI's thread.
            # No need to pass $GuiControls or $LogFile again in the Invoke payload.
            Log-Message -GuiControls $GuiControls -Message $msg -Color $c -LogFile $LogFile
        }, $Message, $Color)
    }
    else {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionLength = 0
        $logBox.SelectionColor = $Color
        $logBox.AppendText("$(Get-Date -Format 'HH:mm:ss') - $Message`n")
        $logBox.ScrollToCaret()
    }
}

function Invoke-LoggedCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GuiControls,
        [Parameter(Mandatory)] [scriptblock]$Command,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$LogFile
    )
    Log-Message -GuiControls $GuiControls -Message "Running: $Name..." -LogFile $LogFile
    
    $output = & $Command *>&1 | ForEach-Object { $_.ToString() }

    if ($LASTEXITCODE -ne 0) {
        Log-Message -GuiControls $GuiControls -Message "ERROR: '$Name' failed. Exit Code: $LASTEXITCODE" -Color "Red" -LogFile $LogFile
        if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Red" -LogFile $LogFile } } }
    } else {
        Log-Message -GuiControls $GuiControls -Message "SUCCESS: $Name completed." -Color "Green" -LogFile $LogFile
        if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Gray" -LogFile $LogFile } } }
    }
}

function Check-HardwareUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] $GuiControls,
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$LogFile
    )
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    Log-Message -GuiControls $GuiControls -Message "Manufacturer detected: $manufacturer" -LogFile $LogFile

    if ($manufacturer -like "*Dell*") {
        Log-Message -GuiControls $GuiControls -Message "Dell system detected. Searching for Dell Command | Update..." -Color "Blue" -LogFile $LogFile
        if (Test-Path $Config.DellUpdateCLI) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Scan" -Command { & $Config.DellUpdateCLI /scan } -LogFile $LogFile
            Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Apply" -Command { & $Config.DellUpdateCLI /applyUpdates -reboot=enable } -LogFile $LogFile
        } else {
            Log-Message -GuiControls $GuiControls -Message "NOTE: Dell Command | Update not found. Attempting automatic installation..." -Color "Orange" -LogFile $LogFile
            try {
                $tempPath = Join-Path $env:TEMP "DCU_Installer.exe"
                Log-Message -GuiControls $GuiControls -Message "Downloading the installer from $($Config.DellInstallerUrl)..." -LogFile $LogFile
                Invoke-WebRequest -Uri $Config.DellInstallerUrl -OutFile $tempPath -ErrorAction Stop
                Log-Message -GuiControls $GuiControls -Message "Download complete." -Color "Green" -LogFile $LogFile

                Log-Message -GuiControls $GuiControls -Message "Starting silent installation..." -LogFile $LogFile
                Start-Process -FilePath $tempPath -ArgumentList "/s" -Wait -ErrorAction Stop
                Log-Message -GuiControls $GuiControls -Message "Installation complete." -Color "Green" -LogFile $LogFile
                
                Remove-Item -Path $tempPath -Force
                Log-Message -GuiControls $GuiControls -Message "ACTION REQUIRED: Dell Command | Update has been installed. Please open it from the Start Menu after the restart to check for updates manually." -Color "Orange" -LogFile $LogFile
            }
            catch {
                Log-Message -GuiControls $GuiControls -Message "ERROR: Failed to automatically install Dell Command | Update. $_" -Color "Red" -LogFile $LogFile
            }
        }
    }
    elseif ($manufacturer -like "*HP*") {
        Log-Message -GuiControls $GuiControls -Message "HP system detected. Searching for HP Image Assistant..." -Color "Blue" -LogFile $LogFile
        if (Test-Path $Config.HPImageAssistant) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Name "HP Image Assistant Update" -Command { & $Config.HPImageAssistant /Operation:Analyze /Action:Install /Silent } -LogFile $LogFile
        } else {
            Log-Message -GuiControls $GuiControls -Message "NOTE: HP Image Assistant not installed. Please download it from: https://support.hp.com/us-en/help/hp-support-assistant" -Color "Orange" -LogFile $LogFile
        }
    }
    else {
        Log-Message -GuiControls $GuiControls -Message "Please check for updates using your manufacturer's tool (e.g., Lenovo Vantage)." -Color "Orange" -LogFile $LogFile
    }
}

function Start-MaintenanceSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GuiControls,
        [Parameter(Mandatory)] $LogFile,
        [Parameter(Mandatory)] $MaintenanceCommands,
        [Parameter(Mandatory)] $Config
    )
    Log-Message -GuiControls $GuiControls -Message "Administrator privileges confirmed. Starting maintenance..." -Color "Green" -LogFile $LogFile
    Log-Message -GuiControls $GuiControls -Message "Log file for this session is located at: $LogFile" -Color "DarkBlue" -LogFile $LogFile
    
    $GuiControls.ProgressBar.Maximum = $MaintenanceCommands.Count + 1

    foreach ($item in $MaintenanceCommands) {
        Invoke-LoggedCommand -GuiControls $GuiControls -Command $item.Command -Name $item.Name -LogFile $LogFile
        if ($item.Note) { Log-Message -GuiControls $GuiControls -Message "NOTE: $($item.Note)" -Color "Orange" -LogFile $LogFile }
        $GuiControls.ProgressBar.Value++
    }

    Check-HardwareUpdates -GuiControls $GuiControls -Config $Config -LogFile $LogFile
    $GuiControls.ProgressBar.Value++

    Log-Message -GuiControls $GuiControls -Message "All maintenance tasks are complete. Restarting computer in 5 seconds..." -Color "DarkBlue" -LogFile $LogFile
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

#endregion

#region --- Script Entry Point ---

# Check for AC Power connection on laptops
$battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
if ($battery) {
    while ((Get-CimInstance -ClassName Win32_Battery).BatteryStatus -eq 1) {
        $promptResult = Show-MessageBox -Text "This maintenance script requires a constant power source. Please connect your laptop to AC power to continue." -Title "Power Connection Required" -Buttons 'OKCancel' -Icon 'Warning'
        if ($promptResult -eq 'Cancel') { exit }
    }
}

# Initial user confirmation
$confirmParams = @{
    Text    = "This tool will perform lengthy system maintenance and will restart your computer. Save all work and close all apps before proceeding.`n`nDo you want to continue?"
    Title   = "Confirmation Required"
    Buttons = 'YesNo'
    Icon    = 'Warning'
}
if ((Show-MessageBox @confirmParams) -ne 'Yes') { exit }

# Check for Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        Show-MessageBox -Text "This script requires administrator rights. We will now open the Company Portal so you can install them." -Title "Administrator Required" -Icon 'Information'
        Start-Process $config.CompanyPortalAppUri -ErrorAction Stop

        $instructions = @"
ACTION REQUIRED:
The Company Portal app has been opened.
1. Find and click 'Install' for the admin rights application. If it says "Reinstall" or "Uninstall", close the Company Portal and re-run this tool as an Administrator.
2. WAIT for the installation to complete.
3. Once 'Installed', MANUALLY RESTART your computer.
4. After restarting, run this script again as an administrator.
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
if (-not (Test-Path -Path $config.LogDirectory)) {
    try {
        New-Item -Path $config.LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Show-MessageBox -Text "Failed to create log directory at '$($config.LogDirectory)'. Please check permissions." -Title "Error" -Icon 'Error'
        exit
    }
}

# Initialize GUI and prepare for background job
$gui = Initialize-GUI

# REFACTOR: Pass all required variables to the runspace in a single, clean parameter object.
$scriptParameters = @{
    GuiControls         = $gui
    LogFile             = $config.LogFile
    MaintenanceCommands = $maintenanceCommands
    Config              = $config
}

$ps = [powershell]::Create().AddScript({
    # This entire script block now just unpacks parameters and calls the main function.
    param($params)
    
    # Unpack parameters inside the runspace
    $guiControls         = $params.GuiControls
    $logFile             = $params.LogFile
    $maintenanceCommands = $params.MaintenanceCommands
    $config              = $params.Config
    
    # Call the main sequence function, which now lives in the global scope.
    Start-MaintenanceSequence -GuiControls $guiControls -LogFile $logFile -MaintenanceCommands $maintenanceCommands -Config $config

}).AddArgument($scriptParameters) # Pass the single hashtable as an argument.

# Start the background task and show the form
$handle = $ps.BeginInvoke()
$gui.Form.ShowDialog() | Out-Null # Pipe to Out-Null to suppress dialog result output

# Cleanup
$ps.EndInvoke($handle)
$ps.Dispose()

#endregion
