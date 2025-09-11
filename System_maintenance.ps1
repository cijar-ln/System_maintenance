<#
.SYNOPSIS
    A GUI-based tool for comprehensive Windows 11 maintenance.
.DESCRIPTION
    This script provides a user-friendly interface to run system repairs, check for updates,
    and apply manufacturer-specific firmware. It handles administrative elevation and provides
    real-time logging of all its actions to both the GUI and a persistent text file.
#>

#region --- Configuration ---

# All paths, IDs, and settings are defined here for easy maintenance.
$config = @{
    LogDirectory        = "C:\ProgramData\SystemMaintenanceTool\Logs"
    DellUpdateCLI       = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    HPImageAssistant    = "C:\Program Files (x86)\HP\HP Image Assistant\HPImageAssistant.exe"
    CompanyPortalAppUri = "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"
}

# Define the sequence of maintenance commands to be executed.
$maintenanceCommands = @(
    [pscustomobject]@{ Name = "Flushing DNS Cache";                  Command = { ipconfig /flushdns } },
    [pscustomobject]@{ Name = "Forcing Group Policy Update";         Command = { gpupdate /force } },
    [pscustomobject]@{ Name = "Resetting Winsock Catalog";           Command = { netsh winsock reset } },
    [pscustomobject]@{ Name = "Resetting TCP/IP Stack";              Command = { netsh int ip reset } },
    [pscustomobject]@{ Name = "System File Integrity Scan (SFC)";    Command = { sfc /scannow } },
    [pscustomobject]@{ Name = "Component Store Health Scan (DISM)";  Command = { DISM /Online /Cleanup-Image /ScanHealth } },
    [pscustomobject]@{ Name = "Component Store Restore (DISM)";      Command = { DISM /Online /Cleanup-Image /RestoreHealth } },
    [pscustomobject]@{ Name = "Scheduling Disk Check (C:)";          Command = { cmd.exe /c "echo y | chkdsk C: /f /r" }; Note = "This will run on the next restart." }
)

#endregion

#region --- GUI Functions ---

function Initialize-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "System Maintenance Tool"
        StartPosition = "CenterScreen"
        WindowState   = "Maximized"
    }

    $label = New-Object System.Windows.Forms.Label -Property @{
        Text = "Status Log:"
        Dock = "Top"
    }

    $logBox = New-Object System.Windows.Forms.RichTextBox -Property @{
        Font      = "Consolas, 10"
        ReadOnly  = $true
        ScrollBars = "Vertical"
        Dock      = "Fill"
    }

    $progressBar = New-Object System.Windows.Forms.ProgressBar -Property @{
        Style = "Continuous"
        Dock  = "Bottom"
    }

    $form.Controls.AddRange(@($logBox, $label, $progressBar))

    return [pscustomobject]@{
        Form        = $form
        LogBox      = $logBox
        ProgressBar = $progressBar
    }
}

#endregion

#region --- Core Functions ---

function Log-Message {
    param(
        [Parameter(Mandatory = $true)]
        $GuiControls,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [System.Drawing.Color]$Color = 'Black',
        [string]$LogFilePath # NEW: Path for the text log file
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $logEntry = "$timestamp - $Message"

    # 1. Log to the GUI (unchanged)
    if ($GuiControls.Form.IsHandleCreated) {
        $logBox = $GuiControls.LogBox
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionLength = 0
        $logBox.SelectionColor = $Color
        $logBox.AppendText("$logEntry`n")
        $logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
    else {
        Write-Host $logEntry
    }

    # 2. NEW: Log to the text file
    if ($LogFilePath) {
        try {
            Add-Content -Path $LogFilePath -Value $logEntry
        }
        catch {
            Write-Warning "Could not write to log file: $LogFilePath"
        }
    }
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)]
        $GuiControls,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$LogFilePath # NEW: Pass the log file path down
    )
    
    Log-Message -GuiControls $GuiControls -Message "Running: $Name..." -LogFilePath $LogFilePath
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = "powershell.exe"
    $processInfo.Arguments = "-NoProfile -Command `"$($Command.ToString())`""
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    
    $process = [System.Diagnostics.Process]::Start($processInfo)
    
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($stdout) {
        $stdout.Split([environment]::NewLine) | ForEach-Object { 
            if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Gray" -LogFilePath $LogFilePath }
        }
    }

    if ($stderr -or $process.ExitCode -ne 0) {
        Log-Message -GuiControls $GuiControls -Message "ERROR: '$Name' failed. Exit Code: $($process.ExitCode)" -Color "Red" -LogFilePath $LogFilePath
        if ($stderr) {
            $stderr.Split([environment]::NewLine) | ForEach-Object {
                if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Red" -LogFilePath $LogFilePath }
            }
        }
    } else {
        Log-Message -GuiControls $GuiControls -Message "SUCCESS: $Name completed." -Color "Green" -LogFilePath $LogFilePath
    }
}

function Start-Maintenance {
    param(
        [Parameter(Mandatory = $true)]
        $GuiControls,
        [string]$LogFilePath
    )

    Log-Message -GuiControls $GuiControls -Message "Administrator privileges confirmed. Starting maintenance..." -Color "Green" -LogFilePath $LogFilePath
    
    $GuiControls.ProgressBar.Maximum = $maintenanceCommands.Count + 1

    foreach ($item in $maintenanceCommands) {
        Invoke-LoggedCommand -GuiControls $GuiControls -Command $item.Command -Name $item.Name -LogFilePath $LogFilePath
        if ($item.Note) {
            Log-Message -GuiControls $GuiControls -Message "NOTE: $($item.Note)" -Color "Orange" -LogFilePath $LogFilePath
        }
        $GuiControls.ProgressBar.Value++
    }

    Check-HardwareUpdates -GuiControls $GuiControls -LogFilePath $LogFilePath
    $GuiControls.ProgressBar.Value++

    Log-Message -GuiControls $GuiControls -Message "All maintenance tasks are complete. A full log has been saved to:" -Color "DarkBlue" -LogFilePath $LogFilePath
    Log-Message -GuiControls $GuiControls -Message $LogFilePath -Color "Blue" -LogFilePath $LogFilePath
    Log-Message -GuiControls $GuiControls -Message "Restarting computer in 5 seconds..." -Color "DarkBlue" -LogFilePath $LogFilePath
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

function Check-HardwareUpdates {
    param (
        [Parameter(Mandatory = $true)]
        $GuiControls,
        [string]$LogFilePath
    )
    
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    Log-Message -GuiControls $GuiControls -Message "Manufacturer detected: $manufacturer" -LogFilePath $LogFilePath

    if ($manufacturer -like "*Dell*") {
        if (Test-Path $config.DellUpdateCLI) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Scan" -Command { & $using:config.DellUpdateCLI /scan } -LogFilePath $LogFilePath
            Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Apply" -Command { & $using:config.DellUpdateCLI /applyUpdates -reboot=enable } -LogFilePath $LogFilePath
        } else {
            Log-Message -GuiControls $GuiControls -Message "Dell Command | Update not found. Please install it manually." -Color "Orange" -LogFilePath $LogFilePath
        }
    }
    elseif ($manufacturer -like "*HP*") {
        if (Test-Path $config.HPImageAssistant) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Name "HP Image Assistant Update" -Command { & $using:config.HPImageAssistant /Operation:Analyze /Action:Install /Silent } -LogFilePath $LogFilePath
        } else {
            Log-Message -GuiControls $GuiControls -Message "HP Image Assistant not found. Please install it manually." -Color "Orange" -LogFilePath $LogFilePath
        }
    }
    else {
        Log-Message -GuiControls $GuiControls -Message "Please check for updates using your manufacturer's tool (e.g., Lenovo Vantage)." -Color "Orange" -LogFilePath $LogFilePath
    }
}

function Handle-NonAdmin {
    param(
        [Parameter(Mandatory = $true)]
        $GuiControls,
        [string]$LogFilePath
    )
    
    Log-Message -GuiControls $GuiControls -Message "Administrator rights not detected. Initiating elevation request..." -Color "Red" -LogFilePath $LogFilePath
    Start-Process $config.CompanyPortalAppUri
    Log-Message -GuiControls $GuiControls -Message "Waiting 15 seconds for Company Portal to load..." -LogFilePath $LogFilePath
    Start-Sleep -Seconds 15

    [System.Windows.Forms.SendKeys]::SendWait("^{i}")
    Log-Message -GuiControls $GuiControls -Message "Install command sent. Please follow instructions in the pop-up." -Color "Green" -LogFilePath $LogFilePath

    $instructions = @"
ACTION REQUIRED:
The installation for admin rights has been automatically started.
1. Wait for the installation to complete in Company Portal.
2. Manually RESTART your computer.
3. Run this script again after restarting.
This tool will now close.
"@
    [System.Windows.Forms.MessageBox]::Show($instructions, "Manual Restart Required", "OK", "Information")
}

#endregion

#region --- Script Entry Point ---

# Show initial confirmation dialog to the user
$confirmationResult = [System.Windows.Forms.MessageBox]::Show(
    "This tool will perform lengthy system maintenance and will restart your computer. Save all work before proceeding.`n`nDo you want to continue?",
    "Confirmation Required",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning
)

if ($confirmationResult -ne 'Yes') {
    exit
}

# Initialize and show the GUI
$gui = Initialize-GUI
$gui.Form.Show()

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# --- NEW: Set up the log file path ---
$logFilePath = $null
if ($isAdmin) {
    try {
        if (-not (Test-Path $config.LogDirectory)) {
            New-Item -Path $config.LogDirectory -ItemType Directory -Force | Out-Null
        }
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFilePath = Join-Path -Path $config.LogDirectory -ChildPath "MaintenanceLog_$timestamp.log"
        Log-Message -GuiControls $gui -Message "Log file will be saved to: $logFilePath" -Color "Gray" -LogFilePath $logFilePath
    }
    catch {
        Log-Message -GuiControls $gui -Message "WARNING: Could not create log directory. File logging will be disabled." -Color "Orange"
    }
}
# --- End of new section ---


if ($isAdmin) {
    Start-Maintenance -GuiControls $gui -LogFilePath $logFilePath
}
else {
    # Non-admin users won't have permission to write to ProgramData, so we don't create a log.
    Handle-NonAdmin -GuiControls $gui
    Start-Sleep -Seconds 5
    $gui.Form.Close()
}

#endregion
