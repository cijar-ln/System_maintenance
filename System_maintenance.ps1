<#
.SYNOPSIS
    A GUI-based tool for comprehensive Windows 11 maintenance.
.DESCRIPTION
    This script provides a user-friendly interface to run system repairs, check for updates,
    and apply manufacturer-specific firmware. It handles administrative elevation and provides
    real-time logging of all its actions. This version runs maintenance tasks in a background
    thread to keep the UI responsive.
#>

#region --- Configuration ---

$config = @{
    DellUpdateCLI       = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    HPImageAssistant    = "C:\Program Files (x86)\HP\HP Image Assistant\HPImageAssistant.exe"
    CompanyPortalAppUri = "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"
}

# Define the sequence of maintenance commands to be executed.
$maintenanceCommands = @(
    @{ Name = "Flushing DNS Cache";               Command = { ipconfig /flushdns } },
    @{ Name = "Forcing Group Policy Update";      Command = { gpupdate /force } },
    @{ Name = "Resetting Winsock Catalog";        Command = { netsh winsock reset } },
    @{ Name = "Resetting TCP/IP Stack";           Command = { netsh int ip reset } },
    @{ Name = "Component Store Health Scan (DISM)"; Command = { DISM /Online /Cleanup-Image /ScanHealth } },
    @{ Name = "Component Store Restore (DISM)";   Command = { DISM /Online /Cleanup-Image /RestoreHealth } },
    @{ Name = "System File Integrity Scan (SFC)";   Command = { sfc /scannow } },
    @{ Name = "Scheduling Disk Check (C:)";        Command = { cmd.exe /c "echo y | chkdsk C: /f /r" }; Note = "This will run on the next restart." }
)

#endregion

#region --- GUI Functions ---

function Initialize-GUI {
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "System Maintenance Tool"
        StartPosition = "CenterScreen"
        WindowState   = "Maximized"
    }

    $label = New-Object System.Windows.Forms.Label -Property @{ Text = "Status Log:"; Dock = "Top" }
    $logBox = New-Object System.Windows.Forms.RichTextBox -Property @{ Font = "Consolas, 10"; ReadOnly = $true; ScrollBars = "Vertical"; Dock = "Fill" }
    $progressBar = New-Object System.Windows.Forms.ProgressBar -Property @{ Style = "Continuous"; Dock = "Bottom" }
    $form.Controls.AddRange(@($logBox, $label, $progressBar))

    return @{
        Form        = $form
        LogBox      = $logBox
        ProgressBar = $progressBar
    }
}

#endregion

#region --- Script Entry Point ---

Add-Type -AssemblyName System.Windows.Forms

$confirmationResult = [System.Windows.Forms.MessageBox]::Show(
    "This tool will perform lengthy system maintenance and will restart your computer. Save all work and close all apps before proceeding.`n`nDo you want to continue?",
    "Confirmation Required", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning
)

if ($confirmationResult -ne 'Yes') { exit }

# Check for Admin privileges BEFORE creating the UI
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    [System.Windows.Forms.MessageBox]::Show("This script requires Administrator privileges. Please right-click and 'Run as Administrator'.", "Administrator Required", "OK", "Error")
    exit
}

$gui = Initialize-GUI

# Create a PowerShell runspace to run the maintenance in the background
$ps = [powershell]::Create()
$ps.AddScript({
    # This entire script block runs on the background thread.
    # We pass in the required variables from the main script.
    param($GuiControls, $maintenanceCommands, $config)
    
    # --- CORE FUNCTIONS (Defined inside the runspace) ---

    function Log-Message {
        param($GuiControls, [string]$Message, [System.Drawing.Color]$Color = 'Black')

        $logBox = $GuiControls.LogBox
        if ($logBox.InvokeRequired) {
            $logBox.Invoke([Action[string, System.Drawing.Color]]{
                param([string]$msg, [System.Drawing.Color]$c)
                Log-Message -GuiControls $GuiControls -Message $msg -Color $c
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
        param($GuiControls, [scriptblock]$Command, [string]$Name)
        
        Log-Message -GuiControls $GuiControls -Message "Running: $Name..."
        $output = & $Command *>&1 | ForEach-Object { $_.ToString() }

        if ($LASTEXITCODE -ne 0) {
            Log-Message -GuiControls $GuiControls -Message "ERROR: '$Name' failed. Exit Code: $LASTEXITCODE" -Color "Red"
            if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Red" } } }
        } else {
            Log-Message -GuiControls $GuiControls -Message "SUCCESS: $Name completed." -Color "Green"
            if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Gray" } } }
        }
    }

    function Check-HardwareUpdates {
        param ($GuiControls)
        
        $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        Log-Message -GuiControls $GuiControls -Message "Manufacturer detected: $manufacturer"

        if ($manufacturer -like "*Dell*") {
            if (Test-Path $config.DellUpdateCLI) {
                Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Scan" -Command { & $config.DellUpdateCLI /scan }
                Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Apply" -Command { & $config.DellUpdateCLI /applyUpdates -reboot=enable }
            } else {
                Log-Message -GuiControls $GuiControls -Message "Dell Command | Update not found. Please install it manually." -Color "Orange"
            }
        }
        elseif ($manufacturer -like "*HP*") {
            if (Test-Path $config.HPImageAssistant) {
                Invoke-LoggedCommand -GuiControls $GuiControls -Name "HP Image Assistant Update" -Command { & $config.HPImageAssistant /Operation:Analyze /Action:Install /Silent }
            } else {
                Log-Message -GuiControls $GuiControls -Message "HP Image Assistant not found. Please install it manually." -Color "Orange"
            }
        }
        else {
            Log-Message -GuiControls $GuiControls -Message "Please check for updates using your manufacturer's tool (e.g., Lenovo Vantage)." -Color "Orange"
        }
    }

    function Start-Maintenance {
        param($GuiControls)

        Log-Message -GuiControls $GuiControls -Message "Administrator privileges confirmed. Starting maintenance..." -Color "Green"
        
        $GuiControls.ProgressBar.Maximum = $maintenanceCommands.Count + 1

        foreach ($item in $maintenanceCommands) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Command $item.Command -Name $item.Name
            if ($item.Note) { Log-Message -GuiControls $GuiControls -Message "NOTE: $($item.Note)" -Color "Orange" }
            $GuiControls.ProgressBar.Value++
        }

        Check-HardwareUpdates -GuiControls $GuiControls
        $GuiControls.ProgressBar.Value++

        Log-Message -GuiControls $GuiControls -Message "All maintenance tasks are complete. Restarting computer..." -Color "DarkBlue"
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }

    # --- SCRIPT EXECUTION (Inside the runspace) ---
    # Now that the functions are defined, call the main one.
    Start-Maintenance -GuiControls $GuiControls

}).AddArgument($gui).AddArgument($maintenanceCommands).AddArgument($config) | Out-Null

# Start the background task. This call returns immediately.
$handle = $ps.BeginInvoke()

# Show the form. It will now be responsive while the background task runs.
# ShowDialog() blocks the script here until the user closes the form.
$gui.Form.ShowDialog()

# Clean up the runspace when the form is closed
$ps.EndInvoke($handle)
$ps.Dispose()

#endregion
