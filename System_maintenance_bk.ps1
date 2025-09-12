<#
.SYNOPSIS
    A verbose, GUI-based tool that runs a comprehensive suite of Windows 11 maintenance tasks.
    It intelligently guides non-admin users to gain elevation via Company Portal and automates manufacturer-specific
    driver and firmware updates, including installer downloads.

.DESCRIPTION
    This script provides a user-friendly graphical interface (GUI) to guide a user or technician through a standardized
    system health and repair process. Its operational flow is as follows:

    1.  Initial User Confirmation: Before any action is taken, it presents a clear pop-up dialog warning the user that
        the process is lengthy and will involve an automatic computer restart. The script only proceeds if the user
        explicitly agrees.

    2.  Administrative Privilege Check: The script determines if it's running with elevated privileges.
        - If NOT running as admin: It opens the corporate Company Portal directly to the Temporary admin rights application
          and displays a message box with clear instructions for the user to manually install the rights, restart
          their computer, and then re-run the script as an administrator OR just run the script as an Admin if the admin rights app has been installed already.
        - If running as admin: It proceeds directly to the main maintenance tasks.

    3.  Background Processing: All maintenance tasks are run in a background thread, ensuring the GUI remains
        responsive and the user can see real-time progress without the application freezing.

    4.  Main Maintenance Sequence: Executes a carefully ordered sequence of system commands designed to resolve common
        Windows issues, such as flushing DNS, resetting network components, and running SFC and DISM scans.

    5.  Hardware-Specific Updates: It detects the computer's manufacturer and takes intelligent action.
        - For Dell machines: If Dell Command | Update is not found, it automatically downloads and silently
          installs the utility, logging a message for the user to check it manually after the final restart.
        - For HP machines: If HP Support Assistant is not found, it logs a direct download link and instructs
          the user to install it.
        - For other manufacturers: It provides on-screen guidance for common update tools (e.g., Lenovo Vantage).

    6.  Real-time and File Logging: All actions, command outputs, successes, and errors are logged in real-time
        to the main GUI window. A permanent text log file is also created in 'C:\ProgramData\SystemMaintenance'
        for each session for later analysis.

    7.  Final Restart: Upon completion of all tasks, it performs a final, automatic restart to ensure all
        changes are fully applied.
#>

#region --- Configuration ---

# CLEANUP: Centralized all configurable strings into one place for easier maintenance.
$config = @{
    LogDirectory        = Join-Path -Path $env:ProgramData -ChildPath "SystemMaintenance" # Use a standard location for logs.
    DellUpdateCLI       = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    HPImageAssistant    = "C:\Program Files (x86)\HP\HP Image Assistant\HPImageAssistant.exe"
    CompanyPortalAppUri = "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"
    DellInstallerUrl    = "https://dl.dell.com/FOLDER13309509M/1/Dell-Command-Update-Application_PPWHH_WIN64_5.5.0_A00.EXE"
}

# Define the sequence of maintenance commands to be executed.
$maintenanceCommands = @(
    @{ Name = "Flushing DNS Cache";             Command = { ipconfig /flushdns } },
    @{ Name = "Forcing Group Policy Update";    Command = { gpupdate /force } },
    @{ Name = "Restarting Windows Explorer";    Command = { Stop-Process -Name explorer -Force; Start-Process explorer } },
    # CLEANUP: Added a comment noting that wuauclt is a legacy command.
    @{ Name = "Checking for Windows Updates";    Command = { wuauclt /detectnow; wuauclt /reportnow } }, # NOTE: wuauclt is deprecated but kept for legacy compatibility.
    @{ Name = "Resetting Winsock Catalog";      Command = { netsh winsock reset } },
    @{ Name = "Resetting TCP/IP Stack";         Command = { netsh int ip reset } },
    @{ Name = "Component Store Health Scan (DISM)"; Command = { DISM /Online /Cleanup-Image /ScanHealth } },
    @{ Name = "Component Store Restore (DISM)"; Command = { DISM /Online /Cleanup-Image /RestoreHealth } },
    @{ Name = "System File Integrity Scan (SFC)";   Command = { sfc /scannow } },
    @{ Name = "Scheduling Disk Check (C:)";       Command = { cmd.exe /c "echo y | chkdsk C: /f /r" }; Note = "This will run on the next restart." }
)

#endregion

#region --- GUI Functions ---

function Initialize-GUI {
    # CLEANUP: Added CmdletBinding as a standard best practice for functions.
    [CmdletBinding()]
    param()

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

# CLEANUP: The MessageBox call is kept on a single line as it's a .NET method that doesn't support PowerShell splatting.
$confirmationResult = [System.Windows.Forms.MessageBox]::Show(
    "This tool will perform lengthy system maintenance and will restart your computer. Save all work and close all apps before proceeding.`n`nDo you want to continue?",
    "Confirmation Required",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning
)


if ($confirmationResult -ne 'Yes') { exit }

# Check for Admin privileges BEFORE creating the UI
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        # CLEANUP: Removed hardcoded URI and used the one from the $config hashtable for consistency.
        [System.Windows.Forms.MessageBox]::Show("This script requires administrator rights. We will now open the Company Portal so you can install them.", "Administrator Required", "OK", "Information")
        Start-Process $config.CompanyPortalAppUri

        $instructions = @"
ACTION REQUIRED:

The Company Portal app has been opened for you.

1. Please find and click the 'Install' button for the admin rights application. If it says "Reinstall" or "Uninstall", just close the Company Portal and re-run the Maintenance Tool as an Administrator.

2. WAIT for the installation to fully complete.

3. Once it shows 'Installed', MANUALLY RESTART your computer.

4. After restarting, please run this script again as an administrator.

This tool will now close.
"@
        [System.Windows.Forms.MessageBox]::Show($instructions, "Manual Steps Required", "OK", "Information")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to open the Company Portal. Please contact your IT department for assistance with getting administrator rights.", "Error", "OK", "Error")
    }
    exit
}

# --- Create Logging Directory and Define Log File Path ---
# CLEANUP: Using the log directory path defined in the $config hashtable.
if (-not (Test-Path -Path $config.LogDirectory)) {
    try {
        New-Item -Path $config.LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to create log directory at '$($config.LogDirectory)'. Please check permissions.", "Error", "OK", "Error")
        exit
    }
}
$logFile = Join-Path -Path $config.LogDirectory -ChildPath "SystemMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

$gui = Initialize-GUI

# Create a PowerShell runspace to run the maintenance in the background
$ps = [powershell]::Create()
$null = $ps.AddScript({
    # This entire script block runs on the background thread.
    param($GuiControls, $maintenanceCommands, $config, $logFile)
    
    # --- CORE FUNCTIONS (Defined inside the runspace) ---

    function Log-Message {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] $GuiControls,
            [Parameter(Mandatory)] [string]$Message,
            [System.Drawing.Color]$Color = 'Black',
            [Parameter(Mandatory)] [string]$logFile
        )
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" | Out-File -FilePath $logFile -Append

        $logBox = $GuiControls.LogBox
        # This Invoke check is crucial for thread safety when updating the GUI from a background thread.
        if ($logBox.InvokeRequired) {
            $logBox.Invoke([Action[string, System.Drawing.Color, string]]{
                # Recursively call this function on the GUI's thread.
                param([string]$msg, [System.Drawing.Color]$c, [string]$lf)
                Log-Message -GuiControls $GuiControls -Message $msg -Color $c -logFile $lf
            }, $Message, $Color, $logFile)
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
            [Parameter(Mandatory)] [string]$logFile
        )
        Log-Message -GuiControls $GuiControls -Message "Running: $Name..." -logFile $logFile
        
        # Using *>&1 redirects all output streams (including errors) to the success stream for capture.
        $output = & $Command *>&1 | ForEach-Object { $_.ToString() }

        # $LASTEXITCODE is reliable for checking the success of external executables (like DISM, SFC).
        if ($LASTEXITCODE -ne 0) {
            Log-Message -GuiControls $GuiControls -Message "ERROR: '$Name' failed. Exit Code: $LASTEXITCODE" -Color "Red" -logFile $logFile
            if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Red" -logFile $logFile } } }
        } else {
            Log-Message -GuiControls $GuiControls -Message "SUCCESS: $Name completed." -Color "Green" -logFile $logFile
            if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Gray" -logFile $logFile } } }
        }
    }

    function Check-HardwareUpdates {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)] $GuiControls,
            [Parameter(Mandatory)] $config,
            [Parameter(Mandatory)] [string]$logFile
        )
        $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        Log-Message -GuiControls $GuiControls -Message "Manufacturer detected: $manufacturer" -logFile $logFile

        if ($manufacturer -like "*Dell*") {
            Log-Message -GuiControls $GuiControls -Message "Dell system detected. Searching for Dell Command | Update..." -Color "Blue" -logFile $logFile
            if (Test-Path $config.DellUpdateCLI) {
                Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Scan" -Command { & $config.DellUpdateCLI /scan } -logFile $logFile
                Invoke-LoggedCommand -GuiControls $GuiControls -Name "Dell Update Apply" -Command { & $config.DellUpdateCLI /applyUpdates -reboot=enable } -logFile $logFile
            } else {
                Log-Message -GuiControls $GuiControls -Message "NOTE: Dell Command | Update not found. Attempting automatic installation..." -Color "Orange" -logFile $logFile
                try {
                    # CLEANUP: Use the URL from the $config hashtable instead of hardcoding it here.
                    $tempPath = Join-Path $env:TEMP "DCU_Installer.exe"

                    Log-Message -GuiControls $GuiControls -Message "Downloading the installer from $($config.DellInstallerUrl)..." -logFile $logFile
                    Invoke-WebRequest -Uri $config.DellInstallerUrl -OutFile $tempPath -ErrorAction Stop
                    Log-Message -GuiControls $GuiControls -Message "Download complete." -Color "Green" -logFile $logFile

                    Log-Message -GuiControls $GuiControls -Message "Starting silent installation..." -logFile $logFile
                    Start-Process -FilePath $tempPath -ArgumentList "/s" -Wait
                    Log-Message -GuiControls $GuiControls -Message "Installation complete." -Color "Green" -logFile $logFile

                    Remove-Item -Path $tempPath -Force
                    Log-Message -GuiControls $GuiControls -Message "ACTION REQUIRED: Dell Command | Update has been installed. Please open it from the Start Menu after the restart to check for and apply driver updates manually." -Color "Orange" -logFile $logFile
                }
                catch {
                    Log-Message -GuiControls $GuiControls -Message "ERROR: Failed to automatically install Dell Command | Update. $_" -Color "Red" -logFile $logFile
                }
            }
        }
        elseif ($manufacturer -like "*HP*") {
            Log-Message -GuiControls $GuiControls -Message "HP system detected. Searching for HP Image Assistant..." -Color "Blue" -logFile $logFile
            if (Test-Path $config.HPImageAssistant) {
                Invoke-LoggedCommand -GuiControls $GuiControls -Name "HP Image Assistant Update" -Command { & $config.HPImageAssistant /Operation:Analyze /Action:Install /Silent } -logFile $logFile
            } else {
                Log-Message -GuiControls $GuiControls -Message "NOTE: HP Image Assistant not installed." -Color "Orange" -logFile $logFile
                Log-Message -GuiControls $GuiControls -Message "Please download and install it manually from: https://support.hp.com/us-en/help/hp-support-assistant" -Color "Orange" -logFile $logFile
            }
        }
        else {
            Log-Message -GuiControls $GuiControls -Message "Please check for updates using your manufacturer's tool (e.g., Lenovo Vantage)." -Color "Orange" -logFile $logFile
        }
    }

    function Start-Maintenance {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] $GuiControls,
            [Parameter(Mandatory)] $logFile,
            [Parameter(Mandatory)] $maintenanceCommands,
            [Parameter(Mandatory)] $config
        )
        Log-Message -GuiControls $GuiControls -Message "Administrator privileges confirmed. Starting maintenance..." -Color "Green" -logFile $logFile
        Log-Message -GuiControls $GuiControls -Message "Log file for this session is located at: $logFile" -Color "DarkBlue" -logFile $logFile
        
        # Add 1 to the count for the hardware check step.
        $GuiControls.ProgressBar.Maximum = $maintenanceCommands.Count + 1

        foreach ($item in $maintenanceCommands) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Command $item.Command -Name $item.Name -logFile $logFile
            if ($item.Note) { Log-Message -GuiControls $GuiControls -Message "NOTE: $($item.Note)" -Color "Orange" -logFile $logFile }
            $GuiControls.ProgressBar.Value++
        }

        Check-HardwareUpdates -GuiControls $GuiControls -config $config -logFile $logFile
        $GuiControls.ProgressBar.Value++

        Log-Message -GuiControls $GuiControls -Message "All maintenance tasks are complete. Restarting computer in 5 seconds..." -Color "DarkBlue" -logFile $logFile
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }

    # --- SCRIPT EXECUTION (Inside the runspace) ---
    Start-Maintenance -GuiControls $GuiControls -logFile $logFile -maintenanceCommands $maintenanceCommands -config $config

}).AddArgument($gui).AddArgument($maintenanceCommands).AddArgument($config).AddArgument($logFile)

# Start the background task.
$handle = $ps.BeginInvoke()

# Show the form and wait for it to be closed.
$gui.Form.ShowDialog()

# Clean up the runspace resources. This is essential to prevent memory leaks.
$ps.EndInvoke($handle)
$ps.Dispose()

#endregion
