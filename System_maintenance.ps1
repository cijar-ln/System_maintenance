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
        to the main GUI window. A permanent text log file is also created in 'C:\Program Files\Maintenance'
        for each session for later analysis.

    7.  Final Restart: Upon completion of all tasks, it performs a final, automatic restart to ensure all
        changes are fully applied.
#>

#region --- Configuration ---

$config = @{
    DellUpdateCLI       = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    HPImageAssistant    = "C:\Program Files (x86)\HP\HP Image Assistant\HPImageAssistant.exe"
    CompanyPortalAppUri = "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"
}

# Define the sequence of maintenance commands to be executed.
$maintenanceCommands = @(
    @{ Name = "Flushing DNS Cache";             Command = { ipconfig /flushdns } },
    @{ Name = "Forcing Group Policy Update";    Command = { gpupdate /force } },

    # --- NEW COMMANDS START HERE ---
    @{ Name = "Restarting Windows Explorer";    Command = { Stop-Process -Name explorer -Force; Start-Process explorer } },
    @{ Name = "Checking for Windows Updates";    Command = { wuauclt /detectnow; wuauclt /reportnow } },
    # --- NEW COMMANDS END HERE ---

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
    # --- NEW NON-ADMIN WORKFLOW ---
    try {
        # Define the URI for the Company Portal application
        $CompanyPortalAppUri = "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"

        # Show a message box to inform the user what is about to happen
        [System.Windows.Forms.MessageBox]::Show("This script requires administrator rights. We will now open the Company Portal so you can install them.", "Administrator Required", "OK", "Information")

        # Open the Company Portal to the specific app
        Start-Process $CompanyPortalAppUri

        # Define the detailed instructions for the user
        $instructions = @"
ACTION REQUIRED:

The Company Portal app has been opened for you.

1. Please find and click the 'Install' button for the admin rights application. If it says "Reinstall" or "Uninstall", just close the Company Portal and re-run the Maintenance Tool as an Administrator.

2. WAIT for the installation to fully complete.

3. Once it shows 'Installed', MANUALLY RESTART your computer.

4. After restarting, please run this script again as an administrator.

This tool will now close.
"@
        # Show the final instructions and wait for the user to acknowledge
        [System.Windows.Forms.MessageBox]::Show($instructions, "Manual Steps Required", "OK", "Information")
    }
    catch {
        # Fallback error if the Company Portal URI fails
        [System.Windows.Forms.MessageBox]::Show("Failed to open the Company Portal. Please contact your IT department for assistance with getting administrator rights.", "Error", "OK", "Error")
    }

    # Exit the script after guiding the user
    exit
}

# --- Create Logging Directory and Define Log File Path ---
$logDirectory = "C:\Program Files\Maintenance"
if (-not (Test-Path -Path $logDirectory)) {
    try {
        New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to create log directory at '$logDirectory'. Please check permissions.", "Error", "OK", "Error")
        exit
    }
}
$logFile = Join-Path -Path $logDirectory -ChildPath "SystemMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
# --- End of Logging Configuration ---

$gui = Initialize-GUI

# Create a PowerShell runspace to run the maintenance in the background
$ps = [powershell]::Create()
$ps.AddScript({
    # This entire script block runs on the background thread.
    # We pass in the required variables from the main script.
    param($GuiControls, $maintenanceCommands, $config, $logFile)
    
    # --- CORE FUNCTIONS (Defined inside the runspace) ---

    function Log-Message {
        param($GuiControls, [string]$Message, [System.Drawing.Color]$Color = 'Black', [string]$logFile)

        # Log to the text file first
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" | Out-File -FilePath $logFile -Append

        # Then, update the GUI
        $logBox = $GuiControls.LogBox
        if ($logBox.InvokeRequired) {
            $logBox.Invoke([Action[string, System.Drawing.Color, string]]{
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
        param($GuiControls, [scriptblock]$Command, [string]$Name, [string]$logFile)
        
        Log-Message -GuiControls $GuiControls -Message "Running: $Name..." -logFile $logFile
        $output = & $Command *>&1 | ForEach-Object { $_.ToString() }

        if ($LASTEXITCODE -ne 0) {
            Log-Message -GuiControls $GuiControls -Message "ERROR: '$Name' failed. Exit Code: $LASTEXITCODE" -Color "Red" -logFile $logFile
            if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Red" -logFile $logFile } } }
        } else {
            Log-Message -GuiControls $GuiControls -Message "SUCCESS: $Name completed." -Color "Green" -logFile $logFile
            if ($output) { $output | ForEach-Object { if ($_.Trim()) { Log-Message -GuiControls $GuiControls -Message "  $_" -Color "Gray" -logFile $logFile } } }
        }
    }

function Check-HardwareUpdates {
    param ($GuiControls, $config, [string]$logFile) # Added $config parameter

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
                $installerUrl = "https://dl.dell.com/FOLDER13309509M/1/Dell-Command-Update-Application_PPWHH_WIN64_5.5.0_A00.EXE"
                $tempPath = Join-Path $env:TEMP "DCU_Installer.exe"

                Log-Message -GuiControls $GuiControls -Message "Downloading the installer..." -logFile $logFile
                Invoke-WebRequest -Uri $installerUrl -OutFile $tempPath
                Log-Message -GuiControls $GuiControls -Message "Download complete." -Color "Green" -logFile $logFile

                Log-Message -GuiControls $GuiControls -Message "Starting silent installation..." -logFile $logFile
                Start-Process -FilePath $tempPath -ArgumentList "/s" -Wait
                Log-Message -GuiControls $GuiControls -Message "Installation complete." -Color "Green" -logFile $logFile

                Remove-Item -Path $tempPath -Force
                Log-Message -GuiControls $GuiControls -Message "ACTION REQUIRED: Dell Command | Update has been installed. Please open it from the Start Menu after the restart to check for and apply driver updates manually." -Color "Orange" -logFile $logFile
            }
            catch {
                Log-Message -GuiControls $GuiControls -Message "ERROR: Failed to automatically install Dell Command | Update. Please do it manually." -Color "Red" -logFile $logFile
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
        param($GuiControls, [string]$logFile)

        Log-Message -GuiControls $GuiControls -Message "Administrator privileges confirmed. Starting maintenance..." -Color "Green" -logFile $logFile
        Log-Message -GuiControls $GuiControls -Message "Log file for this session is located at: $logFile" -Color "DarkBlue" -logFile $logFile
        
        $GuiControls.ProgressBar.Maximum = $maintenanceCommands.Count + 1

        foreach ($item in $maintenanceCommands) {
            Invoke-LoggedCommand -GuiControls $GuiControls -Command $item.Command -Name $item.Name -logFile $logFile
            if ($item.Note) { Log-Message -GuiControls $GuiControls -Message "NOTE: $($item.Note)" -Color "Orange" -logFile $logFile }
            $GuiControls.ProgressBar.Value++
        }

        Check-HardwareUpdates -GuiControls $GuiControls -config $config -logFile $logFile
        $GuiControls.ProgressBar.Value++

        Log-Message -GuiControls $GuiControls -Message "All maintenance tasks are complete. Restarting computer..." -Color "DarkBlue" -logFile $logFile
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }

    # --- SCRIPT EXECUTION (Inside the runspace) ---
    # Now that the functions are defined, call the main one.
    Start-Maintenance -GuiControls $GuiControls -logFile $logFile

}).AddArgument($gui).AddArgument($maintenanceCommands).AddArgument($config).AddArgument($logFile) | Out-Null # Pass the $logFile path into the runspace

# Start the background task. This call returns immediately.
$handle = $ps.BeginInvoke()

# Show the form. It will now be responsive while the background task runs.
# ShowDialog() blocks the script here until the user closes the form.
$gui.Form.ShowDialog()

# Clean up the runspace when the form is closed
$ps.EndInvoke($handle)
$ps.Dispose()

#endregion
