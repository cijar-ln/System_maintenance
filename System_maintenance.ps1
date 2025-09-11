<#
.SYNOPSIS
    A verbose, GUI-based tool designed to run a comprehensive suite of Windows 11 maintenance and troubleshooting commands.
    It intelligently handles administrative rights by either using existing ones or by automatically initiating their installation
    via the corporate Company Portal, and also applies manufacturer-specific firmware and driver updates.

.DESCRIPTION
    This script provides a user-friendly graphical interface (GUI) to guide a user or technician through a standardized
    system health and repair process. Its operational flow is as follows:

    1.  Initial User Confirmation: Before any action is taken, it presents a clear pop-up dialog warning the user that
        the process is lengthy and will involve one or more automatic computer restarts. The script will only proceed
        if the user explicitly agrees.

    2.  Administrative Privilege Check: The script determines if it is currently running with elevated (administrator) privileges.
        - If NOT running as admin: It will automatically launch the Intune Company Portal and send the keystrokes to initiate
          the installation of temporary admin rights. It then instructs the user to wait for completion, manually restart,
          and run the script again. The script then exits.
        - If running as admin: It proceeds directly to the main maintenance tasks.

    3.  Main Maintenance Sequence: Executes a carefully ordered sequence of system commands designed to resolve common
        Windows issues, starting with the least impactful and progressing to more comprehensive repairs (e.g., DNS flush,
        SFC scan, DISM component store repair).

    4.  Hardware-Specific Updates: It detects the computer's manufacturer (specifically Dell or HP).
        - For Dell machines, if the utility is not found, it automatically downloads, installs, and opens it, instructing the user to apply updates manually.
        - For HP machines, if the utility is not found, it provides a download link and instructs the user to install it and apply all updates.
        - For other manufacturers, it provides on-screen guidance.

    5.  Real-time Logging: All actions, successes, errors, and informational notes are logged in real-time to the main GUI window.

    6.  Final Restart: Upon completion of all tasks, it performs a final, automatic restart to ensure all changes are fully applied.
#>

#region --- Initial Setup and GUI Definition ---

# VERBOSE: Loading .NET Framework Assemblies. These are essential for creating a Graphical User Interface (GUI) in PowerShell.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- GUI Components Definition ---
# VERBOSE: Here, we are creating each individual component of our user interface as an object.

# Create the main window (the form). This is the container for all other controls.
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "System Maintenance Tool"
$mainForm.Size = New-Object System.Drawing.Size(600, 500)
$mainForm.StartPosition = "CenterScreen"
$mainForm.FormBorderStyle = 'FixedSingle'
$mainForm.MaximizeBox = $false

# Create a text label for the log box.
$label = New-Object System.Windows.Forms.Label
$label.Text = "Status Log:"
$label.Location = New-Object System.Drawing.Point(10, 10)
$label.Size = New-Object System.Drawing.Size(560, 20)

# Create the main text box where all status messages and logs will be displayed.
$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Location = New-Object System.Drawing.Point(10, 30)
$logBox.Size = New-Object System.Drawing.Size(565, 370)
$logBox.Font = "Consolas, 10"
$logBox.ReadOnly = $true
$logBox.ScrollBars = "Vertical"

# Create a progress bar to give the user a visual indication of the script's progress.
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 415)
$progressBar.Size = New-Object System.Drawing.Size(565, 25)
$progressBar.Style = "Continuous"

# VERBOSE: Now, add all the created controls to the main form's collection of controls.
$mainForm.Controls.Add($label)
$mainForm.Controls.Add($logBox)
$mainForm.Controls.Add($progressBar)

# --- Helper Function to Log Messages to the GUI ---
# VERBOSE: This is a reusable function to make logging messages to the RichTextBox easier and more consistent.
function Log-Message {
    param(
        [string]$Message,
        [System.Drawing.Color]$Color = 'Black'
    )
    
    if ($mainForm.IsHandleCreated) {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionLength = 0
        $logBox.SelectionColor = $Color
        $logBox.AppendText("$(Get-Date -Format 'HH:mm:ss') - $Message`n")
        $logBox.ScrollToCaret()
        $mainForm.Update()
    }
    else {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - $Message"
    }
}

#endregion

#region --- Core Logic ---

# VERBOSE: This function contains the primary maintenance tasks. It will only be called if the script is running as an administrator.
function Start-Maintenance {
    # 1. Initial Warning in GUI Log
    Log-Message "Starting System Maintenance..." -Color "DarkBlue"
    Log-Message "*****************************************************" -Color "Red"
    Log-Message "REMINDER: This process may take a long time and your" -Color "Red"
    Log-Message "computer may restart one or more times." -Color "Red"
    Log-Message "*****************************************************" -Color "Red"
    Start-Sleep -Seconds 5

    # 2. Define Commands
    $commands = @(
        [pscustomobject]@{ Name = "Flushing DNS Cache";              Command = { ipconfig /flushdns } },
        [pscustomobject]@{ Name = "Forcing Group Policy Update";     Command = { gpupdate /force } },
        [pscustomobject]@{ Name = "Restarting Windows Explorer";      Command = { Stop-Process -Name explorer -Force; Start-Process explorer.exe } },
        [pscustomobject]@{ Name = "Checking for Windows Updates";    Command = { wuauclt /detectnow; wuauclt /reportnow } },
        [pscustomobject]@{ Name = "Resetting Winsock Catalog";       Command = { netsh winsock reset } },
        [pscustomobject]@{ Name = "Resetting TCP/IP Stack";          Command = { netsh int ip reset } },
        [pscustomobject]@{ Name = "Checking System File Integrity (SFC)"; Command = { sfc /scannow } },
        [pscustomobject]@{ Name = "Checking Component Store Health (DISM)"; Command = { DISM /Online /Cleanup-Image /ScanHealth } },
        [pscustomobject]@{ Name = "Restoring Component Store (DISM)"; Command = { DISM /Online /Cleanup-Image /RestoreHealth } },
        [pscustomobject]@{ Name = "Scheduling Disk Check for Errors (C:)"; Command = { cmd.exe /c "echo y | chkdsk C: /f /r" }; Note = "This will run on the next restart." }
    )

    $progressBar.Maximum = $commands.Count + 1

    # 3. Execute Commands
    foreach ($item in $commands) {
        try {
            Log-Message "Running: $($item.Name)..."
            & $item.Command | Out-Null
            Log-Message "SUCCESS: $($item.Name) completed." -Color "Green"
            if ($item.Note) {
                Log-Message "NOTE: $($item.Note)" -Color "Orange"
            }
        }
        catch {
            Log-Message "ERROR: Failed to run '$($item.Name)'. Details: $($_.Exception.Message)" -Color "Red"
        }
        $progressBar.Value++
    }

    # 4. Manufacturer-Specific Updates
    Check-Hardware-Updates

    # 5. Final message
    Log-Message "----------------------------------------------------" -Color "DarkBlue"
    Log-Message "All maintenance tasks are complete!" -Color "DarkBlue"
    Log-Message "A final restart is required to apply all changes (like Check Disk)." -Color "DarkBlue"
    Start-Sleep -Seconds 5
    if ((New-Object -ComObject "Shell.Application").Windows().Count -gt 0) {
        Restart-Computer -Force
    }
}

# VERBOSE: This function handles the detection of the computer's manufacturer and runs the appropriate update utility.
function Check-Hardware-Updates {
    Log-Message "Checking computer manufacturer for updates..."
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    Log-Message "Manufacturer detected: $manufacturer"

    if ($manufacturer -like "*Dell*") {
        Log-Message "Dell system detected. Searching for Dell Command | Update..." -Color "Blue"
        $dcuCliPath = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
        if (Test-Path $dcuCliPath) {
            Log-Message "Dell Command | Update found. Scanning for updates silently..."
            Start-Process -FilePath $dcuCliPath -ArgumentList "/scan" -Wait
            Log-Message "Applying all available updates silently..."
            Start-Process -FilePath $dcuCliPath -ArgumentList "/applyUpdates -reboot=enable" -Wait
            Log-Message "Dell updates applied." -Color "Green"
        }
        else {
            Log-Message "NOTE: Dell Command | Update is not installed. Attempting automatic installation..." -Color "Orange"
            
            try {
                $installerUrl = "https://dl.dell.com/FOLDER13309509M/1/Dell-Command-Update-Application_PPWHH_WIN64_5.5.0_A00.EXE"
                $tempPath = Join-Path $env:TEMP "DCU_Installer.exe"

                Log-Message "Downloading the installer from Dell..."
                Invoke-WebRequest -Uri $installerUrl -OutFile $tempPath
                Log-Message "Download complete." -Color "Green"

                Log-Message "Starting silent installation (this may take a few minutes)..."
                Start-Process -FilePath $tempPath -ArgumentList "/s" -Wait
                Log-Message "Installation complete." -Color "Green"

                Remove-Item -Path $tempPath -Force

                $dcuGuiPath = "C:\Program Files\Dell\CommandUpdate\DellCommandUpdate.exe"
                if (Test-Path $dcuGuiPath) {
                    Log-Message "Opening Dell Command | Update for you now..."
                    Start-Process -FilePath $dcuGuiPath

                    $instructions = @"
ACTION REQUIRED:

Dell Command | Update has been installed and opened for you.

Please click the 'CHECK' button in that window and apply all recommended driver and firmware updates.

This script will continue its own tasks in the background.
"@
                    [System.Windows.Forms.MessageBox]::Show($instructions, "Manual Update Required", "OK", "Information")
                    Log-Message "ACTION: Please use the DCU window to install all hardware updates." -Color "Orange"
                }
                else {
                    Throw "DCU was installed, but the GUI application could not be found."
                }
            }
            catch {
                Log-Message "ERROR: Failed to automatically install Dell Command | Update." -Color "Red"
                Log-Message "Details: $($_.Exception.Message)" -Color "Red"
                Log-Message "Please install it manually from the web." -Color "Orange"
            }
        }
    }
    elseif ($manufacturer -like "*HP*" -or $manufacturer -like "*Hewlett-Packard*") {
        Log-Message "HP system detected. Searching for HP update utility..." -Color "Blue"
        $hpPath = "C:\Program Files\HP\HPImageAssistant\HPImageAssistant.exe" # Path for the enterprise tool
        if (Test-Path $hpPath) {
            Log-Message "HP Image Assistant found. Analyzing system and installing updates silently..."
            Start-Process -FilePath $hpPath -ArgumentList "/Operation:Analyze /Action:Install /Silent" -Wait
            Log-Message "HP updates applied." -Color "Green"
        }
        else {
            # MODIFIED: If HPIA is not found, provide a direct download link for HP Support Assistant and instructions.
            Log-Message "NOTE: HP Support Assistant / Image Assistant is not installed." -Color "Orange"
            Log-Message "Please download and install it from the following link:" -Color "Orange"
            Log-Message "https://support.hp.com/us-en/help/hp-support-assistant" -Color "Orange"
            Log-Message "After installation, please open the application and install all available updates." -Color "Orange"
        }
    }
    else {
        # For any other brand, provide helpful guidance.
        Log-Message "Non-Dell/HP system detected. Please manually check for manufacturer updates." -Color "Orange"
        Log-Message "Lenovo: Use the 'Lenovo Vantage' app." -Color "Orange"
        Log-Message "ASUS: Use the 'MyASUS' app." -Color "Orange"
        Log-Message "Acer: Use the 'Acer Care Center' app." -Color "Orange"
    }
    # Increment the progress bar for this final step.
    $progressBar.Value++
}

#endregion
#region --- Entry Point, Confirmation & Elevation ---

# --- 1. Pre-Execution User Confirmation ---
$confirmationMessage = @"
WARNING: This tool will perform system maintenance and install updates.

The process may take a significant amount of time and will likely restart your computer one or more times without further warning.

Please save all your work and close all applications before proceeding.

Do you want to continue?
"@
$confirmationTitle = "Confirmation Required"
$buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
$icon = [System.Windows.Forms.MessageBoxIcon]::Warning

$result = [System.Windows.Forms.MessageBox]::Show($confirmationMessage, $confirmationTitle, $buttons, $icon)

if ($result -ne 'Yes') {
    exit
}

# --- 2. Elevation Check and Handling ---
$mainForm.Show()

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # --- NON-ADMIN WORKFLOW (AUTOMATED INSTALL START) ---
    try {
        Log-Message "Administrator rights not detected." -Color "Red"
        Log-Message "Attempting to automatically start the admin rights installation..." -Color "Orange"
        Start-Sleep -Seconds 3

        Log-Message "Launching Company Portal application..."
        Start-Process "companyportal:ApplicationId=9f4e3de0-34be-47c0-be5d-b2c237f85125"
        
        Log-Message "Waiting 15 seconds for the app to load..."
        Start-Sleep -Seconds 15

        Log-Message "Sending install command (Ctrl+I)..."
        [System.Windows.Forms.SendKeys]::SendWait("^{i}")
        Log-Message "Installation command sent successfully." -Color "Green"

        $instructions = @"
ACTION REQUIRED:

The installation for admin rights has been automatically started for you.

1.  Please monitor the Company Portal window and WAIT for the installation to fully complete.

2.  Once you see a 'Completed' or 'Installed' status, MANUALLY RESTART your computer.

3.  After restarting, please run this script again to perform the maintenance.

This tool will now close.
"@
        $instructionsTitle = "Manual Restart Required"
        
        Log-Message "----------------------------------------------------" -Color "DarkBlue"
        Log-Message "Please follow the steps in the pop-up window to complete the process." -Color "Orange"
        
        [System.Windows.Forms.MessageBox]::Show($instructions, $instructionsTitle, "OK", "Information")
    }
    catch {
        Log-Message "ERROR: Failed to automate the installation process." -Color "Red"
        Log-Message "Please contact your IT department for assistance." -Color "Red"
        Start-Sleep -Seconds 10
    }
    
    $mainForm.Close()
    exit
}
else {
    # --- ADMIN WORKFLOW ---
    Log-Message "Administrator privileges confirmed. Starting maintenance..." -Color "Green"
    Start-Sleep -Seconds 2
    
    Start-Maintenance
}

#endregion
