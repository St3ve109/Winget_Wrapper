# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
$Host.ui.rawui.backgroundcolor = "Black"
make-directory -ErrorAction SilentlyContinue -Path "$env:temp\Winget_Update"
$env:PSModulePath += ";$env:temp\Winget_Update"
write-host Get-Location
clear-host
write-host " __          ___                  _     _    _           _       _            "
write-host " \ \        / (_)                | |   | |  | |         | |     | |           "
write-host "  \ \  /\  / / _ _ __   __ _  ___| |_  | |  | |_ __   __| | __ _| |_ ___ _ __ "
write-host "   \ \/  \/ / | | '_ \ / _` |/ _ \ __| | |  | | '_ \ / _` |/ _` | __/ _ \ '__|"
write-host "    \  /\  /  | | | | | (_| |  __/ |_  | |__| | |_) | (_| | (_| | ||  __/ |   "
write-host "     \/  \/   |_|_| |_|\__, |\___|\__|  \____/| .__/ \__,_|\__,_|\__\___|_|   "
write-host "                        __/ |                 | |                             "
write-host "                       |___/                  |_|                             "
write-host ""
write-host "----------------------------------------"
Install-Module ps2exe
write-host "Welcome to the App Maker Script!"
$fileName = Get-ChildItem -Path . -Filter "IntuneWinAppUtil.exe"
if ($fileName -match "IntuneWinAppUtil.exe") {
    write-host "IntuneWinAppUtil is already installed."
} else {
    write-host "IntuneWinAppUtil is not installed. Downloading it now..."
    Invoke-WebRequest -Uri "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/refs/heads/master/IntuneWinAppUtil.exe" -OutFile "IntuneWinAppUtil.exe"
    write-host "IntuneWinAppUtil.exe has been downloaded successfully."
}

$AppName = Read-Host "Enter the name of the app you want to create: "
winget search $AppName | Select-Object -First 10 | Format-Table -AutoSize
write-host ""
if ($LASTEXITCODE -ne 0) {
    write-host "App '$AppName' not found in winget repository. Please check the name and try again."
}

Write-Host "Make sure the app you have chosen is shown and the id is correct, if so press enter to continue otherwise type the correct id of the app"
$AppId = Read-Host "Enter the correct id of the app (or press Enter to use the name): "
if ($AppId -eq "") {
}else {
    $AppName = $AppId
}

write-host "Creating app '$AppName' with id '$AppId'..."
$AppPath = Read-Host "Enter the path where you want to create the app (default is current directory): "
if (-not $AppPath) {
    $AppPath = Get-Location
}

New-Item -Path $AppPath -Name "$AppName.ps1" -ItemType File -Force | Out-Null
set-Content -Path "$AppPath\$AppName.ps1" -Value "winget install $AppName --silent --disable-interactivity --accept-package-agreements" 
write-host "App '$AppName' created at path: $AppPath\$AppName.ps1"

write-host "----------------------------------------"

ps2exe -inputFile "$AppPath\$AppName.ps1" -outputFile "$AppPath\$AppName.exe" -noConsole -requireAdmin -noOutput
remove-item "$AppPath\$AppName.ps1" -Force
write-host "Executable '$AppName.exe' created at path: $AppPath\$AppName.exe"
Write-Host "Signing the executable with a self-signed certificate"

$certificatePath = Read-Host "Enter the path to your self-signed certificate (PFX file): "
$certificatePassword = Read-Host "Enter the password for the certificate: " -AsSecureString
$fileToSign = "$AppPath\$AppName.exe"

$securePassword = ConvertTo-SecureString -String $certificatePassword -Force -AsPlainText
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath, $securePassword)

Set-AuthenticodeSignature -FilePath $fileToSign -Certificate $certificate

$signedFile = "$AppPath\$AppName.exe"
$signature = Get-AuthenticodeSignature -FilePath $signedFile

if ($signature.Status -eq "Valid")
{
    Write-Host "Signature is valid."
}
else
{
    Write-Host "Signature is not valid."
    break
}
write-host "----------------------------------------"
write-host "Now wrap the executable in a .intunewin file using IntuneWinAppUtil.exe"
.\IntuneWinAppUtil.exe -c $AppPath -s "$AppName.exe" -o $AppPath -q
write-host "The .intunewin file has been created successfully."
write-host "----------------------------------------"
Read-Host "Press Enter to exit the script."
break