# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
$startPath = (Get-Location).Path
$downloadsPath = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
set-location $downloadsPath
$Host.ui.rawui.backgroundcolor = "Black"
$loc = Get-Location
if (-not (Test-Path -Path $loc\Winget_Update)) {
    Write-Host "Creating Winget_Update directory in the current location..."
    New-Item -Path $loc  -Name "Winget_Update" -ItemType "Directory"
} else {
    Write-Host "Winget_Update directory already exists in the current location."
}
Set-Location -Path ".\Winget_Update"
clear-host
write-host "
┌─────────────────────────────────────────────────────────────────────────────────┐
│  █████   ███   █████  ███                                █████                  │
│ ░░███   ░███  ░░███  ░░░                                ░░███                   │
│  ░███   ░███   ░███  ████  ████████    ███████  ██████  ███████                 │
│  ░███   ░███   ░███ ░░███ ░░███░░███  ███░░███ ███░░███░░░███░                  │
│  ░░███  █████  ███   ░███  ░███ ░███ ░███ ░███░███████   ░███                   │
│   ░░░█████░█████░    ░███  ░███ ░███ ░███ ░███░███░░░    ░███ ███               │
│     ░░███ ░░███      █████ ████ █████░░███████░░██████   ░░█████                │
│      ░░░   ░░░      ░░░░░ ░░░░ ░░░░░  ░░░░░███ ░░░░░░     ░░░░░                 │
│                                       ███ ░███                                  │
│                                      ░░██████                                   │
│                                       ░░░░░░                                    │
│  █████   ███   █████                                                            │
│ ░░███   ░███  ░░███                                                             │
│  ░███   ░███   ░███  ████████   ██████   ████████  ████████   ██████  ████████  │
│  ░███   ░███   ░███ ░░███░░███ ░░░░░███ ░░███░░███░░███░░███ ███░░███░░███░░███ │
│  ░░███  █████  ███   ░███ ░░░   ███████  ░███ ░███ ░███ ░███░███████  ░███ ░░░  │
│   ░░░█████░█████░    ░███      ███░░███  ░███ ░███ ░███ ░███░███░░░   ░███      │
│     ░░███ ░░███      █████    ░░████████ ░███████  ░███████ ░░██████  █████     │
│      ░░░   ░░░      ░░░░░      ░░░░░░░░  ░███░░░   ░███░░░   ░░░░░░  ░░░░░      │
│                                          ░███      ░███                         │
│                                          █████     █████                        │
│                                         ░░░░░     ░░░░░                         │
└─────────────────────────────────────────────────────────────────────────────────┘
"
write-host ""
Install-Module ps2exe
write-host "Welcome to Winget Wrapper"
$certLocation = Get-Location
write-host "Before continuing, please make sure that you your certificate (pfx file) in the" $certLocation "directory."
$fileName = Get-ChildItem -Path . -Filter "IntuneWinAppUtil.exe"
if ($fileName -match "IntuneWinAppUtil.exe") {
    write-host "IntuneWinAppUtil is already installed."
} else {
    write-host "IntuneWinAppUtil is not installed. Downloading it now..."
    Invoke-WebRequest -Uri "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/refs/heads/master/IntuneWinAppUtil.exe" -OutFile "IntuneWinAppUtil.exe"
    write-host "IntuneWinAppUtil.exe has been downloaded successfully."
}

$AppName = Read-Host "Enter the name of the app you want to create"
winget search $AppName | Select-Object -First 10 | Format-Table -AutoSize
write-host ""
if ($LASTEXITCODE -ne 0) {
    write-host "App '$AppName' not found in winget repository. Please check the name and try again."
}

Write-Host "Make sure the app you have chosen is shown and the id is correct, if so press enter to continue otherwise type the correct id of the app"
$AppId = Read-Host "Enter the correct id of the app (or press Enter to use the name)"
if ($AppId -eq "") {
}else {
    $AppName = $AppId
}

write-host "Creating app '$AppName' with id '$AppId'..."
$AppPath = Read-Host "Enter the path where you want to create the app (default is current directory)"
if (-not $AppPath) {
    $AppPath = Get-Location
}

New-Item -Path $AppPath -Name "$AppName.ps1" -ItemType File -Force | Out-Null
set-Content -Path "$AppPath\$AppName.ps1" -Value "winget install $AppName --silent --disable-interactivity --accept-package-agreements" 
write-host "App '$AppName' created at path: $AppPath\$AppName.ps1"

write-host "----------------------------------------------------------------------------"

ps2exe -inputFile "$AppPath\$AppName.ps1" -outputFile "$AppPath\$AppName.exe" -noConsole -requireAdmin -noOutput
remove-item "$AppPath\$AppName.ps1" -Force
write-host "Executable '$AppName.exe' created at path: $AppPath\$AppName.exe"
write-host "----------------------------------------------------------------------------"
Write-Host "Signing the executable with a self-signed certificate"

$certificatePath = "$AppPath\CodeSigningCert.pfx"
$certificatePassword = Read-Host "Enter the password for the certificate" -AsSecureString
$fileToSign = "$AppPath\$AppName.exe"

$securePassword = $certificatePassword
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
write-host "----------------------------------------------------------------------------"
write-host "Now wrap the executable in a .intunewin file using IntuneWinAppUtil.exe"
.\IntuneWinAppUtil.exe -c $AppPath -s "$AppName.exe" -o $AppPath -q
write-host "The .intunewin file has been created successfully."
write-host "----------------------------------------------------------------------------"
Read-Host "Press Enter to exit the script."
set-location $startPath
break