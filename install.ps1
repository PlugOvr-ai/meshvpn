# meshvpn installer for Windows (run in an elevated PowerShell: "Run as administrator").
#
#   irm https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.ps1 | iex
#
# Install and join a network in one step (the service starts automatically):
#
#   & ([scriptblock]::Create((irm https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.ps1))) join mesh1-...
#
# Environment: MESHVPN_VERSION=v0.1.0 to pin a release, MESHVPN_DOWNLOAD_URL for a mirror,
# MESHVPN_EDITION=enterprise for the enterprise edition.
#
# Works in Windows PowerShell 5.1 (also the ISE) and PowerShell 7. No "Stop" error preference: in
# Windows PowerShell, messages programs print to stderr count as errors there, so every step that
# matters checks its result itself.
$Repo = if ($env:MESHVPN_EDITION -eq "enterprise") { "PlugOvr-ai/meshvpn-enterprise-releases" } else { "PlugOvr-ai/meshvpn" }
$Version = if ($env:MESHVPN_VERSION) { $env:MESHVPN_VERSION } else { "latest" }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "meshvpn needs an administrator PowerShell (right click - Run as administrator)" }
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") { throw "no prebuilt meshvpn for $arch yet (only x86_64)" }
$target = "x86_64-pc-windows-msvc"

if ($env:MESHVPN_DOWNLOAD_URL) { $base = $env:MESHVPN_DOWNLOAD_URL.TrimEnd("/") }
elseif ($Version -eq "latest") { $base = "https://github.com/$Repo/releases/latest/download" }
else { $base = "https://github.com/$Repo/releases/download/$Version" }

$tmp = Join-Path $env:TEMP ("meshvpn-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
    $zip = "meshvpn-$target.zip"
    Write-Host "Downloading meshvpn ($Version, $target)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest "$base/$zip" -OutFile "$tmp\$zip" -UseBasicParsing -ErrorAction Stop
    Invoke-WebRequest "$base/$zip.sha256" -OutFile "$tmp\$zip.sha256" -UseBasicParsing -ErrorAction Stop
    $want = ((Get-Content "$tmp\$zip.sha256" -Raw).Trim() -split "\s+")[0]
    if ((Get-FileHash "$tmp\$zip" -Algorithm SHA256).Hash -ne $want.ToUpper()) { throw "checksum mismatch - download corrupted?" }
    Expand-Archive "$tmp\$zip" -DestinationPath "$tmp\x" -ErrorAction Stop

    $dest = Join-Path $env:ProgramFiles "meshvpn"
    New-Item -ItemType Directory -Force $dest -ErrorAction Stop | Out-Null
    # A running meshvpn holds its files: stop the task while replacing them.
    $running = $null -ne (Get-ScheduledTask -TaskName meshvpn -ErrorAction SilentlyContinue)
    if ($running) { Stop-ScheduledTask -TaskName meshvpn -ErrorAction SilentlyContinue; Start-Sleep 2 }
    Copy-Item "$tmp\x\*" $dest -Recurse -Force -ErrorAction Stop
    $path = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (($path -split ";") -notcontains $dest) {
        [Environment]::SetEnvironmentVariable("Path", "$path;$dest", "Machine")
        $env:Path = "$env:Path;$dest"
    }
    $exe = Join-Path $dest "meshvpn.exe"
    $version = & $exe --version
    if ($LASTEXITCODE -ne 0) { throw "the installed meshvpn doesn't run" }
    Write-Host "Installed $version to $exe"

    # (no `exit`: with `irm | iex` it would close the PowerShell window)
    if ($args.Count -gt 0) {
        & $exe @args
        if ($LASTEXITCODE -ne 0) { throw "meshvpn $($args[0]) failed" }
        if ($args[0] -in "init", "join") { & $exe install }
    } elseif ($running -and (Test-Path "C:\ProgramData\meshvpn\config.toml")) {
        & $exe install   # restart on the new version
    } else {
        Write-Host ""
        Write-Host "Next: create a network with   meshvpn init"
        Write-Host "      or join one with        meshvpn join <invite>"
        Write-Host "      then start it with      meshvpn install"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
