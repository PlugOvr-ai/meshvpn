# meshvpn on Windows (CI: a GitHub Windows runner, elevated). Two nodes on this machine: "wina" with
# a Wintun interface and "winb" in userspace mode. Traffic in both directions goes through the
# Wintun interface, so this checks the driver, addresses, routes, the hosts file and the task.
#
#   tests\windows\smoke.ps1 target\release\meshvpn.exe
param([Parameter(Mandatory = $true)][string]$Binary)
$ErrorActionPreference = "Stop"
$B = (Resolve-Path $Binary).Path
$DB = Join-Path $env:TEMP "meshvpn-b"

function Fail($what) {
    Write-Host "FAIL: $what"
    foreach ($f in "$env:TEMP\a.log", "$env:TEMP\a.err", "$env:TEMP\b.log", "$env:TEMP\b.err", "C:\ProgramData\meshvpn\meshvpn.log") {
        if (Test-Path $f) { Write-Host "==> $f"; Get-Content $f -Tail 40 }
    }
    exit 1
}
function WaitFor($what, [scriptblock]$check) {
    for ($i = 0; $i -lt 60; $i++) {
        try { if (& $check) { return } } catch {}
        Start-Sleep 1
    }
    Fail "timed out: $what"
}
function Mv { & $B @args; if ($LASTEXITCODE -ne 0) { Fail "meshvpn $args (exit $LASTEXITCODE)" } }
function Json { (& $B --json @args | Out-String) | ConvertFrom-Json }

Remove-Item -Recurse -Force C:\ProgramData\meshvpn, $DB -ErrorAction SilentlyContinue
Mv init --name wina --endpoint 127.0.0.1:7870
$a = Start-Process $B -ArgumentList "up" -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\a.log" -RedirectStandardError "$env:TEMP\a.err"
WaitFor "wina running" { & $B status *> $null; $LASTEXITCODE -eq 0 }
$invite = (Json invite).invite
Mv --dir $DB join $invite --name winb --listen 0.0.0.0:47871 --userspace
# One hosts block on this machine is enough.
$cfg = Join-Path $DB "config.toml"
$lines = Get-Content $cfg | Where-Object { $_ -notmatch "^manage_hosts" }
Set-Content $cfg (@("manage_hosts = false") + $lines)
$b = Start-Process $B -ArgumentList "--dir", "`"$DB`"", "up" -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\b.log" -RedirectStandardError "$env:TEMP\b.err"
WaitFor "winb online" { ((Json status).peers | Where-Object { $_.name -eq "winb" -and $_.online }) -ne $null }

$st = Json status
$bip = (Json --dir $DB status).ip
Write-Host "wina on $($st.interface) ($($st.ip)), winb at $bip"
$adapter = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $st.ip -ErrorAction SilentlyContinue
if (-not $adapter) { Fail "no adapter with the mesh address $($st.ip)" }
if (-not (Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "winb.mesh" -Quiet)) { Fail "hosts file has no entry for winb" }

ping -n 2 -w 5000 $bip | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "ping winb through Wintun" }
New-Item -ItemType Directory -Force "$env:TEMP\www" | Out-Null
Set-Content "$env:TEMP\www\index.html" "hello-win"
$http = Start-Process python -ArgumentList "-m", "http.server", "8000", "--directory", "$env:TEMP\www" -PassThru -NoNewWindow
WaitFor "the web server" { (curl.exe -fsS -m 2 http://127.0.0.1:8000/) -match "hello-win" }
netstat -an -p TCP | Select-String "LISTENING" | Select-String ":8000 "
# out of Wintun: winb's userspace stack forwards to the server here
WaitFor "TCP into the mesh through Wintun" { (curl.exe -fsS -m 5 "http://${bip}:8000/") -match "hello-win" }
# into Wintun: from winb through the mesh to wina's address
WaitFor "TCP out of the mesh into Wintun" { (curl.exe -fsS -m 5 -x socks5h://127.0.0.1:1055 "http://wina.mesh:8000/") -match "hello-win" }
ping -n 2 -w 5000 winb.mesh | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "names: winb.mesh" }

Mv status
& $B doctor
Mv --json nodes | Out-Null

# The task: replaces the hand-started daemon
Stop-Process -Id $a.Id -Force
Start-Sleep 2
Mv install
WaitFor "wina back as a task" { ((Json status).peers | Where-Object { $_.name -eq "winb" -and $_.online }) -ne $null }
schtasks /Query /TN meshvpn | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "no scheduled task" }
Mv uninstall
schtasks /Query /TN meshvpn 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Fail "task still there after uninstall" }

Stop-Process -Id $b.Id, $http.Id -Force -ErrorAction SilentlyContinue
Write-Host "Windows smoke test passed"
