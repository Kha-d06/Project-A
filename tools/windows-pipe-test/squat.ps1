<#
  Pipe-squatting test for qalaa-ipc (docs/windows-pipe-test.md). Test machines only.

  Run as the ATTACKER account. Creates the pipe the victim's Qalaa service would
  use, lets anyone connect, and logs how many bytes a connecting client sends and
  whether they contain a hello. It never prints the bytes themselves, so a real
  token isn't copied into the log.

    powershell -ExecutionPolicy Bypass -File squat.ps1 -User victim            # the old fixed name
    powershell -ExecutionPolicy Bypass -File squat.ps1 -Name qalaa-daemon-...  # an exact pipe name
#>
param(
  [string]$User = "",
  [string]$Name = "",
  [int]$Seconds = 120,
  [string]$Log = (Join-Path $env:TEMP "qalaa-squat.log")
)

if (-not $Name -and -not $User) { Write-Output "Give -User or -Name."; exit 2 }
$name = if ($Name) { $Name } else { "qalaa-daemon-" + ($User -replace '[^A-Za-z0-9_-]', '_') }
$security = New-Object System.IO.Pipes.PipeSecurity
$security.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule("Everyone", "ReadWrite", "Allow")))
try {
  $pipe = New-Object System.IO.Pipes.NamedPipeServerStream($name, "InOut", 1, "Byte", "Asynchronous", 4096, 4096, $security)
} catch {
  "$(Get-Date -Format o) could not create \\.\pipe\$name : $($_.Exception.Message)" | Tee-Object -FilePath $Log -Append
  exit 2
}
"$(Get-Date -Format o) listening on \\.\pipe\$name for $Seconds s" | Tee-Object -FilePath $Log -Append

$wait = $pipe.BeginWaitForConnection($null, $null)
if (-not $wait.AsyncWaitHandle.WaitOne($Seconds * 1000)) {
  "$(Get-Date -Format o) no client connected" | Tee-Object -FilePath $Log -Append
  exit 0
}
$pipe.EndWaitForConnection($wait)
"$(Get-Date -Format o) a client connected" | Tee-Object -FilePath $Log -Append

$buffer = New-Object byte[] 65536
$total = 0
$sawHello = $false
$deadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $deadline) {
  $read = $pipe.BeginRead($buffer, 0, $buffer.Length, $null, $null)
  if (-not $read.AsyncWaitHandle.WaitOne(1000)) { continue }
  $n = $pipe.EndRead($read)
  if ($n -le 0) { break }
  $total += $n
  if ([Text.Encoding]::UTF8.GetString($buffer, 0, $n) -match '"method"\s*:\s*"hello"') { $sawHello = $true }
}
"$(Get-Date -Format o) client sent $total bytes; hello with token: $sawHello" | Tee-Object -FilePath $Log -Append
$pipe.Dispose()
if ($sawHello) { exit 1 } else { exit 0 }
