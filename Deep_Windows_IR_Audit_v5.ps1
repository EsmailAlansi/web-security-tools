<#
.SYNOPSIS
    Deep Windows 11 forensic audit - PowerShell 5.1 compatible, read-only by default.

.DESCRIPTION
    Collects services, processes, drivers, scheduled tasks, WMI persistence,
    Run/RunOnce, Startup folders, IFEO/Winlogon/AppInit-related registry,
    network connections, firewall profiles/rules, DNS/proxy/hosts, local users/groups,
    installed software, AppX packages, Defender/Kaspersky state, selected event logs,
    executable signatures/hashes and weak ACLs.

    The script deliberately separates OBSERVATION from FINDING. It does not treat
    "Auto + LocalSystem + unquoted" as malicious by itself, which avoids the
    false-positive pattern seen in earlier versions.

    READ-ONLY by default. No service is stopped/deleted, no file is modified,
    and no registry key is changed.

.PARAMETER OutputRoot
    Root directory for evidence. Default: C:\Forensic_IR

.PARAMETER DeepHashAllExecutables
    Hash every executable that can be resolved. This is slower.

.PARAMETER CollectEventLogs
    Export selected Security/System/Defender Operational events.

.PARAMETER EventDays
    Number of days of event history to collect. Default: 14.

.EXAMPLE
    .\Deep_Windows_IR_Audit_v5.ps1 -CollectEventLogs

.EXAMPLE
    .\Deep_Windows_IR_Audit_v5.ps1 -CollectEventLogs -EventDays 30 -DeepHashAllExecutables
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = 'C:\Forensic_IR',
    [switch]$DeepHashAllExecutables,
    [switch]$CollectEventLogs,
    [int]$EventDays = 14
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out = Join-Path $OutputRoot ("DeepWindowsIR_v5_" + $stamp)
$raw = Join-Path $out 'Raw'
New-Item -ItemType Directory -Path $raw -Force | Out-Null

$Findings = New-Object System.Collections.ArrayList
$Errors = New-Object System.Collections.ArrayList

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')] [string]$Level='INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath (Join-Path $out 'Audit.log') -Value $line -Encoding UTF8
}

function Add-ErrorRecord {
    param([string]$Stage, [string]$Message)
    [void]$Errors.Add([PSCustomObject]@{
        Time = Get-Date
        Stage = $Stage
        Message = $Message
    })
    Write-Log "$Stage : $Message" 'WARN'
}

function Add-Finding {
    param(
        [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')] [string]$Severity,
        [string]$Category,
        [string]$Name,
        [string]$Path='',
        [string]$Reason='',
        [string]$Evidence='',
        [string]$Recommendation=''
    )
    [void]$Findings.Add([PSCustomObject]@{
        Time = Get-Date
        Severity = $Severity
        Category = $Category
        Name = $Name
        Path = $Path
        Reason = $Reason
        Evidence = $Evidence
        Recommendation = $Recommendation
    })
}

function Is-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Resolve-Executable([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $s = $CommandLine.Trim()
    if ($s.StartsWith('"')) {
        $i = $s.IndexOf('"',1)
        if ($i -gt 1) { return $s.Substring(1,$i-1) }
    }
    $m = [regex]::Match($s, '^(?<e>[A-Za-z]:\\.*?\.(exe|com|bat|cmd))(?=\s|$)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups['e'].Value }
    return $s
}

function Test-SuspiciousLocation([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $s = $Path.ToLowerInvariant()
    return ($s -match '\\users\\[^\\]+\\appdata\\' -or
            $s -match '\\temp\\|\\tmp\\' -or
            $s -match '\\downloads\\' -or
            $s -match '\\desktop\\' -or
            $s -match '\\public\\' -or
            $s -match '\\recycle\.bin\\')
}

function Get-FileSignature([string]$Path) {
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return (Get-AuthenticodeSignature -LiteralPath $Path).Status.ToString()
        }
    } catch {}
    return ''
}

function Get-FileHashSafe([string]$Path) {
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        }
    } catch {}
    return ''
}

function Get-FileVersionSafe([string]$Path) {
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $v = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
            return "Company=$($v.CompanyName);Product=$($v.ProductName);FileVersion=$($v.FileVersion);Original=$($v.OriginalFilename)"
        }
    } catch {}
    return ''
}

function Get-WeakWriteAcl([string]$Path) {
    try {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
        $a = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $hits = @()
        foreach ($ace in @($a.Access)) {
            $broad = $ace.IdentityReference.Value -match '^(Everyone|BUILTIN\\Users|Authenticated Users)$'
            $write = $ace.FileSystemRights.ToString() -match 'FullControl|Modify|Write|WriteData|CreateFiles|AppendData'
            if ($broad -and $write) { $hits += "$($ace.IdentityReference):$($ace.FileSystemRights)" }
        }
        return ($hits -join ' | ')
    } catch { return '' }
}

function Get-ExeIdentity([string]$Path, [bool]$ForceHash=$false) {
    $sig = Get-FileSignature $Path
    $hash = ''
    if ($ForceHash -or $sig -eq 'NotSigned' -or (Test-SuspiciousLocation $Path)) {
        $hash = Get-FileHashSafe $Path
    }
    [PSCustomObject]@{
        Signature = $sig
        SHA256 = $hash
        Version = Get-FileVersionSafe $Path
    }
}

function Export-CsvSafe {
    param($Data, [string]$Name)
    try {
        @($Data) | Export-Csv -LiteralPath (Join-Path $out $Name) -NoTypeInformation -Encoding UTF8
    } catch {
        Add-ErrorRecord "Export:$Name" $_.Exception.Message
    }
}

function Export-TextSafe {
    param([string]$Text, [string]$Name)
    try { $Text | Out-File -LiteralPath (Join-Path $raw $Name) -Encoding UTF8 } catch { Add-ErrorRecord "ExportText:$Name" $_.Exception.Message }
}

Write-Log 'Starting Deep Windows IR Audit v5.'
Write-Log "Computer=$env:COMPUTERNAME User=$env:USERNAME PowerShell=$($PSVersionTable.PSVersion) Admin=$(Is-Admin)"

# System identity
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $os | Format-List * | Out-File -LiteralPath (Join-Path $raw 'OS.txt') -Encoding UTF8
    Add-Finding 'INFO' 'System' 'Operating System' '' 'System baseline collected' "Caption=$($os.Caption);Version=$($os.Version);Build=$($os.BuildNumber);LastBoot=$($os.LastBootUpTime)" ''
} catch { Add-ErrorRecord 'System:OS' $_.Exception.Message }

try {
    Get-ComputerInfo | Out-File -LiteralPath (Join-Path $raw 'ComputerInfo.txt') -Encoding UTF8
} catch { Add-ErrorRecord 'System:ComputerInfo' $_.Exception.Message }

# Services
Write-Log 'Scanning services: signer, hash, ACL, command, account, start mode.'
$services = @()
try {
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
        $exe = Resolve-Executable $s.PathName
        $id = Get-ExeIdentity $exe $DeepHashAllExecutables.IsPresent
        $acl = Get-WeakWriteAcl $exe
        $unquoted = $false
        if ($s.PathName -and $s.PathName -match '\s' -and $s.PathName -notmatch '^".*?"') { $unquoted = $true }

        $isMicrosoftSvchost = ($exe -and $exe.ToLowerInvariant() -eq 'c:\windows\system32\svchost.exe')
        $thirdParty = -not ($isMicrosoftSvchost -or ($exe -and $exe.ToLowerInvariant().StartsWith('c:\windows\')))

        if ($acl) {
            Add-Finding 'CRITICAL' 'Service' $s.Name $exe 'Writable by broad local principals while service runs under a privileged account' "State=$($s.State);StartMode=$($s.StartMode);StartName=$($s.StartName);ACL=$acl" 'Restrict the executable/directory ACL immediately; then update, repair, or remove the owning application.'
        } elseif ($thirdParty -and $s.StartName -match 'LocalSystem|LocalService|NetworkService' -and $id.Signature -eq 'NotSigned' -and $s.StartMode -eq 'Auto') {
            Add-Finding 'HIGH' 'Service' $s.Name $exe 'Unsigned third-party auto-start service running with a service account' "State=$($s.State);StartName=$($s.StartName);SHA256=$($id.SHA256);Version=$($id.Version)" 'Validate publisher, origin, hash, software installation, and persistence before deciding to remove it.'
        } elseif ($thirdParty -and $unquoted -and $s.StartName -eq 'LocalSystem') {
            Add-Finding 'LOW' 'Service' $s.Name $exe 'Potential unquoted service path requires verification' "PathName=$($s.PathName);Signer=$($id.Signature)" 'Verify the executable path and vendor. A path-format issue alone is not proof of exploitation.'
        }

        $services += [PSCustomObject]@{
            Name=$s.Name;DisplayName=$s.DisplayName;State=$s.State;StartMode=$s.StartMode;StartName=$s.StartName;PID=$s.ProcessId
            PathName=$s.PathName;Executable=$exe;Signature=$id.Signature;SHA256=$id.SHA256;Version=$id.Version
            WeakWriteACL=$acl;PotentialUnquoted=$unquoted
        }
    }
} catch { Add-ErrorRecord 'Services' $_.Exception.Message }
Export-CsvSafe $services 'Services.csv'

# Processes
Write-Log 'Scanning processes, command lines, parents, signatures and selective hashes.'
$processes = @()
try {
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $id = Get-ExeIdentity $p.ExecutablePath $DeepHashAllExecutables.IsPresent
        if ($p.ExecutablePath -and $id.Signature -eq 'NotSigned' -and (Test-SuspiciousLocation $p.ExecutablePath)) {
            Add-Finding 'HIGH' 'Process' $p.Name $p.ExecutablePath 'Unsigned process running from a user-controlled/high-risk directory' "PID=$($p.ProcessId);PPID=$($p.ParentProcessId);CommandLine=$($p.CommandLine);SHA256=$($id.SHA256)" 'Validate signer, hash, parent process, launch source and persistence.'
        }
        $processes += [PSCustomObject]@{
            PID=$p.ProcessId;PPID=$p.ParentProcessId;Name=$p.Name;ExecutablePath=$p.ExecutablePath;CommandLine=$p.CommandLine
            Signature=$id.Signature;SHA256=$id.SHA256;Version=$id.Version
        }
    }
} catch { Add-ErrorRecord 'Processes' $_.Exception.Message }
Export-CsvSafe $processes 'Processes.csv'

# Drivers
Write-Log 'Scanning system drivers.'
$drivers = @()
try {
    foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)) {
        $exe = Resolve-Executable $d.PathName
        $id = Get-ExeIdentity $exe $true
        if ($id.Signature -eq 'NotSigned' -and $exe) {
            Add-Finding 'HIGH' 'Driver' $d.Name $exe 'Unsigned system driver' "State=$($d.State);StartMode=$($d.StartMode);StartName=$($d.StartName);SHA256=$($id.SHA256)" 'Verify origin, publisher and hash before allowing kernel-mode persistence.'
        }
        $drivers += [PSCustomObject]@{
            Name=$d.Name;DisplayName=$d.DisplayName;State=$d.State;StartMode=$d.StartMode;StartName=$d.StartName
            PathName=$d.PathName;Executable=$exe;Signature=$id.Signature;SHA256=$id.SHA256;Version=$id.Version
        }
    }
} catch { Add-ErrorRecord 'Drivers' $_.Exception.Message }
Export-CsvSafe $drivers 'Drivers.csv'

# Scheduled Tasks
Write-Log 'Scanning scheduled tasks.'
$tasks = @()
try {
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        try {
            $xml = [xml](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop)
            $execs = @($xml.Task.Actions.Exec)
            if ($execs.Count -eq 0) {
                $tasks += [PSCustomObject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;State=$t.State;ActionType='Non-Exec/Unknown';Command='';Arguments='';Executable='';Signature='';SHA256=''}
            } else {
                foreach ($a in $execs) {
                    $cmd = [string]$a.Command
                    $exe = Resolve-Executable $cmd
                    $id = Get-ExeIdentity $exe $DeepHashAllExecutables.IsPresent
                    if ($exe -and $id.Signature -eq 'NotSigned' -and (Test-SuspiciousLocation $exe)) {
                        Add-Finding 'HIGH' 'ScheduledTask' ($t.TaskPath+$t.TaskName) $exe 'Unsigned executable from a user-controlled/high-risk location launched by a scheduled task' "State=$($t.State);Command=$cmd;Args=$($a.Arguments);SHA256=$($id.SHA256)" 'Validate task author, trigger, signer, hash and software origin.'
                    }
                    $tasks += [PSCustomObject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;State=$t.State;ActionType='Exec';Command=$cmd;Arguments=$a.Arguments;Executable=$exe;Signature=$id.Signature;SHA256=$id.SHA256}
                }
            }
        } catch {
            $tasks += [PSCustomObject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;State=$t.State;ActionType='ERROR';Command=$_.Exception.Message;Arguments='';Executable='';Signature='';SHA256=''}
            Add-ErrorRecord 'ScheduledTask' ("$($t.TaskPath)$($t.TaskName): " + $_.Exception.Message)
        }
    }
} catch { Add-ErrorRecord 'ScheduledTasks' $_.Exception.Message }
Export-CsvSafe $tasks 'ScheduledTasks.csv'

# Autoruns
Write-Log 'Scanning Run/RunOnce, Startup and common Winlogon/IFEO persistence points.'
$autoruns = @()
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($rk in $runKeys) {
    try {
        if (Test-Path $rk) {
            $p = Get-ItemProperty -Path $rk -ErrorAction Stop
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                $cmd = [string]$prop.Value
                $exe = Resolve-Executable $cmd
                $id = Get-ExeIdentity $exe $DeepHashAllExecutables.IsPresent
                if ($exe -and $id.Signature -eq 'NotSigned' -and (Test-SuspiciousLocation $exe)) {
                    Add-Finding 'HIGH' 'Autorun' "$rk::$($prop.Name)" $exe 'Unsigned executable in a user-writable path starts automatically' "Command=$cmd;SHA256=$($id.SHA256)" 'Validate the entry, owner, signer, hash and install source.'
                }
                $autoruns += [PSCustomObject]@{Location=$rk;Name=$prop.Name;Command=$cmd;Executable=$exe;Signature=$id.Signature;SHA256=$id.SHA256}
            }
        }
    } catch { Add-ErrorRecord "Autorun:$rk" $_.Exception.Message }
}

try {
    foreach ($u in @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {$_.LocalPath})) {
        $sp = Join-Path $u.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        if (Test-Path $sp) {
            foreach ($f in @(Get-ChildItem -LiteralPath $sp -Force -ErrorAction SilentlyContinue)) {
                $id = Get-ExeIdentity $f.FullName $false
                if ($id.Signature -eq 'NotSigned') {
                    Add-Finding 'MEDIUM' 'Startup' $f.Name $f.FullName 'Unsigned file in a Startup directory' "UserProfile=$($u.LocalPath);SHA256=$($id.SHA256)" 'Validate whether the file is user-installed software.'
                }
                $autoruns += [PSCustomObject]@{Location=$sp;Name=$f.Name;Command=$f.FullName;Executable=$f.FullName;Signature=$id.Signature;SHA256=$id.SHA256}
            }
        }
    }
} catch { Add-ErrorRecord 'StartupFolders' $_.Exception.Message }
Export-CsvSafe $autoruns 'Autoruns.csv'

# High-value registry snapshots
$regTargets = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
)
foreach ($r in $regTargets) {
    try { Get-ItemProperty -Path $r -ErrorAction Stop | Format-List * | Out-File -LiteralPath (Join-Path $raw ('Registry_' + ($r -replace '[\\/:*?"<>| ]','_') + '.txt')) -Encoding UTF8 }
    catch { Add-ErrorRecord "Registry:$r" $_.Exception.Message }
}

# IFEO (Image File Execution Options)
try {
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        if (Test-Path $base) {
            foreach ($sub in @(Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                try {
                    $p = Get-ItemProperty $sub.PSPath -ErrorAction Stop
                    if ($p.Debugger -or $p.GlobalFlag -or $p.VerifierDlls) {
                        Add-Finding 'HIGH' 'IFEO' $sub.PSChildName ([string]$p.Debugger) 'Non-default IFEO override present' "Debugger=$($p.Debugger);GlobalFlag=$($p.GlobalFlag);VerifierDlls=$($p.VerifierDlls)" 'Validate whether the override is a legitimate developer/debugging configuration.'
                    }
                } catch { Add-ErrorRecord 'IFEOEntry' $_.Exception.Message }
            }
        }
    }
} catch { Add-ErrorRecord 'IFEO' $_.Exception.Message }

# WMI Permanent Subscriptions
Write-Log 'Scanning WMI permanent event subscriptions.'
$wmiRows = @()
try {
    $ns='root/subscription'
    $filters=@(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)
    $consumers=@(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop)
    $bindings=@(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)
    foreach ($f in $filters) {
        $wmiRows += [PSCustomObject]@{Type='EventFilter';Name=$f.Name;Query=$f.Query;Class=$f.CimClass.CimClassName;Details=''}
    }
    foreach ($c in $consumers) {
        $class = $c.CimClass.CimClassName
        $details = ''
        $path = ''
        if ($class -eq 'CommandLineEventConsumer') {
            $path = [string]$c.ExecutablePath
            $details = "ExecutablePath=$($c.ExecutablePath);CommandLineTemplate=$($c.CommandLineTemplate)"
            Add-Finding 'HIGH' 'WMI' ([string]$c.Name) $path 'CommandLineEventConsumer provides a persistent process-launch mechanism' $details 'Validate creator, executable signer/hash and binding.'
        } elseif ($class -eq 'ActiveScriptEventConsumer') {
            $details = "ScriptFileName=$($c.ScriptFileName);ScriptText=$($c.ScriptText)"
            Add-Finding 'HIGH' 'WMI' ([string]$c.Name) '' 'ActiveScriptEventConsumer provides a persistent script execution mechanism' $details 'Validate creator, script source and binding.'
        } else {
            $details = ($c | Format-List * | Out-String).Trim()
        }
        $wmiRows += [PSCustomObject]@{Type='EventConsumer';Name=$c.Name;Query='';Class=$class;Details=$details}
    }
    foreach ($b in $bindings) {
        $wmiRows += [PSCustomObject]@{Type='Binding';Name=$b.__RELPATH;Query='';Class='__FilterToConsumerBinding';Details="Filter=$($b.Filter);Consumer=$($b.Consumer)"}
    }
} catch { Add-ErrorRecord 'WMI' $_.Exception.Message }
Export-CsvSafe $wmiRows 'WMIPermanentSubscriptions.csv'

# Network State
Write-Log 'Collecting network state, connections, proxy, DNS, hosts and firewall configuration.'
try { Get-NetTCPConnection -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'TCPConnections.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Network:TCP' $_.Exception.Message }
try { Get-NetUDPEndpoint -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'UDPEndpoints.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Network:UDP' $_.Exception.Message }
try { Get-NetFirewallProfile -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'FirewallProfiles.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Network:FirewallProfiles' $_.Exception.Message }
try { Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Select-Object DisplayName,Enabled,Direction,Action,Profile,Program,Service | Export-Csv -LiteralPath (Join-Path $out 'FirewallRules.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Network:FirewallRules' $_.Exception.Message }
try { Get-DnsClientServerAddress -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'DNSClientServers.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Network:DNS' $_.Exception.Message }
try { Get-DnsClientNrptPolicy -ErrorAction Stop | Format-List * | Out-File -LiteralPath (Join-Path $raw 'DNS_NRPT.txt') -Encoding UTF8 } catch { }
try { netsh winhttp show proxy | Out-File -LiteralPath (Join-Path $raw 'WinHTTP_Proxy.txt') -Encoding UTF8 } catch { Add-ErrorRecord 'Network:WinHTTPProxy' $_.Exception.Message }
try { Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | Format-List * | Out-File -LiteralPath (Join-Path $raw 'UserProxy.txt') -Encoding UTF8 } catch { }

# Hosts file
$hosts = Join-Path $env:windir 'System32\drivers\etc\hosts'
try {
    $hi = Get-Item -LiteralPath $hosts -ErrorAction Stop
    $hh = Get-FileHashSafe $hosts
    $content = Get-Content -LiteralPath $hosts -ErrorAction Stop
    $active = @($content | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*;' })
    $hostRows = @()
    foreach ($line in $active) {
        $hostRows += [PSCustomObject]@{Line=$line}
        if ($line -match '^\s*0\.0\.0\.0\s+|^\s*127\.0\.0\.1\s+|^\s*::1\s+') {
            Add-Finding 'MEDIUM' 'HostsFile' 'Active hosts entry' $hosts 'Custom hosts mapping present; assess whether intentionally configured' "Entry=$line;SHA256=$hh;LastWrite=$($hi.LastWriteTime)" 'Preserve the file, identify the writer, and remove/reset entries only after confirming the intended policy.'
        } else {
            Add-Finding 'MEDIUM' 'HostsFile' 'Custom hosts mapping' $hosts 'Non-comment hosts entry present' "Entry=$line;SHA256=$hh;LastWrite=$($hi.LastWriteTime)" 'Validate the destination and reason for the mapping.'
        }
    }
    $hostRows | Export-Csv -LiteralPath (Join-Path $out 'HostsActiveEntries.csv') -NoTypeInformation -Encoding UTF8
    Copy-Item -LiteralPath $hosts -Destination (Join-Path $out 'hosts.snapshot') -Force
    Add-Content -LiteralPath (Join-Path $raw 'hosts.metadata.txt') -Value ((Get-Item $hosts | Format-List FullName,Length,CreationTime,LastWriteTime | Out-String) + "SHA256=$hh") -Encoding UTF8
} catch { Add-ErrorRecord 'Network:Hosts' $_.Exception.Message }

# Local accounts and admins
Write-Log 'Collecting local account and local administrators state.'
try {
    Get-LocalUser -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'LocalUsers.csv') -NoTypeInformation -Encoding UTF8
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'LocalAdministrators.csv') -NoTypeInformation -Encoding UTF8
} catch { Add-ErrorRecord 'Accounts' $_.Exception.Message }

# Installed software
Write-Log 'Collecting installed software from 32-bit and 64-bit uninstall hives.'
$software = @()
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($uk in $uninstallKeys) {
    try {
        foreach ($item in @(Get-ItemProperty -Path $uk -ErrorAction SilentlyContinue)) {
            $software += [PSCustomObject]@{
                DisplayName = [string]$item.DisplayName
                DisplayVersion = [string]$item.DisplayVersion
                Publisher = [string]$item.Publisher
                InstallDate = [string]$item.InstallDate
                InstallLocation = [string]$item.InstallLocation
                UninstallString = [string]$item.UninstallString
                PSPath = [string]$item.PSPath
            }
        }
    } catch { Add-ErrorRecord "Software:$uk" $_.Exception.Message }
}
Export-CsvSafe $software 'InstalledSoftware.csv'

# AppX inventory
try { Get-AppxPackage -AllUsers -ErrorAction Stop | Select-Object Name,PackageFullName,Publisher,Version,InstallLocation | Export-Csv -LiteralPath (Join-Path $out 'AppXPackages.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'AppX' $_.Exception.Message }

# AV / Security providers
Write-Log 'Collecting antivirus/security provider state.'
try { Get-Service WinDefend -ErrorAction Stop | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'WinDefendService.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Defender:Service' $_.Exception.Message }
try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,pathToSignedProductExe,productState | Export-Csv -LiteralPath (Join-Path $out 'AntiVirusProducts.csv') -NoTypeInformation -Encoding UTF8 } catch { Add-ErrorRecord 'Defender:SecurityCenter2' $_.Exception.Message }
try { if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { Get-MpComputerStatus | Format-List * | Out-File -LiteralPath (Join-Path $raw 'DefenderStatus.txt') -Encoding UTF8 } else { Add-ErrorRecord 'Defender:Status' 'Get-MpComputerStatus is unavailable in this PowerShell session.' } } catch { Add-ErrorRecord 'Defender:Status' $_.Exception.Message }
try { if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) { Get-MpThreatDetection | Select-Object * | Export-Csv -LiteralPath (Join-Path $out 'DefenderThreatDetections.csv') -NoTypeInformation -Encoding UTF8 } } catch { Add-ErrorRecord 'Defender:Threats' $_.Exception.Message }

# Selected event logs
if ($CollectEventLogs) {
    Write-Log "Collecting selected event logs for the last $EventDays day(s)."
    $start = (Get-Date).AddDays(-1 * [math]::Max(1,$EventDays))
    $queries = @(
        @{Name='Defender1116'; LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116},
        @{Name='Defender1117'; LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1117},
        @{Name='Defender1119'; LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1119},
        @{Name='Security4624'; LogName='Security'; Id=4624},
        @{Name='Security4672'; LogName='Security'; Id=4672},
        @{Name='Security4688'; LogName='Security'; Id=4688},
        @{Name='Security4697'; LogName='Security'; Id=4697},
        @{Name='System7045'; LogName='System'; Id=7045}
    )
    foreach ($q in $queries) {
        try {
            Get-WinEvent -FilterHashtable @{LogName=$q.LogName;Id=$q.Id;StartTime=$start} -ErrorAction Stop |
                Select-Object TimeCreated,Id,ProviderName,Message |
                Export-Csv -LiteralPath (Join-Path $out ($q.Name + '.csv')) -NoTypeInformation -Encoding UTF8
        } catch { Add-ErrorRecord "Event:$($q.Name)" $_.Exception.Message }
    }
}

# Special Hunt: Wondershare remnants
try {
    $wonder = @($services | Where-Object { $_.Name -match 'Wondershare|Wsid|WsApp' -or $_.Executable -match 'Wondershare|Wsid|WsApp' })
    Export-CsvSafe $wonder 'Wondershare_Service_Focus.csv'
} catch {}

# Final Summary
$summary = [PSCustomObject]@{
    Computer = $env:COMPUTERNAME
    User = "$env:USERDOMAIN\$env:USERNAME"
    PowerShell = $PSVersionTable.PSVersion.ToString()
    Admin = Is-Admin
    OutputDirectory = $out
    FindingCount = $Findings.Count
    ErrorCount = $Errors.Count
    Critical = @($Findings | Where-Object Severity -eq 'CRITICAL').Count
    High = @($Findings | Where-Object Severity -eq 'HIGH').Count
    Medium = @($Findings | Where-Object Severity -eq 'MEDIUM').Count
    Low = @($Findings | Where-Object Severity -eq 'LOW').Count
    Info = @($Findings | Where-Object Severity -eq 'INFO').Count
}
$summary | Format-List * | Out-File -LiteralPath (Join-Path $out 'Summary.txt') -Encoding UTF8
$Findings | Export-Csv -LiteralPath (Join-Path $out 'Findings.csv') -NoTypeInformation -Encoding UTF8
$Findings | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $out 'Findings.json') -Encoding UTF8
$Errors | Export-Csv -LiteralPath (Join-Path $out 'CollectionErrors.csv') -NoTypeInformation -Encoding UTF8
$script:Findings = $Findings

Write-Log '========== FINAL SUMMARY =========='
Write-Log "CRITICAL=$($summary.Critical) HIGH=$($summary.High) MEDIUM=$($summary.Medium) LOW=$($summary.Low) INFO=$($summary.Info) ERRORS=$($summary.ErrorCount)"
Write-Log "Evidence directory: $out"
Write-Log 'Audit complete. No remediation actions were performed.'
