#requires -Version 5.1
<#
.SYNOPSIS
  SpaceTrace filesystem inventory with interactive HTML, CSV and JSON exports.
.EXAMPLE
  .\SpaceTrace.ps1
.EXAMPLE
  .\SpaceTrace.ps1 -Path 'D:\CustomerBackups\Paid' -Formats All -Threads 8 -NonInteractive
.EXAMPLE
  .\SpaceTrace.ps1 -Path '\\server\share\archive' -Formats Html,Csv -Threads 6 -NonInteractive
.EXAMPLE
  .\SpaceTrace.ps1 -Path 'E:\' -Allocated -Formats All -NonInteractive
.EXAMPLE
  # All reports and logs go to .\yyyyMMdd_HHmmss_HOSTNAME by default.
  .\SpaceTrace.ps1 -Path '\\SERVER\Share\Backups' -Formats All -NonInteractive
.NOTES
  Windows PowerShell 5.1+ or PowerShell 7+, Windows recommended. -Allocated uses Win32 GetCompressedFileSizeW
  for every file and can substantially increase scan time, especially over SMB.
  Default reports logical size; allocated bytes remain unknown (not fabricated).
  Access denied and reparse-point directories are not followed. This avoids cycles.
  Size totals are a scan-time snapshot, not a transactional filesystem snapshot.
#>
[CmdletBinding()]
param(
  [string[]]$Path,
  [ValidateSet('Html','Csv','Json','All')][string[]]$Formats = @('All'),
  [ValidateRange(1,32)][int]$Threads = [Math]::Min(8, [Environment]::ProcessorCount),
  [ValidateRange(1,16)][int]$ChunkFactor = 6,
  [string]$OutDir = (Get-Location).ProviderPath,
  [switch]$Allocated,
  [switch]$NonInteractive,
  [string]$SessionDir
)
$ErrorActionPreference = 'Stop'
$script:OnWindows = ($env:OS -eq 'Windows_NT')
$script:ErrorLimit = 2000
$script:ScanLog = $null
$script:LastResults = $null

if ($Allocated -and -not $script:OnWindows) { throw '-Allocated requires Windows.' }
if ($script:OnWindows -and -not ('NativeStorage.Allocation' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
namespace NativeStorage {
  public static class Allocation {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="GetCompressedFileSizeW")]
    private static extern uint GetCompressedFileSize(string fileName, out uint high);
    public static long? Get(string path) {
      uint high; uint low = GetCompressedFileSize(path, out high);
      int error = Marshal.GetLastWin32Error();
      if (low == UInt32.MaxValue && error != 0) return null;
      return ((long)high << 32) | low;
    }
  }
}
'@
}

function Write-ScanLog([string]$Message, [string]$Level='INFO') {
  $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
  if ($script:ScanLog) { Add-Content -LiteralPath $script:ScanLog -Value $line -Encoding utf8 }
  if ($Level -eq 'WARN') { Write-Warning $Message }
  else { Write-Host $line -ForegroundColor $(if ($Level -eq 'ERROR') { 'Red' } else { 'DarkGray' }) }
}
function Get-ScanOutputDirectory([string]$BaseDirectory, [string]$TargetPath, [string]$HostOverride) {
  # UNC server name takes precedence; mapped/local drive paths use this computer.
  $targetHost = $env:COMPUTERNAME
  if ($TargetPath -match '^[\\/]{2}([^\\/]+)[\\/]') { $targetHost = $Matches[1] }
  if ($HostOverride) { $targetHost = $HostOverride }
  if ([string]::IsNullOrWhiteSpace($targetHost)) { $targetHost = [Environment]::MachineName }
  $safeHost = ($targetHost -replace '[^A-Za-z0-9_.-]', '_').Trim(' ._')
  if (-not $safeHost) { $safeHost = 'UnknownHost' }
  $dateStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $folderName = '{0}_{1}' -f $dateStamp, $safeHost
  $base = [Environment]::ExpandEnvironmentVariables($BaseDirectory)
  if (-not [IO.Path]::IsPathRooted($base)) { $base = Join-Path (Get-Location).ProviderPath $base }
  $destination = Join-Path $base $folderName
  # Prevent accidental re-use in rapid consecutive runs.
  $suffix = 1
  while (Test-Path -LiteralPath $destination) {
    $destination = Join-Path $base ('{0}_{1:D2}' -f $folderName, $suffix)
    $suffix++
  }
  $null = New-Item -ItemType Directory -Path $destination -Force
  return $destination
}

function Get-CanonicalPath([string]$InputPath) {
  $p = [Environment]::ExpandEnvironmentVariables($InputPath.Trim().Trim('"'))
  if (-not $p) { throw 'A filesystem path is required.' }
  $item = Get-Item -LiteralPath $p -Force -ErrorAction Stop
  if (-not $item.PSIsContainer) { throw "The target must be a directory: $p" }
  # Preserve the UNC root or drive root; otherwise strip final separators.
  $full = [IO.Path]::GetFullPath($item.FullName)
  $root = [IO.Path]::GetPathRoot($full)
  if ($full.Length -gt $root.Length) { $full = $full.TrimEnd('\','/') }
  return $full
}
function Get-LocalTargets {
  $result = [Collections.Generic.List[object]]::new()
  if ($script:OnWindows) {
    try {
      foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        $result.Add([pscustomobject]@{ Path=($d.DeviceID+'\'); Label=$d.VolumeName; Size=[long]$d.Size; Free=[long]$d.FreeSpace })
      }
    } catch { Write-Warning "CIM discovery failed; falling back to PowerShell drives: $_" }
  }
  if ($result.Count -eq 0) {
    foreach ($d in (Get-PSDrive -PSProvider FileSystem)) {
      $result.Add([pscustomobject]@{ Path=$d.Root; Label=$d.Name; Size=$null; Free=$d.Free })
    }
  }
  return $result.ToArray()
}
function Get-RemoteTargets([string]$Computer) {
  if (-not $script:OnWindows) { throw 'Remote host drive discovery requires Windows. You can still enter UNC paths manually.' }
  $computer = $Computer.Trim().TrimStart('\')
  if ($computer -notmatch '^[a-zA-Z0-9_.-]+$') { throw 'Enter a valid hostname or FQDN.' }
  $targets = [Collections.Generic.List[object]]::new()
  try {
    $session = New-CimSession -ComputerName $computer -ErrorAction Stop
    try {
      foreach ($d in @(Get-CimInstance Win32_LogicalDisk -CimSession $session -Filter 'DriveType=3' -ErrorAction Stop)) {
        $remotePath = '\\{0}\{1}$\' -f $computer,$d.DeviceID.Substring(0,1)
        if (Test-Path -LiteralPath $remotePath) {
          $targets.Add([pscustomobject]@{Path=$remotePath;Label=$d.VolumeName;Size=[long]$d.Size;Free=[long]$d.FreeSpace})
        }
      }
    } finally { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
  } catch { Write-Warning "CIM discovery unavailable: $($_.Exception.Message)" }
  if ($targets.Count -eq 0) {
    foreach ($drive in @('C','D','E','F','G')) {
      $candidate = '\\{0}\{1}$\' -f $computer,$drive
      if (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue) {
        $targets.Add([pscustomobject]@{Path=$candidate;Label='Accessible admin share';Size=$null;Free=$null})
      }
    }
  }
  return $targets.ToArray()
}
function Select-Targets([object[]]$Targets) {
  if (-not $Targets -or $Targets.Count -eq 0) { Write-Warning 'No accessible targets found.'; return @() }
  Write-Host ''
  for ($i=0; $i -lt $Targets.Count; $i++) {
    $t=$Targets[$i]
    $sizeText=if ($null -ne $t.Size) { '{0:N1} GB' -f ($t.Size / 1GB) } else { 'size unknown' }
    Write-Host (' [{0}] {1,-35} {2,-22} {3}' -f ($i+1),$t.Path,$t.Label,$sizeText)
  }
  Write-Host ' [A] All accessible targets   Multiple: enter 1,3,4   [Enter] Cancel'
  $selection=(Read-Host 'Select drive number(s) or A').Trim()
  if (-not $selection) { return @() }
  if ($selection -match '^(?i:all|a)$') { return @($Targets | ForEach-Object { $_.Path }) }
  $choices=[Collections.Generic.List[string]]::new()
  foreach ($piece in ($selection -split '[,; ]+' | Where-Object { $_ })) {
    $number=0
    if (-not [int]::TryParse($piece,[ref]$number) -or $number -lt 1 -or $number -gt $Targets.Count) {
      Write-Warning "Invalid drive selection: $piece"; return @()
    }
    $drive=[string]$Targets[$number-1].Path
    if (-not $choices.Contains($drive)) { $choices.Add($drive) }
  }
  return $choices.ToArray()
}

function Resolve-Targets([string[]]$CandidatePaths) {
  $found=[Collections.Generic.List[string]]::new()
  foreach ($candidate in $CandidatePaths) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    $canonical=Get-CanonicalPath $candidate
    if (-not $found.Contains($canonical)) { $found.Add($canonical) }
  }
  return $found.ToArray()
}
function Get-TargetHost([string]$TargetPath) {
  if ($TargetPath -match '^[\\/]{2}([^\\/]+)[\\/]') { return $Matches[1] }
  return [Environment]::MachineName
}
function Get-SessionHostName([string[]]$Targets) {
  $names=@($Targets | ForEach-Object { Get-TargetHost $_ } | Sort-Object -Unique)
  if ($names.Count -eq 1) { return $names[0] }
  return 'MULTIHOST'
}
function Get-ReportKey([string]$TargetPath) {
  $prefix=($TargetPath -replace '[^A-Za-z0-9_-]','_').Trim('_')
  if ($prefix.Length -gt 45) { $prefix=$prefix.Substring(0,45) }
  $sha=[Security.Cryptography.SHA256]::Create()
  try {
    $bytes=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($TargetPath.ToLowerInvariant()))
    $hash=([BitConverter]::ToString($bytes,0,4)).Replace('-','')
  } finally { $sha.Dispose() }
  return ('{0}_{1}' -f $prefix,$hash)
}

# One pass per directory; each partition independently processes its assigned subtree.
# Avoid exporting per-file data: this keeps memory proportional to folder count.
$script:Worker = {
  param([string]$StartPath, [bool]$MeasureAllocated, [int]$ErrorLimitPerChunk)
  $nodes = [Collections.Generic.List[object]]::new()
  $errors = [Collections.Generic.List[object]]::new()
  $stack = [Collections.Generic.Stack[string]]::new()
  $stack.Push($StartPath)
  [long]$seenFiles = 0
  [long]$skippedLinks = 0
  $topFiles = [Collections.Generic.List[object]]::new()
  $fileTypes = @{}
  $fileAges = @{'0-30 days'=@{Count=[long]0;Bytes=[long]0};'31-90 days'=@{Count=[long]0;Bytes=[long]0};'91-365 days'=@{Count=[long]0;Bytes=[long]0};'Over 1 year'=@{Count=[long]0;Bytes=[long]0}}
  $ageReference = [datetime]::UtcNow
  while ($stack.Count -gt 0) {
    $p = $stack.Pop()
    $directBytes = [long]0; $directFiles = [long]0; $directDirs = [long]0
    $allocatedBytes = [long]0; $allocationMissing = [long]0
    $modified = $null; $hadError = $false
    try { $modified = [IO.Directory]::GetLastWriteTimeUtc($p).ToString('o') } catch {}
    try {
      $folder = [IO.DirectoryInfo]::new($p)
      foreach ($entry in $folder.EnumerateFileSystemInfos()) {
        try {
          if (($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            $directDirs++
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $skippedLinks++; continue }
            $stack.Push($entry.FullName)
          } else {
            $directFiles++; $seenFiles++
            $size = [long]([IO.FileInfo]$entry).Length
            $directBytes += $size

            $ext = [IO.Path]::GetExtension($entry.Name).ToLowerInvariant()
            if ([string]::IsNullOrEmpty($ext)) { $ext='[none]' }
            if (-not $fileTypes.ContainsKey($ext)) { $fileTypes[$ext]=@{Count=[long]0;Bytes=[long]0} }
            $fileTypes[$ext]['Count'] = [long]$fileTypes[$ext]['Count'] + 1
            $fileTypes[$ext]['Bytes'] = [long]$fileTypes[$ext]['Bytes'] + [long]$size
            $fileDate = $entry.LastWriteTimeUtc
            $days=($ageReference-$fileDate).TotalDays
            $bucket=if($days -le 30){'0-30 days'}elseif($days -le 90){'31-90 days'}elseif($days -le 365){'91-365 days'}else{'Over 1 year'}
            $fileAges[$bucket]['Count'] = [long]$fileAges[$bucket]['Count'] + 1
            $fileAges[$bucket]['Bytes'] = [long]$fileAges[$bucket]['Bytes'] + [long]$size
            if ($topFiles.Count -lt 100 -or [long]$size -gt [long]$topFiles[$topFiles.Count-1].SizeBytes) {
              $topFiles.Add([pscustomobject]@{Path=$entry.FullName;SizeBytes=[long]$size;LastModifiedUtc=$fileDate.ToString('o');Extension=$ext})
              if ($topFiles.Count -gt 1) {
                $sortedTop=@($topFiles | Sort-Object SizeBytes -Descending)
                $topFiles.Clear()
                foreach($candidate in $sortedTop | Select-Object -First 100){$topFiles.Add($candidate)}
              }
            }
            if ($MeasureAllocated) {
              $alloc = [NativeStorage.Allocation]::Get($entry.FullName)
              if ($null -eq $alloc) { $allocationMissing++ }
              else { $allocatedBytes += [long]$alloc }
            }
          }
        } catch {
          $hadError = $true
          if ($errors.Count -lt $ErrorLimitPerChunk) { $errors.Add([pscustomobject]@{Path=$entry.FullName;Message=$_.Exception.Message}) }
        }
      }
    } catch {
      $hadError = $true
      if ($errors.Count -lt $ErrorLimitPerChunk) { $errors.Add([pscustomobject]@{Path=$p;Message=$_.Exception.Message}) }
    }
    $parent = [IO.Path]::GetDirectoryName($p.TrimEnd('\','/'))
    if ($p -match '^[a-zA-Z]:\\?$' -or $p -match '^\\\\[^\\]+\\[^\\]+\\?$') { $parent = $null }
    $nodes.Add([pscustomobject]@{
      Path=$p; Parent=$parent; Name=([IO.Path]::GetFileName($p.TrimEnd('\','/')));
      DirectBytes=$directBytes;DirectFiles=$directFiles;DirectFolders=$directDirs;
      AllocatedDirect=$(if ($MeasureAllocated) { $allocatedBytes } else { $null });
      AllocationMissing=$allocationMissing;LastModified=$modified;HasError=$hadError
    })
  }
  return [pscustomobject]@{Nodes=$nodes.ToArray();Errors=$errors.ToArray();Files=$seenFiles;SkippedLinks=$skippedLinks;Partitions=1;TopFiles=$topFiles.ToArray();FileTypes=$fileTypes;FileAges=$fileAges}
}

function Invoke-TreeScan([string]$Target,[int]$WorkerCount,[int]$SplitFactor,[bool]$MeasureAllocated) {
  $started = Get-Date
  $target = Get-CanonicalPath $Target
  Write-ScanLog "Starting $target | threads=$WorkerCount | target partitions=$($WorkerCount*$SplitFactor) | allocated=$MeasureAllocated"
  $allNodes = [Collections.Generic.List[object]]::new()
  $issues = [Collections.Generic.List[object]]::new()
  $topFiles = [Collections.Generic.List[object]]::new()
  $fileTypes = @{}
  $fileAges = @{'0-30 days'=@{Count=[long]0;Bytes=[long]0};'31-90 days'=@{Count=[long]0;Bytes=[long]0};'91-365 days'=@{Count=[long]0;Bytes=[long]0};'Over 1 year'=@{Count=[long]0;Bytes=[long]0}}
  $ageReference = [datetime]::UtcNow
  $frontier = [Collections.Generic.Queue[object]]::new()
  $frontier.Enqueue([pscustomobject]@{Path=$target;Depth=0})
  $desired = [Math]::Max(1, $WorkerCount*$SplitFactor)
  [long]$skipped = 0
  # Breadth-first splitting scans each skeleton directory exactly once.
  # Hard cap on skeleton depth prevents excessive preprocessing.
  while ($frontier.Count -gt 0 -and $frontier.Count -lt $desired -and $frontier.Peek().Depth -lt 5) {
    $task = $frontier.Dequeue(); $p = $task.Path
    [long]$bytes=0; [long]$fileCount=0; [long]$dirCount=0; [long]$allocBytes=0; [long]$missing=0
    $hadError=$false; $modified=$null
    try { $modified = [IO.Directory]::GetLastWriteTimeUtc($p).ToString('o') } catch {}
    try {
      foreach ($entry in ([IO.DirectoryInfo]::new($p)).EnumerateFileSystemInfos()) {
        try {
          if (($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            $dirCount++
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $skipped++; continue }
            $frontier.Enqueue([pscustomobject]@{Path=$entry.FullName;Depth=($task.Depth+1)})
          } else {
            $fileCount++; $bytes += [long]([IO.FileInfo]$entry).Length
            $entrySize=[long]([IO.FileInfo]$entry).Length

            $ext = [IO.Path]::GetExtension($entry.Name).ToLowerInvariant()
            if ([string]::IsNullOrEmpty($ext)) { $ext='[none]' }
            if (-not $fileTypes.ContainsKey($ext)) { $fileTypes[$ext]=@{Count=[long]0;Bytes=[long]0} }
            $fileTypes[$ext]['Count'] = [long]$fileTypes[$ext]['Count'] + 1
            $fileTypes[$ext]['Bytes'] = [long]$fileTypes[$ext]['Bytes'] + [long]$entrySize
            $fileDate = $entry.LastWriteTimeUtc
            $days=($ageReference-$fileDate).TotalDays
            $bucket=if($days -le 30){'0-30 days'}elseif($days -le 90){'31-90 days'}elseif($days -le 365){'91-365 days'}else{'Over 1 year'}
            $fileAges[$bucket]['Count'] = [long]$fileAges[$bucket]['Count'] + 1
            $fileAges[$bucket]['Bytes'] = [long]$fileAges[$bucket]['Bytes'] + [long]$entrySize
            if ($topFiles.Count -lt 100 -or [long]$entrySize -gt [long]$topFiles[$topFiles.Count-1].SizeBytes) {
              $topFiles.Add([pscustomobject]@{Path=$entry.FullName;SizeBytes=[long]$entrySize;LastModifiedUtc=$fileDate.ToString('o');Extension=$ext})
              if ($topFiles.Count -gt 1) {
                $sortedTop=@($topFiles | Sort-Object SizeBytes -Descending)
                $topFiles.Clear()
                foreach($candidate in $sortedTop | Select-Object -First 100){$topFiles.Add($candidate)}
              }
            }
            if ($MeasureAllocated) {
              $a = [NativeStorage.Allocation]::Get($entry.FullName)
              if ($null -eq $a) { $missing++ } else { $allocBytes += [long]$a }
            }
          }
        } catch {
          $hadError = $true
          if ($issues.Count -lt $script:ErrorLimit) { $issues.Add([pscustomobject]@{Path=$entry.FullName;Message=$_.Exception.Message}) }
        }
      }
    } catch {
      $hadError = $true
      if ($issues.Count -lt $script:ErrorLimit) { $issues.Add([pscustomobject]@{Path=$p;Message=$_.Exception.Message}) }
    }
    $parent = [IO.Path]::GetDirectoryName($p.TrimEnd('\','/'))
    if ($p -eq $target) { $parent = $null }
    $allNodes.Add([pscustomobject]@{
      Path=$p;Parent=$parent;Name=$(if ($p -eq $target) { $target } else { [IO.Path]::GetFileName($p) });
      DirectBytes=$bytes;DirectFiles=$fileCount;DirectFolders=$dirCount;
      AllocatedDirect=$(if ($MeasureAllocated) { $allocBytes } else { $null });
      AllocationMissing=$missing;LastModified=$modified;HasError=$hadError
    })
  }
  $partitions = @($frontier.ToArray() | ForEach-Object { $_.Path })
  Write-ScanLog "Partitioned into $($partitions.Count) subtrees; $($allNodes.Count) parent folders scanned."
  $done=0; [long]$workerFiles=0
  $workerBody = $script:Worker.ToString()
  $chunkErrorLimit = [Math]::Max(20,[int]($script:ErrorLimit/[Math]::Max(1,$partitions.Count)))
  if ($partitions.Count -gt 0) {
    # Runspace pools are supported in Windows PowerShell 5.1 and PowerShell 7.
    # Keep at most 2x worker count in flight to bound memory and avoid creating
    # a PowerShell instance per partition all at once.
    $pool = [runspacefactory]::CreateRunspacePool(1, $WorkerCount)
    $pool.Open()
    $pending = New-Object 'System.Collections.Generic.List[object]'
    $nextPartition = 0
    $workerWrapper = @'
param([string]$workerSource,[string]$targetPath,[bool]$measureAllocated,[int]$errorCap)
$worker = [scriptblock]::Create($workerSource)
& $worker $targetPath $measureAllocated $errorCap
'@
    try {
      while ($nextPartition -lt $partitions.Count -or $pending.Count -gt 0) {
        while ($nextPartition -lt $partitions.Count -and $pending.Count -lt ($WorkerCount * 2)) {
          $taskPath = [string]$partitions[$nextPartition]
          $ps = [powershell]::Create()
          $ps.RunspacePool = $pool
          $null = $ps.AddScript($workerWrapper).AddArgument($workerBody).AddArgument($taskPath).AddArgument($MeasureAllocated).AddArgument($chunkErrorLimit)
          try {
            $handle = $ps.BeginInvoke()
            $pending.Add([pscustomobject]@{PowerShell=$ps;Handle=$handle;Path=$taskPath})
          } catch {
            $ps.Dispose()
            throw
          }
          $nextPartition++
        }
        $finished = -1
        for ($i = 0; $i -lt $pending.Count; $i++) {
          if ($pending[$i].Handle.IsCompleted) { $finished = $i; break }
        }
        if ($finished -lt 0) { Start-Sleep -Milliseconds 120; continue }
        $task = $pending[$finished]
        $pending.RemoveAt($finished)
        try {
          $results = @($task.PowerShell.EndInvoke($task.Handle))
          if ($task.PowerShell.HadErrors) {
            foreach ($streamError in $task.PowerShell.Streams.Error) {
              if ($issues.Count -lt $script:ErrorLimit) {
                $issues.Add([pscustomobject]@{Path=$task.Path;Message=$streamError.ToString()})
              }
            }
          }
          foreach ($r in $results) {
            if ($null -eq $r) { continue }
            foreach ($n in $r.Nodes) { $allNodes.Add($n) }
            foreach ($err in $r.Errors) { if ($issues.Count -lt $script:ErrorLimit) { $issues.Add($err) } }
            $workerFiles += [long]$r.Files
            $skipped += [long]$r.SkippedLinks
            foreach($item in @($r.TopFiles)) {if($null -ne $item){$topFiles.Add($item)}}
            if($topFiles.Count -gt 100){$best=@($topFiles | Sort-Object SizeBytes -Descending | Select-Object -First 100);$topFiles.Clear();foreach($item in $best){$topFiles.Add($item)}}
            if($null -ne $r.FileTypes){foreach($ext in $r.FileTypes.Keys){
              if(-not $fileTypes.ContainsKey($ext)){$fileTypes[$ext]=@{Count=[long]0;Bytes=[long]0}}
              $fileTypes[$ext]['Count']=[long]$fileTypes[$ext]['Count'] + [long]$r.FileTypes[$ext]['Count']
              $fileTypes[$ext]['Bytes']=[long]$fileTypes[$ext]['Bytes'] + [long]$r.FileTypes[$ext]['Bytes']
            }}
            if($null -ne $r.FileAges){foreach($bucket in $r.FileAges.Keys){
              $fileAges[$bucket]['Count']=[long]$fileAges[$bucket]['Count'] + [long]$r.FileAges[$bucket]['Count']
              $fileAges[$bucket]['Bytes']=[long]$fileAges[$bucket]['Bytes'] + [long]$r.FileAges[$bucket]['Bytes']
            }}
          }
          $done++
          Write-Progress -Activity 'Scanning and merging subtrees' -Status ("{0}/{1} partitions, {2:N0} files completed" -f $done,$partitions.Count,$workerFiles) -PercentComplete ([int](100*$done/$partitions.Count))
        } finally {
          $task.PowerShell.Dispose()
        }
      }
    } finally {
      foreach ($task in $pending) { $task.PowerShell.Dispose() }
      $pool.Close()
      $pool.Dispose()
      Write-Progress -Activity 'Scanning and merging subtrees' -Completed
    }
  }
  Write-ScanLog "Enumerated $($allNodes.Count.ToString('N0')) folders; aggregating subtree totals."
  # Case-insensitive Windows filesystem keys. No per-file objects retained.
  $map = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($n in $allNodes) {
    $n | Add-Member -NotePropertyMembers @{
      Bytes=[long]$n.DirectBytes;Files=[long]$n.DirectFiles;Folders=[long]0;
      Allocated=$(if ($MeasureAllocated) { [long]$n.AllocatedDirect } else { $null });
      AllocationMissingTotal=[long]$n.AllocationMissing; Incomplete=[bool]$n.HasError
    }
    $map[$n.Path] = $n
  }
  # Children always have longer paths than parents.
  foreach ($n in ($allNodes | Sort-Object { $_.Path.Length } -Descending)) {
    if ($n.Parent -and $map.ContainsKey($n.Parent)) {
      $parent = $map[$n.Parent]
      $parent.Bytes += $n.Bytes
      $parent.Files += $n.Files
      $parent.Folders += 1 + $n.Folders
      if ($MeasureAllocated) { $parent.Allocated += $n.Allocated }
      $parent.AllocationMissingTotal += $n.AllocationMissingTotal
      if ($n.Incomplete) { $parent.Incomplete = $true }
    }
  }
  if (-not $map.ContainsKey($target)) { throw 'The scan produced no root record.' }
  $rootNode=$map[$target]
  $driveInfo=$null
  try {
    if ($target -match '^[a-zA-Z]:\\') {
      $di = [IO.DriveInfo]::new($target.Substring(0,1))
      if ($di.IsReady) { $driveInfo = @{Size=[long]$di.TotalSize;Free=[long]$di.AvailableFreeSpace;Name=$di.Name} }
    }
  } catch {}
  $ended=Get-Date
  $metadata=[ordered]@{
    Target=$target;ScanStart=$started.ToString('o');ScanEnd=$ended.ToString('o');
    DurationSeconds=[Math]::Round(($ended-$started).TotalSeconds,2);
    Computer=$env:COMPUTERNAME;Threads=$WorkerCount;Partitions=$partitions.Count;
    AllocatedMode=$MeasureAllocated;AllocationSemantics='GetCompressedFileSizeW logical-on-disk (Windows only); may not reflect shared block/dedup physical savings';
    Files=$rootNode.Files;Folders=$rootNode.Folders;LogicalBytes=$rootNode.Bytes;
    AllocatedBytes=$(if ($MeasureAllocated -and $rootNode.AllocationMissingTotal -eq 0) { $rootNode.Allocated } else { $null });
    AllocationFailures=$rootNode.AllocationMissingTotal;
    ScanIssueCount=$issues.Count;IssuesTruncated=($issues.Count -ge $script:ErrorLimit);
    SkippedReparseDirectories=$skipped;
    Completeness=$(if ($rootNode.Incomplete -or $skipped -gt 0) { 'Partial: errors or skipped reparse directories' } else { 'Scanned accessible directories' });
    Drive=$driveInfo
  }
  Write-ScanLog ("Finished: {0:N0} files, {1:N0} folders, {2:N2} GiB, {3:N1}s; issues={4}, skipped links={5}" -f $metadata.Files,$metadata.Folders,($metadata.LogicalBytes/1GB),$metadata.DurationSeconds,$metadata.ScanIssueCount,$skipped)
  $typeRows=@($fileTypes.Keys | ForEach-Object { [pscustomobject]@{Extension=$_;Files=[long]$fileTypes[$_]['Count'];SizeBytes=[long]$fileTypes[$_]['Bytes']} } | Sort-Object SizeBytes -Descending)
  $ageRows=@(@('0-30 days','31-90 days','91-365 days','Over 1 year') | ForEach-Object { [pscustomobject]@{Age=$_;Files=[long]$fileAges[$_]['Count'];SizeBytes=[long]$fileAges[$_]['Bytes']} })
  $analysis=[pscustomobject]@{TopFiles=@($topFiles | Sort-Object SizeBytes -Descending | Select-Object -First 100);FileTypes=$typeRows;FileAges=$ageRows}
  return [pscustomobject]@{Meta=$metadata;Nodes=$allNodes.ToArray();Issues=$issues.ToArray();Analysis=$analysis}
}

function Convert-ReportRows($Result) {
  $rows = [Collections.Generic.List[object]]::new()
  $root = $Result.Meta.Target
  $rootLength = $root.TrimEnd('\','/').Length
  foreach ($n in $Result.Nodes) {
    $rel = if ($n.Path -eq $root) { '.' } else { $n.Path.Substring($rootLength).TrimStart('\','/') }
    $depth = if ($rel -eq '.') { 0 } else { @($rel -split '[\\/]').Count }
    $rows.Add([pscustomobject][ordered]@{
      Path=$n.Path;Parent=$n.Parent;Name=$n.Name;Depth=$depth;
      SizeBytes=$n.Bytes;AllocatedBytes=$(if ($Result.Meta.AllocatedMode -and $n.AllocationMissingTotal -eq 0) { $n.Allocated } else { $null });
      DirectBytes=$n.DirectBytes;Files=$n.Files;Folders=$n.Folders;
      PercentOfParent=$null;LastModifiedUtc=$n.LastModified;Incomplete=$n.Incomplete
    })
  }
  $lookup = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($r in $rows) { $lookup[$r.Path]=$r }
  foreach ($r in $rows) {
    if ($r.Parent -and $lookup.ContainsKey($r.Parent)) {
      $parent=$lookup[$r.Parent]
      $r.PercentOfParent = if ($parent.SizeBytes -gt 0) { [Math]::Round(100.0*$r.SizeBytes/$parent.SizeBytes,2) } else { 0.0 }
    } else { $r.PercentOfParent = 100.0 }
  }
  return $rows.ToArray()
}
function Export-TreeHtml($Result,[object[]]$Rows,[string]$FilePath) {
  $metaJson = ConvertTo-Json -InputObject $Result.Meta -Depth 8 -Compress
  $rowJson = ConvertTo-Json -InputObject $Rows -Depth 5 -Compress
  $analysisJson = if($Result.Analysis){ConvertTo-Json -InputObject $Result.Analysis -Depth 8 -Compress}else{'null'}
  # Prevent user-controlled folder names from breaking out of the script element.
  $metaJson=$metaJson.Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
  $rowJson=$rowJson.Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
  $analysisJson=$analysisJson.Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
  $page = @'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpaceTrace | @@TARGET_TITLE@@</title>
<style>
:root{color-scheme:dark;--bg:#0b1324;--panel:#14233b;--line:#2a3d56;--text:#e6edf7;--muted:#9aaec8;--accent:#61b9ff;--warning:#ffd279}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.48 Segoe UI,Arial,sans-serif}
header{padding:24px 28px;background:linear-gradient(115deg,#172a46,#0d182a);border-bottom:1px solid var(--line)}
h1{margin:0 0 5px;font-size:24px;font-weight:650}h2{font-size:14px;margin:0 0 12px;color:var(--muted);letter-spacing:.05em;text-transform:uppercase}
.sub{color:var(--muted);overflow-wrap:anywhere}.wrap{padding:20px 28px;max-width:1900px;margin:auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:17px}.stat{font-size:21px;font-weight:650}.desc{color:var(--muted);font-size:12px}
.controls{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:15px 0}button,input,select{background:#172942;color:var(--text);border:1px solid #3c506c;padding:9px 12px;border-radius:7px;font:inherit}button{cursor:pointer}button:hover{border-color:var(--accent)}input{min-width:280px;flex:1;max-width:430px}select{min-width:145px}
.tablewrap{border:1px solid var(--line);border-radius:10px;overflow:auto;background:#101d31}table{border-collapse:collapse;width:100%;min-width:980px}thead{position:sticky;top:0;background:#20324b;z-index:2}
th,td{padding:9px 11px;text-align:right;border-bottom:1px solid #26374c;white-space:nowrap}th{cursor:pointer;font-size:12px;letter-spacing:.02em;color:#bcd0e7}th:first-child,td:first-child{text-align:left;min-width:340px}tbody tr:hover{background:#1b2d46}
.folder{display:inline-flex;align-items:center;gap:6px;text-decoration:none;color:var(--text);cursor:pointer}.toggle{display:inline-block;min-width:25px;color:var(--accent);font:12px Consolas,monospace}.foldericon{width:15px;height:11px;border:1px solid var(--warning);border-radius:2px;background:#98722d;display:inline-block;position:relative;flex:none}.foldericon:before{content:"";position:absolute;left:1px;top:-4px;width:7px;height:3px;background:#98722d;border:1px solid var(--warning);border-bottom:0;border-radius:2px 2px 0 0}.muted{color:var(--muted)}
.meter{height:7px;background:#253750;border-radius:8px;overflow:hidden;min-width:62px}.fill{height:100%;background:linear-gradient(90deg,#2873ae,#69c2fb)}.percent{font-size:12px;margin-top:3px}.note{padding:12px 15px;border:1px solid var(--line);border-radius:9px;background:#12223a;color:var(--muted);margin:10px 0 18px}.warn{color:var(--warning)}
.insights{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:14px;margin:18px 0}.mini{max-height:340px;overflow:auto}.insightrow{display:grid;grid-template-columns:minmax(110px,1fr) 90px 85px;gap:7px;border-bottom:1px solid var(--line);padding:7px 1px;font-size:12px}.insightrow span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.treerow{display:flex;align-items:center;gap:10px;margin:5px 0;font-size:12px}.treebar{height:13px;background:#2873ae;border-radius:3px;min-width:2px}.treelabel{min-width:110px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}footer{padding:20px 0;color:var(--muted);font-size:12px}code{color:#d6e8fb}.results{color:var(--muted);margin-left:auto}
</style></head><body>
<header><h1>SpaceTrace storage utilization report</h1><div class="sub" id="headerTarget"></div><div class="sub" id="scanDate"></div></header>
<main class="wrap">
<div class="cards"><div class="card"><div class="desc">Target logical size</div><div class="stat" id="logical"></div></div>
<div class="card"><div class="desc">Allocated on disk</div><div class="stat" id="allocated"></div></div>
<div class="card"><div class="desc">Files</div><div class="stat" id="files"></div></div>
<div class="card"><div class="desc">Subfolders</div><div class="stat" id="folders"></div></div>
<div class="card"><div class="desc">Scan elapsed</div><div class="stat" id="elapsed"></div></div></div>
<div class="note" id="integrity"></div>
<section class="insights">
  <div class="card"><h2>Largest files (top 100)</h2><div id="topfiles" class="mini"></div></div>
  <div class="card"><h2>File types by size</h2><div id="types" class="mini"></div></div>
  <div class="card"><h2>File age by last modification</h2><div id="ages" class="mini"></div></div>
  <div class="card"><h2>Largest root folders</h2><div id="treemap" class="mini"></div></div>
</section>
<div class="controls"><input id="search" type="search" placeholder="Filter by folder name or path (top 500 matches)" aria-label="Search folders">
<button id="expand">Expand next level</button><button id="expandAll">Expand all</button><button id="collapse">Collapse all</button>
<label for="sort" class="muted">Sort siblings:</label><select id="sort"><option value="SizeBytes">Size, descending</option><option value="Name">Name, A-Z</option><option value="AllocatedBytes">Allocated size</option><option value="Files">File count</option><option value="Folders">Folder count</option><option value="PercentOfParent">% of parent</option><option value="LastModifiedUtc">Last modified</option></select><span class="results" id="matches"></span></div>
<div class="tablewrap"><table><thead><tr><th data-key="Name" title="Folder name; click to sort">Name</th><th data-key="SizeBytes" title="Recursive logical file size; click to sort">Size</th><th data-key="AllocatedBytes" title="Recursive allocated bytes, if -Allocated was selected; click to sort">Allocated</th><th data-key="Files" title="Recursive number of files; click to sort">Files</th><th data-key="Folders" title="Recursive number of child folders; click to sort">Folders</th><th data-key="PercentOfParent" title="Logical size divided by the immediate parent folder size; click to sort">% of parent</th><th data-key="LastModifiedUtc" title="Directory last-write time; click to sort">Last modified</th><th>Health</th></tr></thead><tbody id="tree"></tbody></table></div>
<footer>Generated by SpaceTrace.ps1. Size, Allocated, Files and Folders are recursive subtree totals. % of parent is calculated using logical size. Last modified is the directory last-write timestamp, not the latest descendant file timestamp. Allocated displays N/A unless enabled at scan time. Directory reparse points are not traversed. Results reflect a point-in-time, nontransactional scan. The HTML report is fully self-contained.</footer>
</main>
<script>
const meta=@@META@@;
const rows=@@ROWS@@;
const analysis=@@ANALYSIS@@;
const byPath=new Map(), children=new Map();
for(const r of rows){byPath.set(r.Path.toLowerCase(),r);const k=(r.Parent||'').toLowerCase();if(!children.has(k))children.set(k,[]);children.get(k).push(r)}
const expanded=new Set([meta.Target.toLowerCase()]);
const root=byPath.get(meta.Target.toLowerCase());
const $=id=>document.getElementById(id);
function panel(id,items,labelKey){const el=$(id);if(!analysis||!Array.isArray(items)||!items.length){el.textContent='No inventory data available';return;}const fragment=document.createDocumentFragment();for(const r of items){const d=document.createElement('div');d.className='insightrow';const n=document.createElement('span');n.textContent=String(r[labelKey]||'');n.title=String(r.Path||r[labelKey]||'');const size=document.createElement('span');size.textContent=fmt(r.SizeBytes);const count=document.createElement('span');count.textContent=r.Files===undefined?'':nf.format(r.Files)+' files';d.append(n,size,count);fragment.append(d);}el.append(fragment)}
function renderInsights(){if(analysis){panel('topfiles',analysis.TopFiles,'Path');panel('types',analysis.FileTypes,'Extension');panel('ages',analysis.FileAges,'Age');}else{for(const key of ['topfiles','types','ages'])$(key).textContent='Not available in this report';}const el=$('treemap');const siblings=(children.get(meta.Target.toLowerCase())||[]).slice().sort((a,b)=>b.SizeBytes-a.SizeBytes).slice(0,30);if(!siblings.length){el.textContent='No child folders';return;}const max=Math.max(1,...siblings.map(r=>r.SizeBytes));for(const r of siblings){const line=document.createElement('div');line.className='treerow';const name=document.createElement('span');name.className='treelabel';name.textContent=r.Name;name.title=r.Path;const bar=document.createElement('div');bar.className='treebar';bar.style.width=(Math.max(2,r.SizeBytes/max*65))+'%';const size=document.createElement('span');size.textContent=fmt(r.SizeBytes);line.append(name,bar,size);el.append(line);}}

const nf=new Intl.NumberFormat();
function fmt(b){if(b===null||b===undefined)return 'N/A';if(b===0)return '0 B';const u=['B','KiB','MiB','GiB','TiB','PiB'];let x=b,i=0;while(x>=1024&&i<u.length-1){x/=1024;i++}return (i===0?x.toFixed(0):x.toFixed(1))+' '+u[i]}
$('headerTarget').textContent=meta.Target;
$('scanDate').textContent='Scanned: '+new Date(meta.ScanStart).toLocaleString()+'  |  Host: '+meta.Computer;
$('logical').textContent=fmt(meta.LogicalBytes);$('allocated').textContent=fmt(meta.AllocatedBytes);
$('files').textContent=nf.format(meta.Files);$('folders').textContent=nf.format(meta.Folders);$('elapsed').textContent=meta.DurationSeconds+' s';
$('integrity').textContent='Completeness: '+meta.Completeness+'  |  Reported access/errors: '+meta.ScanIssueCount+'  |  Skipped directory links: '+meta.SkippedReparseDirectories+'  |  Allocation lookup failures: '+meta.AllocationFailures+(meta.Drive?'  |  Volume total '+fmt(meta.Drive.Size)+'; free '+fmt(meta.Drive.Free):'');
if(meta.ScanIssueCount || meta.SkippedReparseDirectories)$('integrity').classList.add('warn');
let sorting='SizeBytes', invert=false;
function ordered(list){return [...list].sort((a,b)=>{
 let v;
 if(sorting==='Name')v=String(a.Name||'').localeCompare(String(b.Name||''));
 else if(sorting==='LastModifiedUtc')v=String(b.LastModifiedUtc||'').localeCompare(String(a.LastModifiedUtc||''));
 else {const av=a[sorting],bv=b[sorting];v=(av===null||av===undefined?Number.NEGATIVE_INFINITY:bv===null||bv===undefined?Number.POSITIVE_INFINITY:Number(bv)-Number(av));}
 return invert?-v:v;
})}
function updateSortIndicators(){document.querySelectorAll('th[data-key]').forEach(h=>{const active=h.dataset.key===sorting;h.setAttribute('aria-sort',active?(invert?'ascending':'descending'):'none');h.title=h.title.replace(/ \[(ascending|descending)\]$/,'')+(active?(invert?' [ascending]':' [descending]'):'');});}
function makeCell(tr,value,cls){let td=document.createElement('td');td.textContent=value;if(cls)td.className=cls;tr.appendChild(td);return td}
function renderRow(r,level,body,isFiltered){
 let tr=document.createElement('tr'),td=document.createElement('td'),a=document.createElement('span');
 a.className='folder';a.style.paddingLeft=Math.min(level,40)*16+'px';
 const key=r.Path.toLowerCase(),kids=children.get(key)||[];
 let t=document.createElement('span');t.className='toggle';t.textContent=kids.length?(expanded.has(key)?'[-]':'[+]'):'   ';
 let icon=document.createElement('span');icon.className='foldericon';icon.setAttribute('aria-hidden','true');
 let name=document.createElement('span');name.textContent=r.Name;
 a.append(t,icon,name);a.title=r.Path;
 a.onclick=()=>{if(isFiltered||!kids.length)return;if(expanded.has(key))expanded.delete(key);else expanded.add(key);render()};
 td.appendChild(a);tr.appendChild(td);
 makeCell(tr,fmt(r.SizeBytes));makeCell(tr,fmt(r.AllocatedBytes));makeCell(tr,nf.format(r.Files));makeCell(tr,nf.format(r.Folders));
 let pct=document.createElement('td'),met=document.createElement('div'),fill=document.createElement('div'),label=document.createElement('div');
 met.className='meter';fill.className='fill';fill.style.width=Math.max(0,Math.min(100,r.PercentOfParent||0))+'%';met.appendChild(fill);
 label.className='percent muted';label.textContent=Number(r.PercentOfParent||0).toFixed(1)+'%';pct.append(met,label);tr.appendChild(pct);
 makeCell(tr,r.LastModifiedUtc?new Date(r.LastModifiedUtc).toLocaleDateString():'N/A');
 makeCell(tr,r.Incomplete?'Partial':'OK',r.Incomplete?'warn':'muted');body.appendChild(tr)
}
// Render large expand-all results in small batches so the browser remains responsive.
let renderToken=0;
function render(){
 const token=++renderToken,q=$('search').value.trim().toLowerCase(),body=$('tree');body.replaceChildren();
 if(q){
   const matches=rows.filter(r=>r.Path.toLowerCase().includes(q)).sort((a,b)=>b.SizeBytes-a.SizeBytes);
   for(let r of matches.slice(0,500))renderRow(r,Math.min(r.Depth,6),body,true);
   $('matches').textContent=matches.length+' matches'+(matches.length>500?' (showing first 500)':'');return;
 }
 const todo=[{r:root,level:0}];let visible=0;
 function batch(){
   if(token!==renderToken)return;
   const fragment=document.createDocumentFragment();let count=0;
   while(todo.length&&count<350){
     let {r,level}=todo.pop();if(!r)continue;
     renderRow(r,level,fragment,false);visible++;count++;
     if(expanded.has(r.Path.toLowerCase())){
       let kids=ordered(children.get(r.Path.toLowerCase())||[]);
       for(let i=kids.length-1;i>=0;i--)todo.push({r:kids[i],level:level+1});
     }
   }
   body.appendChild(fragment);
   $('matches').textContent=nf.format(visible)+' visible / '+nf.format(rows.length)+' folders'+(todo.length?' (loading...)':'');
   if(todo.length)requestAnimationFrame(batch);
 }
 batch();
}
$('search').addEventListener('input',render);
$('sort').addEventListener('change',e=>{sorting=e.target.value;invert=false;updateSortIndicators();render()});
document.querySelectorAll('th[data-key]').forEach(h=>h.addEventListener('click',()=>{let k=h.dataset.key;invert=sorting===k?!invert:false;sorting=k;$('sort').value=k;updateSortIndicators();render()}));
$('collapse').onclick=()=>{expanded.clear();expanded.add(meta.Target.toLowerCase());$('search').value='';render()};
$('expand').onclick=()=>{let current=[...expanded];for(let k of current)for(let r of (children.get(k)||[]))expanded.add(r.Path.toLowerCase());$('search').value='';render()};
$('expandAll').onclick=()=>{for(const r of rows)expanded.add(r.Path.toLowerCase());$('search').value='';render()};
updateSortIndicators();renderInsights();render();
</script></body></html>
'@
  # HTML-escape the title rather than treating any user folder name as markup.
  $safeTitle=[System.Net.WebUtility]::HtmlEncode($Result.Meta.Target)
  $page=$page.Replace('@@TARGET_TITLE@@',$safeTitle).Replace('@@META@@',$metaJson).Replace('@@ROWS@@',$rowJson).Replace('@@ANALYSIS@@',$analysisJson)
  [IO.File]::WriteAllText($FilePath,$page,[Text.UTF8Encoding]::new($false))
}
function Save-TreeReport($Result,[string[]]$ChosenFormats,[string]$Directory) {
  $null=New-Item -ItemType Directory -Force -Path $Directory
  $rows=Convert-ReportRows $Result
  $stem=Get-ReportKey ([string]$Result.Meta.Target)
  $exportAll=$ChosenFormats -contains 'All'
  $output=[ordered]@{}
  if ($exportAll -or $ChosenFormats -contains 'Csv') {
    $file=Join-Path $Directory ($stem+'.csv')
    $rows | Export-Csv -LiteralPath $file -Encoding utf8 -NoTypeInformation
    $output.Csv=$file; Write-ScanLog "CSV: $file"
    foreach($item in @(@{Key='TopFiles';Suffix='_top100files'},@{Key='FileTypes';Suffix='_filetypes'},@{Key='FileAges';Suffix='_fileages'})) {
      $outputFile=Join-Path $Directory ($stem+$item.Suffix+'.csv')
      $value=$Result.Analysis.($item.Key)
      if($value){@($value)|Export-Csv -LiteralPath $outputFile -NoTypeInformation -Encoding UTF8}
    }
  }
  if ($exportAll -or $ChosenFormats -contains 'Json') {
    $file=Join-Path $Directory ($stem+'.json')
    $json=ConvertTo-Json -InputObject ([ordered]@{Metadata=$Result.Meta;Folders=$rows;Issues=$Result.Issues;Analysis=$Result.Analysis}) -Depth 10
    [IO.File]::WriteAllText($file,$json,[Text.UTF8Encoding]::new($false))
    $output.Json=$file; Write-ScanLog "JSON: $file"
  }
  if ($exportAll -or $ChosenFormats -contains 'Html') {
    $file=Join-Path $Directory ($stem+'.html')
    Export-TreeHtml $Result $rows $file
    $output.Html=$file; Write-ScanLog "HTML: $file"
  }
  $issueFile=Join-Path $Directory ($stem+'_issues.csv')
  if ($Result.Issues.Count -gt 0) {
    $Result.Issues | Export-Csv -LiteralPath $issueFile -Encoding utf8 -NoTypeInformation
    $output.Issues=$issueFile; Write-ScanLog "Issues: $issueFile" 'WARN'
  }
  return [pscustomobject]$output
}
function Save-CombinedReport([string[]]$JsonFiles,[string[]]$SelectedTargets,[string[]]$ChosenFormats,[string]$Directory,[int]$ExpectedCount) {
  if (-not $JsonFiles -or $JsonFiles.Count -eq 0) { return $null }
  $hostName=Get-SessionHostName $SelectedTargets
  $rootKey='COMBINED_'+$hostName
  $rows=[Collections.Generic.List[object]]::new()
  [long]$bytes=0;[long]$files=0;[long]$folders=0;[long]$allocated=0;[long]$missing=0
  [long]$issueCount=0;[long]$skipped=0
  $anyPartial=$false;$allAllocated=$true;$minStart=$null;$maxEnd=$null
  $issueList=[Collections.Generic.List[object]]::new()
  $reportDetails=[Collections.Generic.List[object]]::new()
  $combinedTop=[Collections.Generic.List[object]]::new()
  $combinedTypes=@{}
  $combinedAges=@{}
  foreach ($jsonFile in $JsonFiles) {
    $item=Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $meta=$item.Metadata
    if($item.Analysis){
      foreach($top in @($item.Analysis.TopFiles)){if($null -ne $top){$combinedTop.Add($top)}}
      foreach($typ in @($item.Analysis.FileTypes)){
        if($null -eq $typ){continue}
        $key=[string]$typ.Extension
        if(-not $combinedTypes.ContainsKey($key)){$combinedTypes[$key]=@{Count=[long]0;Bytes=[long]0}}
        $combinedTypes[$key]['Count'] += [long]$typ.Files;$combinedTypes[$key]['Bytes'] += [long]$typ.SizeBytes
      }
      foreach($age in @($item.Analysis.FileAges)){
        if($null -eq $age){continue}
        $key=[string]$age.Age
        if(-not $combinedAges.ContainsKey($key)){$combinedAges[$key]=@{Count=[long]0;Bytes=[long]0}}
        $combinedAges[$key]['Count'] += [long]$age.Files;$combinedAges[$key]['Bytes'] += [long]$age.SizeBytes
      }
    }
    $reportDetails.Add($meta)
    $bytes += [long]$meta.LogicalBytes
    $files += [long]$meta.Files
    $folders += 1+[long]$meta.Folders
    $issueCount += [long]$meta.ScanIssueCount
    $skipped += [long]$meta.SkippedReparseDirectories
    $missing += [long]$meta.AllocationFailures
    if (-not $meta.AllocatedMode -or $null -eq $meta.AllocatedBytes) { $allAllocated=$false }
    else { $allocated += [long]$meta.AllocatedBytes }
    if ($meta.Completeness -match 'Partial') { $anyPartial=$true }
    $start=[datetime]$meta.ScanStart;$end=[datetime]$meta.ScanEnd
    if ($null -eq $minStart -or $start -lt $minStart) { $minStart=$start }
    if ($null -eq $maxEnd -or $end -gt $maxEnd) { $maxEnd=$end }
    foreach ($issue in @($item.Issues)) { if ($null -ne $issue -and $issueList.Count -lt 2000) { $issueList.Add($issue) } }
    foreach ($entry in @($item.Folders)) {
      if ($null -eq $entry) { continue }
      # Only the top level drive roots are repointed under the synthetic host root.
      if ([string]$entry.Path -eq [string]$meta.Target) {
        $entry.Parent=$rootKey
        $entry.Depth=1
      } else { $entry.Depth=[int]$entry.Depth + 1 }
      $rows.Add($entry)
    }
  }
  $successCount=$JsonFiles.Count
  $complete=($successCount -eq $ExpectedCount)
  $status=if (-not $complete) { 'Partial: one or more targets failed' } elseif ($anyPartial) { 'Partial: errors or skipped reparse directories' } else { 'Scanned accessible directories' }
  $root=[pscustomobject][ordered]@{
    Path=$rootKey;Parent=$null;Name=$rootKey;Depth=0;SizeBytes=$bytes;
    AllocatedBytes=$(if ($allAllocated) { $allocated } else { $null });DirectBytes=[long]0;
    Files=$files;Folders=$folders;PercentOfParent=100.0;LastModifiedUtc=$null;
    Incomplete=(-not $complete -or $anyPartial)
  }
  $rows.Insert(0,$root)
  foreach ($entry in $rows) {
    if ([string]$entry.Parent -eq $rootKey) {
      $entry.PercentOfParent=if ($bytes -gt 0) { [Math]::Round(100.0*$entry.SizeBytes/$bytes,2) } else { 0.0 }
    }
  }
  $meta=[ordered]@{
    Target=$rootKey;Computer=$hostName;ScanStart=$minStart.ToString('o');ScanEnd=$maxEnd.ToString('o');
    DurationSeconds=[Math]::Round(($maxEnd-$minStart).TotalSeconds,2);Threads=$Threads;Partitions=0;
    AllocatedMode=$allAllocated;AllocationSemantics='Aggregated individual reports; N/A if any source lacks allocated bytes';
    Files=$files;Folders=$folders;LogicalBytes=$bytes;AllocatedBytes=$(if ($allAllocated) { $allocated } else { $null });
    AllocationFailures=$missing;ScanIssueCount=$issueCount;IssuesTruncated=($issueList.Count -ge 2000);
    SkippedReparseDirectories=$skipped;Completeness=$status;Drive=$null;
    SuccessfulTargets=$successCount;RequestedTargets=$ExpectedCount;Targets=$reportDetails.ToArray()
  }
  $combinedAnalysis=[pscustomobject]@{
    TopFiles=@($combinedTop | Sort-Object SizeBytes -Descending | Select-Object -First 100)
    FileTypes=@($combinedTypes.Keys | ForEach-Object { [pscustomobject]@{Extension=$_;Files=[long]$combinedTypes[$_]['Count'];SizeBytes=[long]$combinedTypes[$_]['Bytes']} } | Sort-Object SizeBytes -Descending)
    FileAges=@($combinedAges.Keys | ForEach-Object { [pscustomobject]@{Age=$_;Files=[long]$combinedAges[$_]['Count'];SizeBytes=[long]$combinedAges[$_]['Bytes']} })
  }
  $output=[ordered]@{}
  $all=$ChosenFormats -contains 'All'
  $stem=$hostName+'_Combined'
  if ($all -or $ChosenFormats -contains 'Csv') {
    $file=Join-Path $Directory ($stem+'.csv')
    $rows | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
    $output.Csv=$file;Write-ScanLog "Combined CSV: $file"
    foreach($item in @(@{Key='TopFiles';Suffix='_top100files'},@{Key='FileTypes';Suffix='_filetypes'},@{Key='FileAges';Suffix='_fileages'})) {
      $outputFile=Join-Path $Directory ($stem+$item.Suffix+'.csv')
      $value=$combinedAnalysis.($item.Key)
      if($value){@($value)|Export-Csv -LiteralPath $outputFile -NoTypeInformation -Encoding UTF8}
    }
  }
  if ($all -or $ChosenFormats -contains 'Json') {
    $file=Join-Path $Directory ($stem+'.json')
    $json=ConvertTo-Json -InputObject ([ordered]@{Metadata=$meta;Folders=$rows.ToArray();Issues=$issueList.ToArray();Analysis=$combinedAnalysis}) -Depth 10
    [IO.File]::WriteAllText($file,$json,[Text.UTF8Encoding]::new($false))
    $output.Json=$file;Write-ScanLog "Combined JSON: $file"
  }
  if ($all -or $ChosenFormats -contains 'Html') {
    $file=Join-Path $Directory ($stem+'.html')
    Export-TreeHtml ([pscustomobject]@{Meta=$meta;Analysis=$combinedAnalysis}) $rows.ToArray() $file
    $output.Html=$file;Write-ScanLog "Combined HTML: $file"
  }
  return [pscustomobject]$output
}
function Invoke-SelectedScan([string[]]$Targets,[int]$MaxWorkers,[int]$SplitFactor,[bool]$MeasureAllocated,[string[]]$ChosenFormats,[string]$BaseDirectory) {
  $resolved=@(Resolve-Targets $Targets)
  if ($resolved.Count -eq 0) { throw 'No valid targets selected.' }
  $sessionHost=Get-SessionHostName $resolved
  $dir=Get-ScanOutputDirectory -BaseDirectory $BaseDirectory -TargetPath $resolved[0] -HostOverride $sessionHost
  $script:ScanLog=Join-Path $dir 'Session.log'
  Write-Host "Reports directory: $dir" -ForegroundColor Cyan
  Write-ScanLog "Session with $($resolved.Count) selected target(s); global worker budget=$MaxWorkers"
  # One selected target runs in this PowerShell session, eliminating background
  # job prompts and giving immediate, actionable errors for normal single-drive scans.
  # Multiple targets use child powershell.exe/pwsh.exe processes with redirected streams:
  # no Start-Job / Wait-Job, and no interactive prompts in the child.
  $parallel=[Math]::Min($resolved.Count,$MaxWorkers)
  $baseWorkers=[int][Math]::Floor($MaxWorkers/$parallel)
  $extras=$MaxWorkers%$parallel
  $completed=[Collections.Generic.List[object]]::new()
  $failures=[Collections.Generic.List[object]]::new()
  $scriptPath=$PSCommandPath
  if (-not $scriptPath) { throw 'Scanning requires the script to be saved as a .ps1 file.' }
  if ($resolved.Count -eq 1) {
    $target=$resolved[0]
    Write-ScanLog "Scanning target $target directly with $MaxWorkers worker(s)"
    try {
      $script:ScanLog=Join-Path $dir ((Get-ReportKey $target)+'_scan.log')
      $result=Invoke-TreeScan -Target $target -WorkerCount $MaxWorkers -SplitFactor $SplitFactor -MeasureAllocated $MeasureAllocated
      Save-TreeReport $result @('Json') $dir | Out-Null
      $completed.Add([pscustomobject]@{Target=$target;State='Completed'})
      Write-ScanLog "Finished: $target"
    } catch {
      $failures.Add([pscustomobject]@{Target=$target;State='Failed';Error=$_.Exception.Message})
      Write-Warning "Scan failed for ${target}: $($_.Exception.Message)"
      throw
    } finally { $script:ScanLog=Join-Path $dir 'Session.log' }
  } else {
    $running=[Collections.Generic.List[object]]::new()
    $next=0
    # Use the installed PowerShell executable, whether Windows PowerShell 5.1 or PowerShell 7.
    $engine=Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' })
    if (-not (Test-Path -LiteralPath $engine)) { throw "Cannot locate PowerShell executable: $engine" }
    try {
      while ($next -lt $resolved.Count -or $running.Count -gt 0) {
        while ($next -lt $resolved.Count -and $running.Count -lt $parallel) {
          $slot=$running.Count
          $budget=$baseWorkers+$(if ($slot -lt $extras) { 1 } else { 0 })
          $target=$resolved[$next]
          $stem=Get-ReportKey $target
          $stdout=Join-Path $dir ($stem+'_stdout.log')
          $stderr=Join-Path $dir ($stem+'_stderr.log')
          # Single quote escaping keeps arbitrary legitimate UNC and directory names safe.
          $escapedScript=$scriptPath.Replace("'","''")
          $escapedTarget=$target.Replace("'","''")
          $escapedDir=$dir.Replace("'","''")
          $allocatedLiteral=if ($MeasureAllocated) { '$true' } else { '$false' }
          $command=@"
`$ErrorActionPreference='Stop'
try {
  & '$escapedScript' -Path '$escapedTarget' -Formats Json -Threads $budget -ChunkFactor $SplitFactor -Allocated:$allocatedLiteral -NonInteractive -SessionDir '$escapedDir'
  exit 0
} catch {
  [Console]::Error.WriteLine(`$_.ToString())
  exit 1
}
"@
          $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
          $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded
          Write-ScanLog "Starting target $target with $budget worker(s)"
          try {
            $process=Start-Process -FilePath $engine -ArgumentList $arguments -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -ErrorAction Stop
            $running.Add([pscustomobject]@{Process=$process;Target=$target;Workers=$budget;Stdout=$stdout;Stderr=$stderr})
          } catch {
            $failures.Add([pscustomobject]@{Target=$target;State='LaunchFailed';Error=$_.Exception.Message})
            Write-ScanLog "Failed to launch ${target}: $($_.Exception.Message)" 'WARN'
          }
          $next++
        }
        $done=$null
        foreach ($item in $running) {
          $item.Process.Refresh()
          if ($item.Process.HasExited) { $done=$item; break }
        }
        if ($null -eq $done) { Start-Sleep -Milliseconds 250; continue }
        $null=$running.Remove($done)
        $code=$done.Process.ExitCode
        $done.Process.Dispose()
        if ($code -eq 0) {
          $completed.Add([pscustomobject]@{Target=$done.Target;State='Completed'})
          Write-ScanLog "Finished: $($done.Target)"
        } else {
          $details='Child process returned exit code '+$code
          if (Test-Path -LiteralPath $done.Stderr) {
            $errText=(Get-Content -LiteralPath $done.Stderr -Tail 15 -ErrorAction SilentlyContinue) -join ' '
            if ($errText) { $details+='; '+$errText }
          }
          $failures.Add([pscustomobject]@{Target=$done.Target;State='Failed';Error=$details})
          Write-ScanLog "Failed: $($done.Target): $details" 'WARN'
        }
        $pct=[int](100*($completed.Count+$failures.Count)/$resolved.Count)
        Write-Progress -Activity 'Multiple drive scan' -Status "$($completed.Count+$failures.Count) / $($resolved.Count) targets completed" -PercentComplete $pct
      }
    } finally {
      Write-Progress -Activity 'Multiple drive scan' -Completed
      foreach ($item in $running) {
        try { if (-not $item.Process.HasExited) { $item.Process.Kill() } } catch {}
        $item.Process.Dispose()
      }
    }
  }
  # Each child always writes JSON as an interchange format. Export only the requested
  # formats and delete interchange JSON when JSON was not selected.
  $jsonSources=[Collections.Generic.List[string]]::new()
  foreach ($record in $completed) {
    $stem=Get-ReportKey $record.Target
    $jsonFile=Join-Path $dir ($stem+'.json')
    if (-not (Test-Path -LiteralPath $jsonFile)) {
      $failures.Add([pscustomobject]@{Target=$record.Target;State='Missing output'})
      Write-ScanLog "Missing JSON output from $($record.Target)" 'WARN'
      continue
    }
    $jsonSources.Add($jsonFile)
    $needHtml=($ChosenFormats -contains 'All' -or $ChosenFormats -contains 'Html')
    $needCsv=($ChosenFormats -contains 'All' -or $ChosenFormats -contains 'Csv')
    if ($needHtml -or $needCsv) {
      $data=Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8 | ConvertFrom-Json
      if ($needCsv) {
        $file=Join-Path $dir ($stem+'.csv')
        $data.Folders | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
        foreach($item in @(@{Key='TopFiles';Suffix='_top100files'},@{Key='FileTypes';Suffix='_filetypes'},@{Key='FileAges';Suffix='_fileages'})) {
          $outputFile=Join-Path $dir ($stem+$item.Suffix+'.csv')
          $value=$data.Analysis.($item.Key)
          if($value){@($value)|Export-Csv -LiteralPath $outputFile -NoTypeInformation -Encoding UTF8}
        }
        Write-ScanLog "CSV: $file"
      }
      if ($needHtml) {
        $file=Join-Path $dir ($stem+'.html')
        Export-TreeHtml ([pscustomobject]@{Meta=$data.Metadata;Analysis=$data.Analysis}) @($data.Folders) $file
        Write-ScanLog "HTML: $file"
      }
    }
  }
  if ($resolved.Count -gt 1 -and $jsonSources.Count -gt 0) {
    Save-CombinedReport $jsonSources.ToArray() $resolved $ChosenFormats $dir $resolved.Count | Out-Null
  }
  if (-not ($ChosenFormats -contains 'All' -or $ChosenFormats -contains 'Json')) {
    foreach ($file in $jsonSources) { Remove-Item -LiteralPath $file -Force }
  }
  $manifest=[ordered]@{
    SessionDirectory=$dir;StartTargets=$resolved;SuccessTargets=@($completed | ForEach-Object {$_.Target});
    FailedTargets=@($failures | ForEach-Object {$_.Target});GlobalWorkers=$MaxWorkers;
    Formats=$ChosenFormats;AllocatedMode=$MeasureAllocated;Timestamp=(Get-Date).ToString('o')
  }
  [IO.File]::WriteAllText((Join-Path $dir 'SessionManifest.json'),(ConvertTo-Json -InputObject $manifest -Depth 6),[Text.UTF8Encoding]::new($false))
  Write-ScanLog "Session complete. $($completed.Count) finished; $($failures.Count) issues."
  return $dir
}
function Show-Menu {
  $selectedTargets=@($Path | Where-Object { $_ })
  $selectedFormats=@($Formats)
  $selectedThreads=$Threads
  $selectedOutDir=$OutDir
  $measure=[bool]$Allocated
  $sessionStatus='Ready. Select one or more targets.'
  $lastReportDirectory=$null
  $lastScanTime=$null
  while ($true) {
    Clear-Host
    Write-Host '======= SPACETRACE =======' -ForegroundColor Cyan
    Write-Host ('Computer: {0}   Session: {1}' -f [Environment]::MachineName,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-Host ('Targets  : {0}' -f $(if ($selectedTargets.Count) { $selectedTargets -join ', ' } else { '(not selected)' }))
    Write-Host "Formats  : $($selectedFormats -join ', ')"
    Write-Host "Workers  : $selectedThreads total across all drives  |  Chunk factor: $ChunkFactor"
    Write-Host "Allocated: $(if ($measure) { 'ON (slower)' } else { 'OFF (fast)' })"
    Write-Host "Output   : $selectedOutDir (dated hostname folder per run)"
    if ($lastReportDirectory) {
      Write-Host ('Last run : {0}' -f $lastScanTime) -ForegroundColor DarkCyan
      Write-Host ('Reports  : {0}' -f $lastReportDirectory) -ForegroundColor DarkCyan
    }
    Write-Host ('Status   : {0}' -f $sessionStatus) -ForegroundColor Yellow
    Write-Host ''
    Write-Host ' 1. Discover local drives and select one/many/all'
    Write-Host ' 2. Discover remote host drives and select one/many/all'
    Write-Host ' 3. Add local folder or UNC path'
    Write-Host ' 4. Choose output formats'
    Write-Host ' 5. Change TOTAL worker budget'
    Write-Host ' 6. Toggle allocated-size check'
    Write-Host ' 7. Change output directory'
    Write-Host ' 8. RUN SELECTED SCANS'
    Write-Host ' 9. Clear selected targets'
    Write-Host ' 0. Exit'
    switch ((Read-Host 'Select').Trim()) {
      '1' {
        $chosen=@(Select-Targets @(Get-LocalTargets))
        if ($chosen.Count) { $selectedTargets=$chosen;$sessionStatus="$($chosen.Count) target(s) selected." }
        else { $sessionStatus='No changes to selected targets.' }
      }
      '2' {
        $hostName=Read-Host 'Remote host or FQDN'
        if ($hostName) {
          try {
            $chosen=@(Select-Targets @(Get-RemoteTargets $hostName))
            if ($chosen.Count) { $selectedTargets=$chosen;$sessionStatus="$($chosen.Count) remote target(s) selected." }
            else { $sessionStatus='No changes to selected targets.' }
          } catch { $sessionStatus="Remote discovery failed: $($_.Exception.Message)" }
        }
      }
      '3' {
        $manual=Read-Host 'Local folder or UNC path to ADD'
        if ($manual) {
          try {
            $canonical=Get-CanonicalPath $manual
            if ($selectedTargets -notcontains $canonical) { $selectedTargets+= $canonical }
            $sessionStatus="$($selectedTargets.Count) selected target(s)."
          } catch { $sessionStatus="Invalid target: $($_.Exception.Message)" }
        }
      }
      '4' {
        Write-Host ' 1. HTML  2. CSV  3. JSON  4. All  5. HTML+CSV  6. CSV+JSON  7. HTML+JSON'
        $opt=Read-Host 'Output selection'
        $map=@{'1'=@('Html');'2'=@('Csv');'3'=@('Json');'4'=@('All');'5'=@('Html','Csv');'6'=@('Csv','Json');'7'=@('Html','Json')}
        if ($map.ContainsKey($opt)) { $selectedFormats=$map[$opt];$sessionStatus="Formats: $($selectedFormats -join ', ')" }
      }
      '5' {
        $n=0
        if ([int]::TryParse((Read-Host 'Total parallel workers (1-32)'),[ref]$n) -and $n -ge 1 -and $n -le 32) {
          $selectedThreads=$n;$sessionStatus="Global worker budget: $n"
        } else { $sessionStatus='Worker budget unchanged.' }
      }
      '6' { if ($script:OnWindows) { $measure=-not $measure;$sessionStatus="Allocated measurement: $measure" } }
      '7' {
        $dir=Read-Host 'Output parent folder'
        if ($dir) { $selectedOutDir=[Environment]::ExpandEnvironmentVariables($dir.Trim('"'));$sessionStatus="Output: $selectedOutDir" }
      }
      '8' {
        if (-not $selectedTargets.Count) { $sessionStatus='Select at least one target.';break }
        try {
          $lastReportDirectory=Invoke-SelectedScan $selectedTargets $selectedThreads $ChunkFactor $measure $selectedFormats $selectedOutDir
          $lastScanTime=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
          $sessionStatus="Scan complete. $lastReportDirectory"
        } catch { $sessionStatus="Scan failed: $($_.Exception.Message)";Write-Warning $sessionStatus;Read-Host 'Press Enter' | Out-Null }
      }
      '9' { $selectedTargets=@();$sessionStatus='Target selection cleared.' }
      '0' { return }
      default { $sessionStatus='Invalid selection (0-9).' }
    }
  }
}

if ($NonInteractive) {
  if (-not $Path -or $Path.Count -eq 0) { throw '-Path is required with -NonInteractive.' }
  if ($SessionDir) {
    # Internal child-worker entry point: a single target and an existing session folder.
    if ($Path.Count -ne 1) { throw '-SessionDir worker mode accepts one path.' }
    $script:ScanLog=Join-Path $SessionDir ((Get-ReportKey $Path[0])+'_scan.log')
    $result=Invoke-TreeScan -Target $Path[0] -WorkerCount $Threads -SplitFactor $ChunkFactor -MeasureAllocated ([bool]$Allocated)
    Save-TreeReport $result @('Json') $SessionDir | Out-Null
  } else {
    Invoke-SelectedScan $Path $Threads $ChunkFactor ([bool]$Allocated) $Formats $OutDir | Out-Null
  }
} else { Show-Menu }
