#requires -Version 5.1
<# .SYNOPSIS Compare two SpaceTrace JSON reports of the same target. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Before,
  [Parameter(Mandatory=$true)][string]$After,
  [string]$OutputDirectory=(Get-Location).ProviderPath
)
$ErrorActionPreference='Stop'
$old=Get-Content -LiteralPath $Before -Raw -Encoding UTF8 | ConvertFrom-Json
$new=Get-Content -LiteralPath $After -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $old.Metadata -or -not $new.Metadata) { throw 'Both inputs must be SpaceTrace JSON reports.' }
if ([string]$old.Metadata.Target -ine [string]$new.Metadata.Target) { throw "Different targets: $($old.Metadata.Target) vs $($new.Metadata.Target). Compare like-for-like paths." }
$map=@{}
foreach($r in @($old.Folders)){$map[[string]$r.Path]=[pscustomobject]@{Path=$r.Path;Name=$r.Name;BeforeBytes=[long]$r.SizeBytes;AfterBytes=[long]0;BeforeFiles=[long]$r.Files;AfterFiles=[long]0;SeenAfter=$false}}
foreach($r in @($new.Folders)){
  $key=[string]$r.Path
  if(-not $map.ContainsKey($key)){$map[$key]=[pscustomobject]@{Path=$r.Path;Name=$r.Name;BeforeBytes=[long]0;AfterBytes=[long]0;BeforeFiles=[long]0;AfterFiles=[long]0;SeenAfter=$false}}
  $map[$key].AfterBytes=[long]$r.SizeBytes;$map[$key].AfterFiles=[long]$r.Files;$map[$key].SeenAfter=$true
}
$oldPaths=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($r in @($old.Folders)){[void]$oldPaths.Add([string]$r.Path)}
$rows=@(foreach($r in $map.Values){
  [pscustomobject][ordered]@{
    Path=$r.Path;BeforeBytes=$r.BeforeBytes;AfterBytes=$r.AfterBytes
    DeltaBytes=([long]$r.AfterBytes-[long]$r.BeforeBytes)
    BeforeFiles=$r.BeforeFiles;AfterFiles=$r.AfterFiles;DeltaFiles=([long]$r.AfterFiles-[long]$r.BeforeFiles)
    Status=$(if(-not $oldPaths.Contains($r.Path)){'New'}elseif(-not $r.SeenAfter){'Removed'}else{'Existing'})
  }
})
$rows=@($rows | Sort-Object @{Expression={ [Math]::Abs([double]$_.DeltaBytes) };Descending=$true})
$dir=New-Item -ItemType Directory -Path $OutputDirectory -Force
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$stem='GrowthComparison_'+$stamp
$csv=Join-Path $dir.FullName ($stem+'.csv')
$json=Join-Path $dir.FullName ($stem+'.json')
$html=Join-Path $dir.FullName ($stem+'.html')
$rows|Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
[IO.File]::WriteAllText($json,(ConvertTo-Json -InputObject ([ordered]@{Target=$new.Metadata.Target;Before=$old.Metadata.ScanEnd;After=$new.Metadata.ScanEnd;Folders=$rows}) -Depth 7),[Text.UTF8Encoding]::new($false))
$data=(ConvertTo-Json -InputObject $rows -Depth 5 -Compress).Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
$target=[Net.WebUtility]::HtmlEncode([string]$new.Metadata.Target)
$page=@'
<!doctype html><html><head><meta charset="utf-8"><title>SpaceTrace | Storage growth comparison</title><style>
body{font:14px Segoe UI,Arial;background:#0b1324;color:#e6edf7;margin:0;padding:28px}h1{font-size:25px}
small{color:#9aaec8}input{background:#172942;color:#fff;padding:10px;border:1px solid #506380;border-radius:7px;width:400px;max-width:90%}
table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:9px 12px;border-bottom:1px solid #2a3d56;text-align:right}td:first-child,th:first-child{text-align:left}th{cursor:pointer;background:#20324b;position:sticky;top:0}.gain{color:#ffaf79}.loss{color:#7ce6bd}td:first-child{overflow-wrap:anywhere}</style></head><body>
<h1>SpaceTrace storage growth comparison</h1><div>@@TARGET@@</div><p><small>Positive deltas indicate growth. Recursive folder sizes mean parent and child differences overlap; do not sum all rows.</small></p><input id="q" placeholder="Filter folder path"><table><thead><tr><th>Folder</th><th>Before</th><th>After</th><th>Change</th><th>File count change</th><th>Status</th></tr></thead><tbody id="table"></tbody></table>
<script>const rows=@@DATA@@;const root=document.getElementById('table');const fmt=n=>{let s=n<0?'-':'';n=Math.abs(n);let i=0;while(n>=1024&&i<5){n/=1024;i++}return s+n.toFixed(1)+' '+['B','KiB','MiB','GiB','TiB','PiB'][i]};function draw(){root.replaceChildren();const q=document.getElementById('q').value.toLowerCase();for(const r of rows.filter(x=>x.Path.toLowerCase().includes(q)).slice(0,10000)){const tr=document.createElement('tr');for(let i=0;i<6;i++){const td=document.createElement('td');td.textContent=[r.Path,fmt(r.BeforeBytes),fmt(r.AfterBytes),fmt(r.DeltaBytes),r.DeltaFiles,r.Status][i];if(i===3)td.className=r.DeltaBytes>0?'gain':'loss';tr.appendChild(td)}root.appendChild(tr)}}document.getElementById('q').addEventListener('input',draw);draw();</script></body></html>
'@
$page=$page.Replace('@@TARGET@@',$target).Replace('@@DATA@@',$data)
[IO.File]::WriteAllText($html,$page,[Text.UTF8Encoding]::new($false))
Write-Host "Growth comparison saved to: $($dir.FullName)" -ForegroundColor Cyan
Write-Host "CSV : $csv`nJSON: $json`nHTML: $html"
