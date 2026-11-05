# SpaceTrace — Multi-Drive Edition

**Minimum:** Windows PowerShell 5.1; no external modules. Runs from the current directory and creates a new `yyyyMMdd_HHmmss_HOSTNAME` output directory for each session. If targets span hosts, the directory is named `yyyyMMdd_HHmmss_MULTIHOST`.

## Launch

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SpaceTrace.ps1
```

The interactive menu discovers local logical fixed drives or remote accessible administrative shares, and lets you select **one**, **multiple** (for example `1,3,4`), or **all** (`A`). Add custom folders and UNC paths using menu option 3. The screen clears when returning to the main menu, showing only the current selection and session status.

### Noninteractive examples

```powershell
# Multiple volumes on the local host
.\SpaceTrace.ps1 -Path 'C:\','D:\','E:\' -Formats All -Threads 8 -NonInteractive

# Remote administrative shares: same host, one report per drive and one combined report
.\SpaceTrace.ps1 -Path '\\SERVER01\C$\','\\SERVER01\D$\' -Formats Html,Csv -Threads 8 -OutDir 'C:\Temp' -NonInteractive

# A single location (no combined report needed)
.\SpaceTrace.ps1 -Path 'D:\Backups' -Formats Html -Threads 6 -NonInteractive

# Optional allocated-size inspection (slower; Windows API per file)
.\SpaceTrace.ps1 -Path 'D:\','E:\' -Formats All -Allocated -NonInteractive
```

`-Threads` is the **global traversal-worker budget for the session**, not a per-drive budget. Up to `min(drives, Threads)` independent drive jobs execute concurrently, dividing the available runspace workers among them. Each drive uses a bounded runspace pool, breadth-first partitioning (`-ChunkFactor`, default 6), and bottom-up aggregation. The wrapper runs one Windows PowerShell background job per active drive. Worker processes themselves have overhead in addition to scan workers; on slow disks/SMB start at 4–8 workers total and tune conservatively.

## Output layout

When scanning `\\SERVER01\C$\` and `\\SERVER01\D$\`, the results resemble:

```text
C:\Temp\20261105_120700_SERVER01\
  Session.log
  SessionManifest.json
  SERVER01_C_<hash>.html
  SERVER01_C_<hash>.csv
  SERVER01_C_<hash>.json
  SERVER01_C_<hash>_scan.log
  SERVER01_D_<hash>.html
  SERVER01_D_<hash>.csv
  SERVER01_D_<hash>.json
  SERVER01_D_<hash>_scan.log
  SERVER01_Combined.html
  SERVER01_Combined.csv
  SERVER01_Combined.json
```

Exact individual filenames are derived from the path plus a short stable hash, which prevents collisions for distinct paths with similar names. Exports are limited to the requested formats. Temporary interchange JSON files are deleted when JSON output is not selected. Every run produces a session manifest, session log, and target scan logs. Access issues also produce per-target `_issues.csv` files.

A **combined report** is generated when 2+ targets are selected. It includes a synthetic host root with independent drive roots beneath it. This allows a single HTML folder tree with **Expand all**, **Collapse all**, **Expand next level**, filtering, sorting, and summary totals. The combined CSV and JSON contain this same tree. Drive-root percentages are calculated from the combined logical size. If one target fails, successful drives are reported and the combined report is marked partial; the session manifest lists failed targets.

## Report columns

The sortable HTML grid includes **Name, Size, Allocated, Files, Folders, % of parent, Last modified**, and a health indicator. Size/file/folder counts are recursive. `% of parent` compares each subtree with its immediate parent. Last modified is the directory timestamp, not the latest modified descendant file. The HTML uses a dark navy theme, CSS-drawn folder icons and ASCII `[+]` / `[-]` toggles, so no malformed Unicode arrows are displayed. The HTML is offline and self-contained and renders expanded results in batches.

## Accuracy and operational considerations

- **Fast mode:** reports logical bytes only. Allocation displays `N/A`; it never silently substitutes logical bytes.
- **`-Allocated`:** uses Windows `GetCompressedFileSizeW` for each file. Much slower on millions of files or UNC; physical deduplication/storage-array effects may not be reflected.
- **Directory links:** reparse directories are skipped to avoid loops. Access failures and skipped links make the inventory partial.
- **Overlapping input targets:** if you scan `D:\` and `D:\Backups` together, the combined total double-counts the nested subtree. Select nonoverlapping roots for an accurate total.
- **Live volume changes:** this is not a transactional snapshot. For repeatable forensic/audit evidence, scan a stable snapshot.
- **Memory and browser load:** millions of files are not retained individually, but every folder is represented. Very large folder trees and `Expand all` may still demand significant memory and browser rendering time. Combined reports load the individual JSON tree snapshots after scans finish.
- **Remote discovery:** uses CIM where available and falls back to selected admin share probes. Requires corresponding Windows/SMB privileges.
- **Host naming:** local paths use the machine running the script; UNC paths use the server portion. Multiple hosts create a MULTIHOST session.

## Validation

The source and package are assembled and checked for archive integrity and embedded HTML JavaScript syntax. **Windows PowerShell 5.1 execution has not been verified in this environment.** Run a small two-directory test before using production volumes.

## 2026-11-05 — background job blockage fix

The drive coordinator no longer uses `Start-Job` / `Wait-Job`. A single selected
drive scans directly in the current PowerShell session, so normal progress and
errors are visible. Multi-drive sessions launch noninteractive PowerShell child
processes with redirected stdout/stderr logs and an aggregate worker budget.
Each worker process writes its own JSON intermediary; the parent produces the
requested individual and combined HTML/CSV/JSON outputs. Nonzero child exit
codes and stderr are recorded in `Session.log` and session manifests.

Run from Windows PowerShell 5.1 (no additional modules required):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SpaceTrace.ps1
```

If the first scan fails, review the per-target `_scan.log` and `Session.log`
in the dated output directory; with multi-drive runs, also check each target's
`_stderr.log`. Full Windows runtime validation has not yet been performed.

## Expanded analytical views (2026-11-05)

The storage scanner now collects these metrics **during the existing enumeration pass**, without retaining a complete file inventory:

- **Top 100 largest individual files:** full file path, logical size, extension, last modified UTC.
- **File types:** counts and logical size by extension (including extensionless files).
- **File age:** four last-modification buckets: 0–30, 31–90, 91–365, and over 365 days.
- **Largest root folders:** interactive HTML horizontal relative-size visualization.
- **CSV exports:** alongside the folder CSV, additional `_top100files.csv`, `_filetypes.csv`, and `_fileages.csv` when populated.
- **JSON:** includes an `Analysis` object with all three summaries, including combined-host reports.

To compare storage usage between two scans of **the same path**, retain the JSON files and run:

```powershell
.\Compare-SpaceTraceSnapshots.ps1 -Before 'C:\Reports\old\C_XXXX.json' -After 'C:\Reports\new\C_XXXX.json' -OutputDirectory 'C:\Reports\Growth'
```

This produces an HTML growth report, CSV, and JSON. Positive changes mean growth; folder sizes are recursive, so do **not** sum all folder deltas. Snapshot comparison measures changes between two nontransactional scans and does not identify which exact files changed.

### Not yet equivalent to TreeSize Professional

There is no MFT-native scan acceleration, true file-level interactive browser, checksum-based duplicate engine, NTFS hardlink/ADS handling, detailed ACL/owner census, advanced search, direct delete/move/rename operations, or native explorer integration. The root-folder visualization is a proportional bar display, not a hierarchical rectangle treemap. The scanner remains read-only and Windows PowerShell 5.1 compatible.

### Validation and operating cautions

Source-level checks and HTML JavaScript syntax validation were performed, but Windows PowerShell 5.1 execution has not been verified in this environment. Start with a small local directory before a multi-million-file host. Exclude the generated report directory from the scanned path when possible so report writes do not affect the scan.
