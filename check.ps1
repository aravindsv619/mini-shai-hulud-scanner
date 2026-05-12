# =============================================================================
# Mini Shai-Hulud / TeamPCP — Supply Chain Scanner (PowerShell)
# =============================================================================
# No Python needed. Runs on any Windows machine.
#
# USAGE
# -----
# 1. Open PowerShell (Windows key + R -> type powershell -> Enter)
# 2. Run:
#       powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\Users\you\Downloads\my-repo"
#
# Or run with no argument to scan current folder:
#       powershell -ExecutionPolicy Bypass -File check.ps1
#
# =============================================================================

param(
    [string]$RepoPath = "."
)

$RepoPath = Resolve-Path $RepoPath -ErrorAction SilentlyContinue
if (-not $RepoPath) {
    Write-Host "ERROR: Folder not found. Check the path and try again." -ForegroundColor Red
    exit 1
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ── All 169 compromised packages and bad versions ────────────────────────────
$AFFECTED = @{
    "@tanstack/history"                          = @("1.161.9","1.161.12")
    "@tanstack/react-router"                     = @("1.169.5","1.169.8")
    "@tanstack/router-core"                      = @("1.169.5","1.169.8")
    "@tanstack/router-utils"                     = @("1.161.11","1.161.14")
    "@tanstack/router-plugin"                    = @("1.167.38","1.167.41")
    "@tanstack/virtual-file-routes"              = @("1.161.10","1.161.13")
    "@tanstack/router-generator"                 = @("1.166.45","1.166.48")
    "@tanstack/start-server-core"                = @("1.167.33","1.167.36")
    "@tanstack/start-client-core"                = @("1.168.5","1.168.8")
    "@tanstack/start-storage-context"            = @("1.166.38","1.166.41")
    "@tanstack/start-plugin-core"                = @("1.169.23","1.169.26")
    "@tanstack/react-start-server"               = @("1.166.55","1.166.58")
    "@tanstack/react-start-client"               = @("1.166.51","1.166.54")
    "@tanstack/start-fn-stubs"                   = @("1.161.9","1.161.12")
    "@tanstack/react-start"                      = @("1.167.68","1.167.71")
    "@tanstack/react-start-rsc"                  = @("0.0.47","0.0.50")
    "@tanstack/react-router-devtools"            = @("1.166.16","1.166.19")
    "@tanstack/router-devtools-core"             = @("1.167.6","1.167.9")
    "@tanstack/router-devtools"                  = @("1.166.16","1.166.19")
    "@tanstack/router-ssr-query-core"            = @("1.168.3","1.168.6")
    "@tanstack/react-router-ssr-query"           = @("1.166.15","1.166.18")
    "@tanstack/router-cli"                       = @("1.166.46","1.166.49")
    "@tanstack/zod-adapter"                      = @("1.166.12","1.166.15")
    "@tanstack/eslint-plugin-router"             = @("1.161.9")
    "@tanstack/router-vite-plugin"               = @("1.166.53","1.166.56")
    "@tanstack/nitro-v2-vite-plugin"             = @("1.154.12","1.154.15")
    "@tanstack/solid-router"                     = @("1.169.5","1.169.8")
    "@tanstack/solid-start"                      = @("1.167.65","1.167.68")
    "@tanstack/solid-start-client"               = @("1.166.50","1.166.53")
    "@tanstack/solid-start-server"               = @("1.166.54","1.166.57")
    "@tanstack/solid-router-devtools"            = @("1.166.16","1.166.19")
    "@tanstack/start-static-server-functions"    = @("1.166.44","1.166.47")
    "@tanstack/vue-router"                       = @("1.169.5","1.169.8")
    "@tanstack/solid-router-ssr-query"           = @("1.166.15","1.166.18")
    "@tanstack/valibot-adapter"                  = @("1.166.12","1.166.15")
    "@tanstack/vue-start"                        = @("1.167.61","1.167.64")
    "@tanstack/vue-start-server"                 = @("1.166.50","1.166.53")
    "@tanstack/vue-router-ssr-query"             = @("1.166.15","1.166.18")
    "@tanstack/vue-router-devtools"              = @("1.166.16","1.166.19")
    "@tanstack/vue-start-client"                 = @("1.166.46","1.166.49")
    "@tanstack/arktype-adapter"                  = @("1.166.12","1.166.15")
    "@tanstack/eslint-plugin-start"              = @("0.0.4","0.0.7")
    "@mistralai/mistralai"                       = @("2.2.2","2.2.3","2.2.4")
    "@mistralai/mistralai-gcp"                   = @("1.7.1","1.7.2","1.7.3")
    "@mistralai/mistralai-azure"                 = @("1.7.1","1.7.2","1.7.3")
    "@uipath/apollo-react"                       = @("4.24.5")
    "@uipath/apollo-wind"                        = @("2.16.2")
    "@uipath/cli"                                = @("1.0.1")
    "@uipath/rpa-tool"                           = @("0.9.5")
    "@uipath/apollo-core"                        = @("5.9.2")
    "@uipath/filesystem"                         = @("1.0.1")
    "@uipath/solutionpackager-tool-core"         = @("0.0.34")
    "@uipath/solution-tool"                      = @("1.0.1")
    "@uipath/maestro-tool"                       = @("1.0.1")
    "@uipath/codedapp-tool"                      = @("1.0.1")
    "@uipath/agent-tool"                         = @("1.0.1")
    "@uipath/orchestrator-tool"                  = @("1.0.1")
    "@uipath/integrationservice-tool"            = @("1.0.2")
    "@uipath/rpa-legacy-tool"                    = @("1.0.1")
    "@uipath/vertical-solutions-tool"            = @("1.0.1")
    "@uipath/flow-tool"                          = @("1.0.2")
    "@uipath/codedagent-tool"                    = @("1.0.1")
    "@uipath/common"                             = @("1.0.1")
    "@uipath/resource-tool"                      = @("1.0.1")
    "@uipath/auth"                               = @("1.0.1")
    "@uipath/docsai-tool"                        = @("1.0.1")
    "@uipath/case-tool"                          = @("1.0.1")
    "@uipath/api-workflow-tool"                  = @("1.0.1")
    "@uipath/test-manager-tool"                  = @("1.0.2")
    "@uipath/robot"                              = @("1.3.4")
    "@uipath/traces-tool"                        = @("1.0.1")
    "@uipath/agent-sdk"                          = @("1.0.2")
    "@uipath/integrationservice-sdk"             = @("1.0.2")
    "@uipath/maestro-sdk"                        = @("1.0.1")
    "@uipath/data-fabric-tool"                   = @("1.0.2")
    "@uipath/tasks-tool"                         = @("1.0.1")
    "@uipath/insights-tool"                      = @("1.0.1")
    "@uipath/insights-sdk"                       = @("1.0.1")
    "@uipath/uipath-python-bridge"               = @("1.0.1")
    "@uipath/ap-chat"                            = @("1.5.7")
    "@uipath/project-packager"                   = @("1.1.16")
    "@uipath/packager-tool-case"                 = @("0.0.9")
    "@uipath/packager-tool-workflowcompiler-browser" = @("0.0.34")
    "@uipath/packager-tool-connector"            = @("0.0.19")
    "@uipath/packager-tool-workflowcompiler"     = @("0.0.16")
    "@uipath/packager-tool-webapp"               = @("1.0.6")
    "@uipath/packager-tool-apiworkflow"          = @("0.0.19")
    "@uipath/packager-tool-functions"            = @("0.1.1")
    "@uipath/widget.sdk"                         = @("1.2.3")
    "@uipath/resources-tool"                     = @("0.1.11")
    "@uipath/agent.sdk"                          = @("0.0.18")
    "@uipath/codedagents-tool"                   = @("0.1.12")
    "@uipath/aops-policy-tool"                   = @("0.3.1")
    "@uipath/solution-packager"                  = @("0.0.35")
    "@uipath/packager-tool-bpmn"                 = @("0.0.9")
    "@uipath/tool-workflowcompiler"              = @("0.0.12")
    "@uipath/vss"                                = @("0.1.6")
    "@uipath/solutionpackager-sdk"               = @("1.0.11")
    "@uipath/ui-widgets-multi-file-upload"       = @("1.0.1")
    "@uipath/access-policy-tool"                 = @("0.3.1")
    "@uipath/context-grounding-tool"             = @("0.1.1")
    "@uipath/gov-tool"                           = @("0.3.1")
    "@uipath/admin-tool"                         = @("0.1.1")
    "@uipath/identity-tool"                      = @("0.1.1")
    "@uipath/llmgw-tool"                         = @("1.0.1")
    "@uipath/resourcecatalog-tool"               = @("0.1.1")
    "@uipath/functions-tool"                     = @("1.0.1")
    "@uipath/access-policy-sdk"                  = @("0.3.1")
    "@uipath/platform-tool"                      = @("1.0.1")
    "@uipath/telemetry"                          = @("0.0.7")
    "@squawk/types"                              = @("0.8.2","0.8.3","0.8.4")
    "@squawk/mcp"                                = @("0.9.1","0.9.2","0.9.3","0.9.4")
    "@squawk/weather"                            = @("0.5.6","0.5.7","0.5.8","0.5.9")
    "@squawk/airspace"                           = @("0.8.1","0.8.2","0.8.3","0.8.4")
    "@squawk/icao-registry-data"                 = @("0.8.4","0.8.5","0.8.6","0.8.7")
    "@squawk/flightplan"                         = @("0.5.2","0.5.3","0.5.4","0.5.5")
    "@squawk/airports"                           = @("0.6.2","0.6.3","0.6.4","0.6.5")
    "@squawk/geo"                                = @("0.4.4","0.4.5","0.4.6","0.4.7")
    "@squawk/procedure-data"                     = @("0.7.3","0.7.4","0.7.5","0.7.6")
    "@squawk/navaid-data"                        = @("0.6.4","0.6.5","0.6.6","0.6.7")
    "@squawk/fix-data"                           = @("0.6.4","0.6.5","0.6.6","0.6.7")
    "@squawk/navaids"                            = @("0.4.2","0.4.3","0.4.4","0.4.5")
    "@squawk/fixes"                              = @("0.3.2","0.3.3","0.3.4","0.3.5")
    "@squawk/airport-data"                       = @("0.7.4","0.7.5","0.7.6","0.7.7")
    "@squawk/airway-data"                        = @("0.5.4","0.5.5","0.5.6","0.5.7")
    "@squawk/units"                              = @("0.4.3","0.4.4","0.4.5","0.4.6")
    "@squawk/procedures"                         = @("0.5.2","0.5.3","0.5.4","0.5.5")
    "@squawk/airways"                            = @("0.4.2","0.4.3","0.4.4","0.4.5")
    "@squawk/icao-registry"                      = @("0.5.2","0.5.3","0.5.4","0.5.5")
    "@squawk/notams"                             = @("0.3.6","0.3.7","0.3.8","0.3.9")
    "@squawk/flight-math"                        = @("0.5.4","0.5.5","0.5.6","0.5.7")
    "@squawk/airspace-data"                      = @("0.5.3","0.5.4","0.5.5","0.5.6")
    "@tallyui/connector-medusa"                  = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/theme"                             = @("0.2.1","0.2.2","0.2.3")
    "@tallyui/storage-sqlite"                    = @("0.2.1","0.2.2","0.2.3")
    "@tallyui/connector-vendure"                 = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/core"                              = @("0.2.1","0.2.2","0.2.3")
    "@tallyui/connector-woocommerce"             = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/components"                        = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/pos"                               = @("0.1.1","0.1.2","0.1.3")
    "@tallyui/database"                          = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/connector-shopify"                 = @("1.0.1","1.0.2","1.0.3")
    "@draftlab/auth"                             = @("0.24.1","0.24.2")
    "@draftlab/db"                               = @("0.16.1")
    "@draftlab/auth-router"                      = @("0.5.1","0.5.2")
    "@draftauth/core"                            = @("0.13.1","0.13.2")
    "@draftauth/client"                          = @("0.2.1","0.2.2")
    "@taskflow-corp/cli"                         = @("0.1.24","0.1.25","0.1.26","0.1.27","0.1.28","0.1.29")
    "@mesadev/sdk"                               = @("0.28.3")
    "@mesadev/rest"                              = @("0.28.3")
    "@mesadev/saguaro"                           = @("0.4.22")
    "@ml-toolkit-ts/xgboost"                     = @("1.0.3","1.0.4")
    "@ml-toolkit-ts/preprocessing"               = @("1.0.2","1.0.3")
    "@dirigible-ai/sdk"                          = @("0.6.2","0.6.3")
    "@supersurkhet/cli"                          = @("0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7")
    "@supersurkhet/sdk"                          = @("0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7")
    "@tolka/cli"                                 = @("1.0.2","1.0.3","1.0.4","1.0.5","1.0.6")
    "@beproduct/nestjs-auth"                     = @("0.1.2","0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8","0.1.9","0.1.10","0.1.11","0.1.12","0.1.13","0.1.14","0.1.15","0.1.16","0.1.17","0.1.18","0.1.19")
    "safe-action"                                = @("0.8.3","0.8.4")
    "ts-dna"                                     = @("3.0.1","3.0.2","3.0.3","3.0.4")
    "cross-stitch"                               = @("1.1.3","1.1.4","1.1.5","1.1.6")
    "cmux-agent-mcp"                             = @("0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8")
    "agentwork-cli"                              = @("0.1.4","0.1.5")
    "git-branch-selector"                        = @("1.3.3","1.3.4","1.3.5","1.3.6","1.3.7")
    "wot-api"                                    = @("0.8.1","0.8.2","0.8.3","0.8.4")
    "git-git-git"                                = @("1.0.8","1.0.9","1.0.10","1.0.11","1.0.12")
    "nextmove-mcp"                               = @("0.1.3","0.1.4","0.1.5","0.1.6","0.1.7")
    "ml-toolkit-ts"                              = @("1.0.4","1.0.5")
}

$PAYLOAD_FILES = @("router_init.js","router_runtime.js","tanstack_runner.js","setup.mjs")
$IOC_STRINGS   = @("79ac49eedf774dd4b0cfa308722bc463cfe5885c","@tanstack/setup",
                   "git-tanstack.com","getsession.org","A Mini Shai-Hulud",
                   "gh-token-monitor","83.142.209.194")
$SKIP_DIRS     = @("node_modules",".git","dist","build",".next",".nuxt","coverage",".cache")

# ── Counters ──────────────────────────────────────────────────────────────────
$confirmedHits   = @()
$safeVersions    = @()
$payloadCritical = @()
$iocHits         = @()
$lockfilesFound  = @()

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Mini Shai-Hulud / TeamPCP -- Supply Chain Scanner" -ForegroundColor Cyan
Write-Host "  Date   : $timestamp" -ForegroundColor Cyan
Write-Host "  Folder : $RepoPath" -ForegroundColor Cyan
Write-Host "  Checks : $($AFFECTED.Count) packages | payload files | IOC strings" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. LOCKFILES
# =============================================================================
Write-Host "[1/3] Finding lockfiles..." -ForegroundColor White

$lockfiles = Get-ChildItem -Path $RepoPath -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -in @("package-lock.json","yarn.lock","pnpm-lock.yaml") -and
        ($_.FullName -notmatch "\\node_modules\\" ) -and
        ($_.FullName -notmatch "\\.git\\")
    }

if (-not $lockfiles) {
    Write-Host "  No lockfiles found (package-lock.json / yarn.lock / pnpm-lock.yaml)" -ForegroundColor Yellow
    Write-Host "  This repo may not be a JS/TS project." -ForegroundColor Yellow
} else {
    foreach ($lf in $lockfiles) {
        $rel = $lf.FullName.Replace($RepoPath.ToString(),"").TrimStart("\")
        Write-Host "  Scanning: $rel" -ForegroundColor Gray
        $lockfilesFound += $rel

        # ── package-lock.json ─────────────────────────────────────────────────
        if ($lf.Name -eq "package-lock.json") {
            try {
                $data = Get-Content $lf.FullName -Raw | ConvertFrom-Json
                # Try packages (v2/v3) then dependencies (v1)
                $pkgs = $null
                if ($data.PSObject.Properties["packages"]) { $pkgs = $data.packages }
                elseif ($data.PSObject.Properties["dependencies"]) { $pkgs = $data.dependencies }

                if ($pkgs) {
                    $pkgs.PSObject.Properties | ForEach-Object {
                        $rawName = $_.Name -replace "^node_modules/",""
                        $info    = $_.Value
                        if ($AFFECTED.ContainsKey($rawName)) {
                            $ver    = $info.version
                            $badVers = $AFFECTED[$rawName]
                            if ($ver -in $badVers) {
                                $confirmedHits += [PSCustomObject]@{
                                    File=$rel; Package=$rawName; Version=$ver; BadVersions=($badVers -join ", ")
                                }
                            } else {
                                $safeVersions += [PSCustomObject]@{
                                    File=$rel; Package=$rawName; Version=$ver; BadVersions=($badVers -join ", ")
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Host "  Could not parse $rel" -ForegroundColor Yellow
            }
        }

        # ── yarn.lock / pnpm-lock.yaml — text search ──────────────────────────
        if ($lf.Name -in @("yarn.lock","pnpm-lock.yaml")) {
            $content = Get-Content $lf.FullName -Raw -ErrorAction SilentlyContinue
            foreach ($pkg in $AFFECTED.Keys) {
                if ($content -match [regex]::Escape($pkg)) {
                    foreach ($bv in $AFFECTED[$pkg]) {
                        if ($content -match [regex]::Escape($bv)) {
                            $confirmedHits += [PSCustomObject]@{
                                File=$rel; Package=$pkg; Version=$bv; BadVersions=($AFFECTED[$pkg] -join ", ")
                            }
                        }
                    }
                }
            }
        }
    }
}

# =============================================================================
# 2. PAYLOAD FILES
# =============================================================================
Write-Host ""
Write-Host "[2/3] Scanning for malicious payload files..." -ForegroundColor White

Get-ChildItem -Path $RepoPath -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in $PAYLOAD_FILES } |
    ForEach-Object {
        $rel      = $_.FullName.Replace($RepoPath.ToString(),"").TrimStart("\")
        $outside  = $_.FullName -notmatch "\\node_modules\\"
        if ($outside) {
            Write-Host "  [CRITICAL] Payload file outside node_modules: $rel" -ForegroundColor Red
            $payloadCritical += $rel
        } else {
            Write-Host "  [INFO] Payload file in node_modules: $rel" -ForegroundColor Yellow
        }
    }

if ($payloadCritical.Count -eq 0) {
    Write-Host "  No payload files found." -ForegroundColor Green
}

# =============================================================================
# 3. IOC STRINGS
# =============================================================================
Write-Host ""
Write-Host "[3/3] Scanning source files for IOC strings..." -ForegroundColor White

$textExts = @(".json",".yaml",".yml",".js",".ts",".mjs",".cjs",".sh",".env",".txt",".lock",".toml",".md")

Get-ChildItem -Path $RepoPath -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        ($textExts -contains $_.Extension) -and
        ($_.FullName -notmatch "\\node_modules\\") -and
        ($_.FullName -notmatch "\\.git\\")
    } |
    ForEach-Object {
        $fpath = $_.FullName
        $rel   = $fpath.Replace($RepoPath.ToString(),"").TrimStart("\")
        try {
            $content = Get-Content $fpath -Raw -ErrorAction SilentlyContinue
            foreach ($ioc in $IOC_STRINGS) {
                if ($content -match [regex]::Escape($ioc)) {
                    Write-Host "  [HIT] '$ioc' found in: $rel" -ForegroundColor Red
                    $iocHits += [PSCustomObject]@{ IOC=$ioc; File=$rel }
                }
            }
        } catch {}
    }

if ($iocHits.Count -eq 0) {
    Write-Host "  No IOC strings found." -ForegroundColor Green
}

# =============================================================================
# RESULTS
# =============================================================================
$totalHits = $confirmedHits.Count + $payloadCritical.Count + $iocHits.Count
$overall   = if ($totalHits -gt 0) { "AFFECTED" } else { "CLEAN" }
$col       = if ($totalHits -gt 0) { "Red" } else { "Green" }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($confirmedHits.Count -gt 0) {
    Write-Host "  *** $($confirmedHits.Count) CONFIRMED HIT(S) ***" -ForegroundColor Red
    Write-Host ""
    foreach ($r in $confirmedHits) {
        Write-Host "  [HIT]  $($r.Package)@$($r.Version)" -ForegroundColor Red
        Write-Host "         File         : $($r.File)"
        Write-Host "         All bad vers : $($r.BadVersions)"
        Write-Host ""
    }
} else {
    Write-Host "  Lockfile check -- CLEAN. No affected versions found." -ForegroundColor Green
    Write-Host ""
}

if ($safeVersions.Count -gt 0) {
    Write-Host "  Same packages present but on SAFE versions:" -ForegroundColor Yellow
    foreach ($r in $safeVersions) {
        Write-Host "  [OK]   $($r.Package)@$($r.Version)  ($($r.File))" -ForegroundColor Yellow
    }
    Write-Host ""
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor White
Write-Host "============================================================"
Write-Host "  Scan date             : $timestamp"
Write-Host "  Folder scanned        : $RepoPath"
Write-Host "  Lockfiles found       : $($lockfilesFound.Count)"
Write-Host "  IOC packages checked  : $($AFFECTED.Count)"
Write-Host "  Confirmed pkg hits    : $($confirmedHits.Count)" -ForegroundColor $col
Write-Host "  Safe versions seen    : $($safeVersions.Count)"
Write-Host "  Payload files (crit)  : $($payloadCritical.Count)" -ForegroundColor $col
Write-Host "  IOC string hits       : $($iocHits.Count)" -ForegroundColor $col
Write-Host "  Overall status        : $overall" -ForegroundColor $col

if ($totalHits -gt 0) {
    Write-Host ""
    Write-Host "  IMMEDIATE ACTIONS -- DO IN THIS ORDER:" -ForegroundColor Red
    Write-Host "  1. Remove gh-token-monitor daemon BEFORE revoking tokens" -ForegroundColor Red
    Write-Host "     Run: launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist" -ForegroundColor Red
    Write-Host "  2. Delete payload files from .claude/ and .vscode/" -ForegroundColor Red
    Write-Host "  3. Rotate: GitHub tokens, npm tokens, AWS creds, CI/CD secrets" -ForegroundColor Red
    Write-Host "  4. Block:  git-tanstack.com | *.getsession.org | 83.142.209.194" -ForegroundColor Red
} else {
    Write-Host ""
    Write-Host "  No action required. Safe to report as unaffected." -ForegroundColor Green
}

Write-Host ""
Write-Host "  Ref: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
Write-Host ""

# =============================================================================
# SAVE REPORT
# =============================================================================
$reportPath = Join-Path $RepoPath "triage_results.txt"
$report = @"
Mini Shai-Hulud / TeamPCP -- Triage Report
============================================================
Date              : $timestamp
Folder scanned    : $RepoPath
Overall status    : $overall

Lockfiles found   : $($lockfilesFound.Count)
Packages checked  : $($AFFECTED.Count)
Confirmed hits    : $($confirmedHits.Count)
Safe versions     : $($safeVersions.Count)
Payload files     : $($payloadCritical.Count)
IOC string hits   : $($iocHits.Count)

CONFIRMED PACKAGE HITS:
$(if ($confirmedHits.Count -eq 0) { "None" } else { ($confirmedHits | ForEach-Object { "  $($_.Package)@$($_.Version) -- $($_.File)" }) -join "`n" })

SAFE VERSIONS (package present, not bad version):
$(if ($safeVersions.Count -eq 0) { "None" } else { ($safeVersions | ForEach-Object { "  $($_.Package)@$($_.Version) -- $($_.File)" }) -join "`n" })

PAYLOAD FILES FOUND:
$(if ($payloadCritical.Count -eq 0) { "None" } else { ($payloadCritical | ForEach-Object { "  $_" }) -join "`n" })

IOC STRINGS FOUND:
$(if ($iocHits.Count -eq 0) { "None" } else { ($iocHits | ForEach-Object { "  '$($_.IOC)' in $($_.File)" }) -join "`n" })

Ref: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
"@

$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "  Report saved to: $reportPath"
Write-Host ""
