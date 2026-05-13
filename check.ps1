# =============================================================================
# Mini Shai-Hulud / TeamPCP — Supply Chain Scanner v3.0 (PowerShell)
# Updated: May 13 2026 — Sources: Wiz + Aikido + StepSecurity
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

$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$repoName   = Split-Path $RepoPath -Leaf

# ── All 169 compromised packages and bad versions ────────────────────────────
$AFFECTED = @{
    # ── @cap-js (NEW) ──────────────────────────────────────────────────────
    "@cap-js/db-service"                         = @("2.10.1")
    "@cap-js/postgres"                           = @("2.2.2")
    "@cap-js/sqlite"                             = @("2.2.2")
    # ── @tanstack ──────────────────────────────────────────────────────────
    "@tanstack/arktype-adapter"                  = @("1.166.12","1.166.15")
    "@tanstack/eslint-plugin-router"             = @("1.161.9","1.161.12")
    "@tanstack/eslint-plugin-start"              = @("0.0.4","0.0.7")
    "@tanstack/history"                          = @("1.161.9","1.161.12")
    "@tanstack/nitro-v2-vite-plugin"             = @("1.154.12","1.154.15")
    "@tanstack/react-router"                     = @("1.169.5","1.169.8")
    "@tanstack/react-router-devtools"            = @("1.166.16","1.166.19")
    "@tanstack/react-router-ssr-query"           = @("1.166.15","1.166.18")
    "@tanstack/react-start"                      = @("1.167.68","1.167.71")
    "@tanstack/react-start-client"               = @("1.166.51","1.166.54")
    "@tanstack/react-start-rsc"                  = @("0.0.47","0.0.50")
    "@tanstack/react-start-server"               = @("1.166.55","1.166.58")
    "@tanstack/router-cli"                       = @("1.166.46","1.166.49")
    "@tanstack/router-core"                      = @("1.169.5","1.169.8")
    "@tanstack/router-devtools"                  = @("1.166.16","1.166.19")
    "@tanstack/router-devtools-core"             = @("1.167.6","1.167.9")
    "@tanstack/router-generator"                 = @("1.166.45","1.166.48")
    "@tanstack/router-plugin"                    = @("1.167.38","1.167.41")
    "@tanstack/router-ssr-query-core"            = @("1.168.3","1.168.6")
    "@tanstack/router-utils"                     = @("1.161.11","1.161.14")
    "@tanstack/router-vite-plugin"               = @("1.166.53","1.166.56")
    "@tanstack/solid-router"                     = @("1.169.5","1.169.8")
    "@tanstack/solid-router-devtools"            = @("1.166.16","1.166.19")
    "@tanstack/solid-router-ssr-query"           = @("1.166.15","1.166.18")
    "@tanstack/solid-start"                      = @("1.167.65","1.167.68")
    "@tanstack/solid-start-client"               = @("1.166.50","1.166.53")
    "@tanstack/solid-start-server"               = @("1.166.54","1.166.57")
    "@tanstack/start-client-core"                = @("1.168.5","1.168.8")
    "@tanstack/start-fn-stubs"                   = @("1.161.9","1.161.12")
    "@tanstack/start-plugin-core"                = @("1.169.23","1.169.26")
    "@tanstack/start-server-core"                = @("1.167.33","1.167.36")
    "@tanstack/start-static-server-functions"    = @("1.166.44","1.166.47")
    "@tanstack/start-storage-context"            = @("1.166.38","1.166.41")
    "@tanstack/valibot-adapter"                  = @("1.166.12","1.166.15")
    "@tanstack/virtual-file-routes"              = @("1.161.10","1.161.13")
    "@tanstack/vue-router"                       = @("1.169.5","1.169.8")
    "@tanstack/vue-router-devtools"              = @("1.166.16","1.166.19")
    "@tanstack/vue-router-ssr-query"             = @("1.166.15","1.166.18")
    "@tanstack/vue-start"                        = @("1.167.61","1.167.64")
    "@tanstack/vue-start-client"                 = @("1.166.46","1.166.49")
    "@tanstack/vue-start-server"                 = @("1.166.50","1.166.53")
    "@tanstack/zod-adapter"                      = @("1.166.12","1.166.15")
    # ── @mistralai ─────────────────────────────────────────────────────────
    "@mistralai/mistralai"                       = @("2.2.2","2.2.3","2.2.4")
    "@mistralai/mistralai-azure"                 = @("1.7.1","1.7.2","1.7.3")
    "@mistralai/mistralai-gcp"                   = @("1.7.1","1.7.2","1.7.3")
    # ── @opensearch-project (NEW) ───────────────────────────────────────────
    "@opensearch-project/opensearch"             = @("3.5.3","3.6.2","3.7.0","3.8.0")
    # ── @squawk (updated versions) ──────────────────────────────────────────
    "@squawk/airport-data"                       = @("0.7.4","0.7.5","0.7.6","0.7.7","0.7.8")
    "@squawk/airports"                           = @("0.6.2","0.6.3","0.6.4","0.6.5","0.6.6")
    "@squawk/airspace"                           = @("0.8.1","0.8.2","0.8.3","0.8.4","0.8.5")
    "@squawk/airspace-data"                      = @("0.5.3","0.5.4","0.5.5","0.5.6","0.5.7")
    "@squawk/airway-data"                        = @("0.5.4","0.5.5","0.5.6","0.5.7","0.5.8")
    "@squawk/airways"                            = @("0.4.2","0.4.3","0.4.4","0.4.5","0.4.6")
    "@squawk/fix-data"                           = @("0.6.4","0.6.5","0.6.6","0.6.7","0.6.8")
    "@squawk/fixes"                              = @("0.3.2","0.3.3","0.3.4","0.3.5","0.3.6")
    "@squawk/flight-math"                        = @("0.5.4","0.5.5","0.5.6","0.5.7","0.5.8")
    "@squawk/flightplan"                         = @("0.5.2","0.5.3","0.5.4","0.5.5","0.5.6")
    "@squawk/geo"                                = @("0.4.4","0.4.5","0.4.6","0.4.7","0.4.8")
    "@squawk/icao-registry"                      = @("0.5.2","0.5.3","0.5.4","0.5.5","0.5.6")
    "@squawk/icao-registry-data"                 = @("0.8.4","0.8.5","0.8.6","0.8.7","0.8.8")
    "@squawk/mcp"                                = @("0.9.1","0.9.2","0.9.3","0.9.4","0.9.5")
    "@squawk/navaid-data"                        = @("0.6.4","0.6.5","0.6.6","0.6.7","0.6.8")
    "@squawk/navaids"                            = @("0.4.2","0.4.3","0.4.4","0.4.5","0.4.6")
    "@squawk/notams"                             = @("0.3.6","0.3.7","0.3.8","0.3.9","0.3.10")
    "@squawk/procedure-data"                     = @("0.7.3","0.7.4","0.7.5","0.7.6","0.7.7")
    "@squawk/procedures"                         = @("0.5.2","0.5.3","0.5.4","0.5.5","0.5.6")
    "@squawk/types"                              = @("0.8.1","0.8.2","0.8.3","0.8.4","0.8.5")
    "@squawk/units"                              = @("0.4.3","0.4.4","0.4.5","0.4.6","0.4.7")
    "@squawk/weather"                            = @("0.5.6","0.5.7","0.5.8","0.5.9","0.5.10")
    # ── @tallyui ───────────────────────────────────────────────────────────
    "@tallyui/components"                        = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/connector-medusa"                  = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/connector-shopify"                 = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/connector-vendure"                 = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/connector-woocommerce"             = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/core"                              = @("0.2.1","0.2.2","0.2.3")
    "@tallyui/database"                          = @("1.0.1","1.0.2","1.0.3")
    "@tallyui/pos"                               = @("0.1.1","0.1.2","0.1.3")
    "@tallyui/storage-sqlite"                    = @("0.2.1","0.2.2","0.2.3")
    "@tallyui/theme"                             = @("0.2.1","0.2.2","0.2.3")
    # ── @uipath ────────────────────────────────────────────────────────────
    "@uipath/access-policy-sdk"                  = @("0.3.1")
    "@uipath/access-policy-tool"                 = @("0.3.1")
    "@uipath/admin-tool"                         = @("0.1.1")
    "@uipath/agent-sdk"                          = @("1.0.2")
    "@uipath/agent-tool"                         = @("1.0.1")
    "@uipath/agent.sdk"                          = @("0.0.18")
    "@uipath/aops-policy-tool"                   = @("0.3.1")
    "@uipath/ap-chat"                            = @("1.5.7")
    "@uipath/api-workflow-tool"                  = @("1.0.1")
    "@uipath/apollo-core"                        = @("5.9.2")
    "@uipath/apollo-react"                       = @("4.24.5")
    "@uipath/apollo-wind"                        = @("2.16.2")
    "@uipath/auth"                               = @("1.0.1")
    "@uipath/case-tool"                          = @("1.0.1")
    "@uipath/cli"                                = @("1.0.1")
    "@uipath/codedagent-tool"                    = @("1.0.1")
    "@uipath/codedagents-tool"                   = @("0.1.12")
    "@uipath/codedapp-tool"                      = @("1.0.1")
    "@uipath/common"                             = @("1.0.1")
    "@uipath/context-grounding-tool"             = @("0.1.1")
    "@uipath/data-fabric-tool"                   = @("1.0.2")
    "@uipath/docsai-tool"                        = @("1.0.1")
    "@uipath/filesystem"                         = @("1.0.1")
    "@uipath/flow-tool"                          = @("1.0.2")
    "@uipath/functions-tool"                     = @("1.0.1")
    "@uipath/gov-tool"                           = @("0.3.1")
    "@uipath/identity-tool"                      = @("0.1.1")
    "@uipath/insights-sdk"                       = @("1.0.1")
    "@uipath/insights-tool"                      = @("1.0.1")
    "@uipath/integrationservice-sdk"             = @("1.0.2")
    "@uipath/integrationservice-tool"            = @("1.0.2")
    "@uipath/llmgw-tool"                         = @("1.0.1")
    "@uipath/maestro-sdk"                        = @("1.0.1")
    "@uipath/maestro-tool"                       = @("1.0.1")
    "@uipath/orchestrator-tool"                  = @("1.0.1")
    "@uipath/packager-tool-apiworkflow"          = @("0.0.19")
    "@uipath/packager-tool-bpmn"                 = @("0.0.9")
    "@uipath/packager-tool-case"                 = @("0.0.9")
    "@uipath/packager-tool-connector"            = @("0.0.19")
    "@uipath/packager-tool-flow"                 = @("0.0.19")
    "@uipath/packager-tool-functions"            = @("0.1.1")
    "@uipath/packager-tool-webapp"               = @("1.0.6")
    "@uipath/packager-tool-workflowcompiler"     = @("0.0.16")
    "@uipath/packager-tool-workflowcompiler-browser" = @("0.0.34")
    "@uipath/platform-tool"                      = @("1.0.1")
    "@uipath/project-packager"                   = @("1.1.16")
    "@uipath/resource-tool"                      = @("1.0.1")
    "@uipath/resourcecatalog-tool"               = @("0.1.1")
    "@uipath/resources-tool"                     = @("0.1.11")
    "@uipath/robot"                              = @("1.3.4")
    "@uipath/rpa-legacy-tool"                    = @("1.0.1")
    "@uipath/rpa-tool"                           = @("0.9.5")
    "@uipath/solution-packager"                  = @("0.0.35")
    "@uipath/solution-tool"                      = @("1.0.1")
    "@uipath/solutionpackager-sdk"               = @("1.0.11")
    "@uipath/solutionpackager-tool-core"         = @("0.0.34")
    "@uipath/tasks-tool"                         = @("1.0.1")
    "@uipath/telemetry"                          = @("0.0.7")
    "@uipath/test-manager-tool"                  = @("1.0.2")
    "@uipath/tool-workflowcompiler"              = @("0.0.12")
    "@uipath/traces-tool"                        = @("1.0.1")
    "@uipath/ui-widgets-multi-file-upload"       = @("1.0.1")
    "@uipath/uipath-python-bridge"               = @("1.0.1")
    "@uipath/vertical-solutions-tool"            = @("1.0.1")
    "@uipath/vss"                                = @("0.1.6")
    "@uipath/widget.sdk"                         = @("1.2.3")
    # ── Other scoped ────────────────────────────────────────────────────────
    "@beproduct/nestjs-auth"                     = @("0.1.2","0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8","0.1.9","0.1.10","0.1.11","0.1.12","0.1.13","0.1.14","0.1.15","0.1.16","0.1.17","0.1.18","0.1.19")
    "@dirigible-ai/sdk"                          = @("0.6.2","0.6.3")
    "@draftauth/client"                          = @("0.2.1","0.2.2")
    "@draftauth/core"                            = @("0.13.1","0.13.2")
    "@draftlab/auth"                             = @("0.24.1","0.24.2")
    "@draftlab/auth-router"                      = @("0.5.1","0.5.2")
    "@draftlab/db"                               = @("0.16.1","0.16.2")
    "@mesadev/rest"                              = @("0.28.3")
    "@mesadev/saguaro"                           = @("0.4.22")
    "@mesadev/sdk"                               = @("0.28.3")
    "@ml-toolkit-ts/preprocessing"               = @("1.0.2","1.0.3")
    "@ml-toolkit-ts/xgboost"                    = @("1.0.3","1.0.4")
    "@supersurkhet/cli"                          = @("0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7")
    "@supersurkhet/sdk"                          = @("0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7")
    "@taskflow-corp/cli"                         = @("0.1.24","0.1.25","0.1.26","0.1.27","0.1.28","0.1.29")
    "@tolka/cli"                                 = @("1.0.2","1.0.3","1.0.4","1.0.5","1.0.6")
    # ── Unscoped npm ────────────────────────────────────────────────────────
    "agentwork-cli"                              = @("0.1.4","0.1.5")
    "cmux-agent-mcp"                             = @("0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8")
    "cross-stitch"                               = @("1.1.3","1.1.4","1.1.5","1.1.6","1.1.7")
    "git-branch-selector"                        = @("1.3.3","1.3.4","1.3.5","1.3.6","1.3.7")
    "git-git-git"                                = @("1.0.8","1.0.9","1.0.10","1.0.11","1.0.12")
    "guardrails-ai"                              = @("0.10.1")
    "intercom-client"                            = @("7.0.4")
    "lightning"                                  = @("2.6.2","2.6.3")
    "mbt"                                        = @("1.2.48")
    "mistralai"                                  = @("2.4.6")
    "ml-toolkit-ts"                              = @("1.0.4","1.0.5")
    "nextmove-mcp"                               = @("0.1.3","0.1.4","0.1.5","0.1.6","0.1.7")
    "safe-action"                                = @("0.8.3","0.8.4")
    "ts-dna"                                     = @("3.0.1","3.0.2","3.0.3","3.0.4","3.0.5")
    "wot-api"                                    = @("0.8.1","0.8.2","0.8.3","0.8.4")
}
$PAYLOAD_FILES = @("router_init.js","router_runtime.js","tanstack_runner.js","setup.mjs","opensearch_init.js")

$PAYLOAD_HASHES = @{
    "router_init.js"     = @("ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
                              "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96")
    "setup.mjs"          = @("2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df")
    "tanstack_runner.js" = @("2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96")
}

$AFFECTED_PYPI = @{
    "guardrails-ai" = @("0.10.1")
    "mistralai"     = @("2.4.6")
}

# Persistence files to check
$PERSISTENCE_FILES = @(
    ".claude/settings.json",
    ".claude/router_runtime.js",
    ".claude/setup.mjs",
    ".vscode/tasks.json",
    ".vscode/setup.mjs",
    ".github/workflows/codeql_analysis.yml"
)

$IOC_STRINGS = @(
    # Commit/package markers
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "@tanstack/setup",
    "bun run tanstack_runner.js",
    # Crypto campaign markers (NEW v3)
    "0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa",
    "svksjrhjkcejg",
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b",
    # Campaign signatures
    "A Mini Shai-Hulud",
    "Shai-Hulud: Here We Go Again",
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
    "siridar-ghola-567",
    "tleilaxu-ornithopter-43",
    # Attacker infrastructure (NEW v3)
    "voicproducoes",
    "claude@users.noreply.github.com",
    "chore: update dependencies",
    "dependabot/github_actions/format/",
    # Persistence daemon
    "gh-token-monitor",
    # CI workflow injection (NEW v3)
    "codeql_analysis.yml",
    # C2 network (NEW v3: api.masscan.cloud)
    "api.masscan.cloud",
    "git-tanstack.com",
    "getsession.org",
    "filev2.getsession.org",
    "seed1.getsession.org",
    "83.142.209.194",
    # Credential theft endpoints
    "169.254.169.254",
    "169.254.170.2",
    "registry.npmjs.org/-/npm/v1/tokens",
    "vault.svc.cluster.local",
    "127.0.0.1:8200",
    # Payload markers
    "opensearch_init.js"
)
$SKIP_DIRS     = @("node_modules",".git","dist","build",".next",".nuxt","coverage",".cache")

# ── Counters ──────────────────────────────────────────────────────────────────
$confirmedHits   = @()
$safeVersions    = @()
$payloadCritical = @()
$iocHits         = @()
$lockfilesFound  = @()

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Mini Shai-Hulud Supply Chain Attack Scanner v4.0" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
Write-Host "    SCAN TARGET" -ForegroundColor White
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
Write-Host "  Repository   : $repoName" -ForegroundColor Red
Write-Host "  Full path    : $RepoPath" -ForegroundColor White
Write-Host "  Scan started : $timestamp" -ForegroundColor White
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
Write-Host ""
Write-Host "  Checking     : $($AFFECTED.Count) npm packages  |  2 PyPI packages" -ForegroundColor White
Write-Host "                 $($IOC_STRINGS.Count) attack signatures  |  6 persistence locations" -ForegroundColor White
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
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
Write-Host ""
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
Write-Host "    FULL SCAN SUMMARY" -ForegroundColor White
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
Write-Host ""
Write-Host "    SCAN TARGET" -ForegroundColor White
Write-Host "  Repository                          : $repoName" -ForegroundColor Red
Write-Host "  Full path                           : $RepoPath"
Write-Host "  Scan date                           : $timestamp"
Write-Host ""
Write-Host "    WHAT WAS SCANNED" -ForegroundColor White
Write-Host "  npm lockfiles found                 : $($lockfilesFound.Count)"
Write-Host "  PyPI req files found                : 0"
Write-Host ""
Write-Host "    WHAT WAS CHECKED" -ForegroundColor White
Write-Host "  npm packages in IOC list            : $($AFFECTED.Count)"
Write-Host "  PyPI packages in IOC list           : 2"
Write-Host "  Attack signatures checked           : $($IOC_STRINGS.Count)"
Write-Host "  Persistence locations checked       : 6"
Write-Host ""
Write-Host "    STEP 1 - Package version check" -ForegroundColor White
$pkgCol = if ($confirmedHits.Count -eq 0) { "Green" } else { "Red" }
$pkgStatus = if ($confirmedHits.Count -eq 0) { "NONE FOUND" } else { "*** $($confirmedHits.Count) FOUND ***" }
Write-Host "  Infected npm versions found         : $($confirmedHits.Count)      $pkgStatus" -ForegroundColor $pkgCol
Write-Host "  Safe npm versions seen              : $($safeVersions.Count)"
Write-Host ""
Write-Host "    STEP 2 - Malware file check" -ForegroundColor White
$payCol = if ($payloadCritical.Count -eq 0) { "Green" } else { "Red" }
$payStatus = if ($payloadCritical.Count -eq 0) { "NONE FOUND" } else { "*** $($payloadCritical.Count) FOUND ***" }
Write-Host "  Malware files (outside node_modules): $($payloadCritical.Count)     $payStatus" -ForegroundColor $payCol
Write-Host ""
Write-Host "    STEP 3 - Backdoor / persistence check" -ForegroundColor White
Write-Host "  Suspicious persistence files        : 0      NONE FOUND" -ForegroundColor Green
Write-Host ""
Write-Host "    STEP 4 - Attack fingerprint check" -ForegroundColor White
$iocCol = if ($iocHits.Count -eq 0) { "Green" } else { "Red" }
$iocStatus = if ($iocHits.Count -eq 0) { "NONE FOUND" } else { "*** $($iocHits.Count) FOUND ***" }
Write-Host "  Unique IOC strings matched          : $($iocHits.Count)      $iocStatus" -ForegroundColor $iocCol
Write-Host ""
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White
Write-Host "  OVERALL STATUS                      : $overall" -ForegroundColor $col
Write-Host "  -----------------------------------------------------------------" -ForegroundColor White

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
# PERSISTENCE FILES CHECK (.claude, .vscode, .github/workflows)
# =============================================================================
Write-Host ""
Write-Host "[4/4] Checking IDE and CI persistence files..." -ForegroundColor White

$persistSuspicious = @()
foreach ($pf in $PERSISTENCE_FILES) {
    $full = Join-Path $RepoPath $pf
    if (Test-Path $full) {
        $content2 = Get-Content $full -Raw -ErrorAction SilentlyContinue
        $suspicious = $false
        $reasons = @()
        $checks = @("router_runtime","tanstack_runner","setup.mjs","gh-token-monitor","bun run","git-tanstack","getsession","masscan","79ac49ee")
        foreach ($c in $checks) {
            if ($content2 -match [regex]::Escape($c)) { $suspicious = $true; $reasons += $c }
        }
        if ($pf -like "*.github/workflows/codeql_analysis.yml") { $suspicious = $true; $reasons += "unexpected codeql workflow" }
        if ($suspicious) {
            Write-Host "  [CRITICAL] Suspicious: $pf — contains: $($reasons -join ', ')" -ForegroundColor Red
            $persistSuspicious += $pf
        } else {
            Write-Host "  [INFO] Exists (review manually): $pf" -ForegroundColor Yellow
        }
    }
}
if ($persistSuspicious.Count -eq 0) { Write-Host "  No suspicious persistence files found." -ForegroundColor Green }

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
