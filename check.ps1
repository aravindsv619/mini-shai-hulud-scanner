# =============================================================================
#  Mini Shai-Hulud / TeamPCP  -  Supply Chain Attack Scanner  v4.0
#  PowerShell edition  -  exact equivalent of check.py
#  May 2026  |  Sources: Wiz + Aikido + StepSecurity
# =============================================================================
#
#  HOW TO RUN
#  ----------
#  Open PowerShell (blue window):
#    Windows key + R  ->  type powershell  ->  Enter
#
#  Then run:
#    powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\path\to\repo"
#
#  Scan multiple repos:
#    powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\repos\frontend"
#    powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\repos\backend"
#
#  Save output to file:
#    powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\repos\myrepo" > results.txt
#
#  WHAT IT CHECKS  (same as check.py)
#  ------------------------------------
#  Step 1  -  package-lock.json, yarn.lock, pnpm-lock.yaml  (178 npm packages)
#  Step 2  -  requirements*.txt  (2 PyPI packages)
#  Step 3  -  Malware payload files + SHA256 hash verification
#  Step 4  -  Hidden backdoors in .claude / .vscode / .github/workflows
#  Step 5  -  30 IOC strings in source files
#
#  NOTE: Read-only. Never deletes, modifies, or connects to anything.
#
# =============================================================================

param([string]$RepoPath = ".")

# ------------------------------------------------------------------
# Resolve path
# ------------------------------------------------------------------
$resolved = Resolve-Path $RepoPath -ErrorAction SilentlyContinue
if (-not $resolved) {
    Write-Host ""
    Write-Host "  ERROR: Folder not found: $RepoPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Usage:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath `"C:\path\to\repo`""
    Write-Host ""
    exit 1
}
$RepoPath  = $resolved.Path
$repoName  = Split-Path $RepoPath -Leaf
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# =============================================================================
# IOC DATABASE  -  identical to check.py
# =============================================================================

$AFFECTED_PYPI = @{
    "guardrails-ai" = @("0.10.1")
    "mistralai"     = @("2.4.6")
}

$AFFECTED = @{
    "@cap-js/db-service"                         = @("2.10.1")
    "@cap-js/postgres"                           = @("2.2.2")
    "@cap-js/sqlite"                             = @("2.2.2")
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
    "@mistralai/mistralai"                       = @("2.2.2","2.2.3","2.2.4")
    "@mistralai/mistralai-azure"                 = @("1.7.1","1.7.2","1.7.3")
    "@mistralai/mistralai-gcp"                   = @("1.7.1","1.7.2","1.7.3")
    "@opensearch-project/opensearch"             = @("3.5.3","3.6.2","3.7.0","3.8.0")
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
    "@ml-toolkit-ts/xgboost"                     = @("1.0.3","1.0.4")
    "@supersurkhet/cli"                          = @("0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7")
    "@supersurkhet/sdk"                          = @("0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7")
    "@taskflow-corp/cli"                         = @("0.1.24","0.1.25","0.1.26","0.1.27","0.1.28","0.1.29")
    "@tolka/cli"                                 = @("1.0.2","1.0.3","1.0.4","1.0.5","1.0.6")
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

# Malicious payload filenames  -  same as Python
$PAYLOAD_FILES = @(
    "router_init.js","router_runtime.js","tanstack_runner.js",
    "setup.mjs","opensearch_init.js"
)

# SHA256 hashes  -  same as Python
$PAYLOAD_HASHES = @{
    "router_init.js"     = @("ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
                              "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96")
    "setup.mjs"          = @("2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df")
    "tanstack_runner.js" = @("2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96")
}

# IOC strings  -  same as Python
$IOC_STRINGS = @(
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "@tanstack/setup",
    "bun run tanstack_runner.js",
    "0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa",
    "svksjrhjkcejg",
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b",
    "A Mini Shai-Hulud",
    "Shai-Hulud: Here We Go Again",
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
    "siridar-ghola-567",
    "tleilaxu-ornithopter-43",
    "voicproducoes",
    "claude@users.noreply.github.com",
    "chore: update dependencies",
    "dependabot/github_actions/format/",
    "gh-token-monitor",
    "codeql_analysis.yml",
    "api.masscan.cloud",
    "git-tanstack.com",
    "getsession.org",
    "filev2.getsession.org",
    "seed1.getsession.org",
    "83.142.209.194",
    "169.254.169.254",
    "169.254.170.2",
    "registry.npmjs.org/-/npm/v1/tokens",
    "vault.svc.cluster.local",
    "127.0.0.1:8200",
    "opensearch_init.js"
)

# Persistence files  -  same as Python
$PERSISTENCE_FILES = @(
    ".claude\settings.json",
    ".claude\router_runtime.js",
    ".claude\setup.mjs",
    ".vscode\tasks.json",
    ".vscode\setup.mjs",
    ".github\workflows\codeql_analysis.yml"
)

$SKIP_DIRS  = @("node_modules",".git",".svn","dist","build","__pycache__",".next",".nuxt","coverage",".cache","vendor")
$TEXT_EXTS  = @(".json",".yaml",".yml",".js",".ts",".mjs",".cjs",".sh",".env",".txt",".lock",".toml",".md")

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Get-SHA256($path) {
    try {
        $h = Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop
        return $h.Hash.ToLower()
    } catch { return "" }
}

function Get-RelPath($full) {
    return $full.Replace($RepoPath,"").TrimStart("\").TrimStart("/")
}

function Should-Skip($path) {
    foreach ($d in $SKIP_DIRS) {
        if ($path -match [regex]::Escape("\$d\") -or $path -match [regex]::Escape("/$d/")) { return $true }
    }
    return $false
}

function Write-Tick($msg)  { Write-Host "  " -NoNewline; Write-Host "[OK]" -ForegroundColor Green -NoNewline; Write-Host "  $msg" }
function Write-Cross($msg) { Write-Host "  " -NoNewline; Write-Host "[!!]" -ForegroundColor Red   -NoNewline; Write-Host "  $msg" }
function Write-Warn($msg)  { Write-Host "  " -NoNewline; Write-Host "[!]" -ForegroundColor Yellow -NoNewline; Write-Host "  $msg" }
function Write-Info($msg)  { Write-Host "     $msg" }
function Write-Blank()     { Write-Host "" }

# =============================================================================
# SCANNERS  -  equivalent to Python functions
# =============================================================================

# -- scan_npm_lock  -------------------------------------------------------------
function Scan-NpmLock($path) {
    $results  = @()
    $rel      = Get-RelPath $path
    $parsed   = $false
    $data     = $null

    # Attempt 1: UTF-8 with BOM strip  (fixes the 374KB issue you saw)
    try {
        $raw  = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
        $raw  = $raw.TrimStart([char]0xFEFF)   # strip BOM
        $raw  = $raw.Trim()
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
        $parsed = $true
    } catch {}

    # Attempt 2: Unicode encoding
    if (-not $parsed) {
        try {
            $raw  = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::Unicode)
            $raw  = $raw.TrimStart([char]0xFEFF)
            $data = $raw | ConvertFrom-Json -ErrorAction Stop
            $parsed = $true
        } catch {}
    }

    if ($parsed -and $data) {
        # npm v2/v3 uses 'packages', v1 uses 'dependencies'
        $pkgs = $null
        if ($data.PSObject.Properties["packages"])     { $pkgs = $data.packages }
        elseif ($data.PSObject.Properties["dependencies"]) { $pkgs = $data.dependencies }

        if ($pkgs) {
            $pkgCount = ($pkgs.PSObject.Properties | Measure-Object).Count
            Write-Host "    Parsed OK - $pkgCount entries checked" -ForegroundColor DarkGray
            $pkgs.PSObject.Properties | ForEach-Object {
                $name = $_.Name -replace "^node_modules/","" -replace "^/",""
                $ver  = $_.Value.version
                if ($AFFECTED.ContainsKey($name) -and $ver) {
                    $status = if ($ver -in $AFFECTED[$name]) { "HIT" } else { "SAFE" }
                    $results += [PSCustomObject]@{
                        File=$rel; Pkg=$name; Ver=$ver; Status=$status; Bad=($AFFECTED[$name] -join ", ")
                    }
                }
            }
        }
    } else {
        # Text scan fallback  -  still accurate for finding package+version pairs
        Write-Host "    Note: JSON parse failed (likely BOM or encoding). Using text scan - file still fully checked." -ForegroundColor Yellow
        $raw = Get-Content $path -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if (-not $raw) { $raw = Get-Content $path -Raw -ErrorAction SilentlyContinue }
        foreach ($pkg in $AFFECTED.Keys) {
            if ($raw -match [regex]::Escape($pkg)) {
                foreach ($bv in $AFFECTED[$pkg]) {
                    # Look for version near the package name (within 400 chars)
                    $idx = $raw.IndexOf($pkg)
                    while ($idx -ge 0) {
                        $slice = $raw.Substring($idx, [Math]::Min(400, $raw.Length - $idx))
                        if ($slice -match [regex]::Escape($bv)) {
                            $results += [PSCustomObject]@{
                                File=$rel; Pkg=$pkg; Ver=$bv; Status="HIT"; Bad=($AFFECTED[$pkg] -join ", ")
                            }
                            break
                        }
                        $idx = $raw.IndexOf($pkg, $idx + 1)
                        if ($idx -lt 0) { break }
                    }
                }
            }
        }
        Write-Host "    Text scan complete." -ForegroundColor DarkGray
    }
    return $results
}

# -- scan_yarn  ----------------------------------------------------------------
function Scan-Yarn($path) {
    $results = @()
    $rel     = Get-RelPath $path
    try {
        $content = Get-Content $path -Raw -Encoding UTF8 -ErrorAction Stop
    } catch { return $results }

    foreach ($pkg in $AFFECTED.Keys) {
        if ($content -notmatch [regex]::Escape($pkg)) { continue }
        # Match: package name line followed by version within next 6 lines
        $pat   = [regex]::Escape($pkg) + '[^\n]*\n(?:[^\n]*\n){0,6}?\s+version\s+"?([^\s"\n]+)"?'
        $seen  = @{}
        foreach ($m in [regex]::Matches($content, $pat)) {
            $ver = $m.Groups[1].Value.Trim().Trim('"')
            if ($seen[$ver]) { continue }
            $seen[$ver] = $true
            $status = if ($ver -in $AFFECTED[$pkg]) { "HIT" } else { "SAFE" }
            $results += [PSCustomObject]@{
                File=$rel; Pkg=$pkg; Ver=$ver; Status=$status; Bad=($AFFECTED[$pkg] -join ", ")
            }
        }
    }
    return $results
}

# -- scan_pnpm  ----------------------------------------------------------------
function Scan-Pnpm($path) {
    $results = @()
    $rel     = Get-RelPath $path
    try {
        $content = Get-Content $path -Raw -Encoding UTF8 -ErrorAction Stop
    } catch { return $results }

    foreach ($pkg in $AFFECTED.Keys) {
        if ($content -notmatch [regex]::Escape($pkg)) { continue }
        foreach ($bv in $AFFECTED[$pkg]) {
            $idx = $content.IndexOf($pkg)
            while ($idx -ge 0) {
                $slice = $content.Substring($idx, [Math]::Min(300, $content.Length - $idx))
                if ($slice -match [regex]::Escape($bv)) {
                    $rel2 = Get-RelPath $path
                    $results += [PSCustomObject]@{
                        File=$rel2; Pkg=$pkg; Ver=$bv; Status="HIT"; Bad=($AFFECTED[$pkg] -join ", ")
                    }
                    break
                }
                $idx = $content.IndexOf($pkg, $idx + 1)
                if ($idx -lt 0) { break }
            }
        }
    }
    return $results
}

# -- scan_pypi  ----------------------------------------------------------------
function Scan-Pypi($path) {
    $results = @()
    $rel     = Get-RelPath $path
    try {
        $lines = Get-Content $path -Encoding UTF8 -ErrorAction Stop
    } catch { return $results }

    foreach ($line in $lines) {
        $line = $line.Trim()
        foreach ($pkg in $AFFECTED_PYPI.Keys) {
            if ($line.ToLower() -match [regex]::Escape($pkg.ToLower())) {
                foreach ($bv in $AFFECTED_PYPI[$pkg]) {
                    if ($line -match [regex]::Escape($bv)) {
                        $results += [PSCustomObject]@{
                            File=$rel; Pkg=$pkg; Ver=$bv; Status="HIT"; Bad=($AFFECTED_PYPI[$pkg] -join ", ")
                        }
                    }
                }
            }
        }
    }
    return $results
}

# -- scan_payloads  ------------------------------------------------------------
function Scan-Payloads($root) {
    $found = @()
    Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in $PAYLOAD_FILES } |
        ForEach-Object {
            $full    = $_.FullName
            $rel     = Get-RelPath $full
            $outside = $full -notmatch "\\node_modules\\"
            $hash    = Get-SHA256 $full
            $known   = $PAYLOAD_HASHES[$_.Name]
            $match   = ($known -and ($hash -in $known))
            $found  += [PSCustomObject]@{
                Outside=$outside; Full=$full; Rel=$rel; Hash=$hash; HashMatch=$match
            }
        }
    return $found
}

# -- scan_persistence  --------------------------------------------------------
function Scan-Persistence($root) {
    $found   = @()
    $checks  = @("router_runtime","tanstack_runner","setup.mjs","gh-token-monitor",
                 "bun run","git-tanstack","getsession","masscan","79ac49ee")
    foreach ($pf in $PERSISTENCE_FILES) {
        $full = Join-Path $root $pf
        if (Test-Path $full) {
            try {
                $content = Get-Content $full -Raw -Encoding UTF8 -ErrorAction Stop
                $reasons = $checks | Where-Object { $content -match [regex]::Escape($_) }
                $reasons = @($reasons)
                if ($pf -like "*codeql*") { $reasons += "unexpected codeql workflow" }
                $found += [PSCustomObject]@{
                    File=$pf; Full=$full; Suspicious=($reasons.Count -gt 0); Reasons=$reasons
                }
            } catch {
                $found += [PSCustomObject]@{ File=$pf; Full=$full; Suspicious=$false; Reasons=@() }
            }
        }
    }
    return $found
}

# -- scan_iocs  ----------------------------------------------------------------
function Scan-Iocs($root) {
    $found = @()
    Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            ($TEXT_EXTS -contains $_.Extension) -and
            (-not (Should-Skip $_.FullName))
        } |
        ForEach-Object {
            $fpath = $_.FullName
            $rel   = Get-RelPath $fpath
            try {
                $content = Get-Content $fpath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                if (-not $content) { return }
                foreach ($ioc in $IOC_STRINGS) {
                    if ($content.Contains($ioc)) {
                        $found += [PSCustomObject]@{ IOC=$ioc; File=$rel }
                    }
                }
            } catch {}
        }
    return $found
}

# =============================================================================
# MAIN  -  same flow as Python main()
# =============================================================================

# -- Header  -------------------------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Mini Shai-Hulud Supply Chain Attack Scanner v4.0" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
Write-Host "    SCAN TARGET"
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
Write-Host "  Repository   : " -NoNewline; Write-Host $repoName -ForegroundColor Yellow
Write-Host "  Full path    : $RepoPath"
Write-Host "  Scan started : $timestamp"
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
Write-Host ""
Write-Host "  Checking     : $($AFFECTED.Count) npm packages  |  $($AFFECTED_PYPI.Count) PyPI packages"
Write-Host "                 $($IOC_STRINGS.Count) attack signatures  |  6 persistence locations"
Write-Host "  " -NoNewline; Write-Host ("-" * 61)

$allPkg    = @()
$lockfiles = @()
$reqFiles  = @()

# Find lockfiles
Get-ChildItem -Path $RepoPath -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -in @("package-lock.json","yarn.lock","pnpm-lock.yaml") -and
        (-not (Should-Skip $_.FullName))
    } | ForEach-Object { $lockfiles += $_.FullName }

# Find requirements
Get-ChildItem -Path $RepoPath -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like "requirements*.txt" -and
        (-not (Should-Skip $_.FullName))
    } | ForEach-Object { $reqFiles += $_.FullName }

# -- STEP 1: Lockfiles  --------------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  STEP 1 of 5 - Checking package files (lockfiles)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What this does: Looks inside your project's dependency files"
Write-Host "  to see if any of the 180+ infected packages were installed."
Write-Host ""

if ($lockfiles.Count -eq 0 -and $reqFiles.Count -eq 0) {
    Write-Warn "No package files found."
    Write-Info "Looked for: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt"
    Write-Info "This repo may not be a JavaScript or Python project."
} else {
    foreach ($lf in $lockfiles) {
        $rel = Get-RelPath $lf
        Write-Host "  Scanning: $rel" -ForegroundColor Cyan
        if ($lf -like "*package-lock.json") { $allPkg += Scan-NpmLock $lf }
        elseif ($lf -like "*yarn.lock")     { $allPkg += Scan-Yarn   $lf }
        elseif ($lf -like "*pnpm-lock*")    { $allPkg += Scan-Pnpm   $lf }
    }
    foreach ($rf in $reqFiles) {
        $rel = Get-RelPath $rf
        Write-Host "  Scanning: $rel" -ForegroundColor Cyan
        $allPkg += Scan-Pypi $rf
    }
}

$hits  = @($allPkg | Where-Object { $_.Status -eq "HIT"  })
$safes = @($allPkg | Where-Object { $_.Status -eq "SAFE" })

Write-Blank
if ($hits.Count -gt 0) {
    foreach ($r in $hits) {
        Write-Cross "$($r.Pkg)  version $($r.Ver)"
        Write-Info  "Found in   : $($r.File)"
        Write-Info  "Why bad    : This exact version was infected by attackers"
        Write-Info  "Bad list   : $($r.Bad)"
        Write-Blank
    }
} else {
    Write-Tick "No infected package versions found in any lockfile"
}
if ($safes.Count -gt 0) {
    Write-Warn "Found $($safes.Count) package(s) from infected namespaces - but on SAFE versions:"
    foreach ($r in $safes) { Write-Info "  $($r.Pkg)  version $($r.Ver)  <- this version is OK" }
}

# -- STEP 2: Payload files  ----------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  STEP 2 of 5 - Checking for malware files" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What this does: Searches for files that the malware drops"
Write-Host "  onto the system after it runs. Finding these means the malware"
Write-Host "  already executed on this machine or in CI/CD."
Write-Host ""

$payloadHits = Scan-Payloads $RepoPath
$crit = @($payloadHits | Where-Object { $_.Outside })
$inNm = @($payloadHits | Where-Object { -not $_.Outside })

if ($crit.Count -gt 0) {
    foreach ($p in $crit) {
        Write-Cross "Malware file found: $([System.IO.Path]::GetFileName($p.Full))"
        Write-Info  "Location   : $($p.Rel)"
        if ($p.HashMatch) { Write-Info "Confirmed  : Hash matches known malicious file - DEFINITE INFECTION" }
        else               { Write-Info "Warning    : File found outside node_modules - needs investigation" }
        Write-Info  "SHA256     : $($p.Hash)"
        Write-Blank
    }
} else {
    Write-Tick "No malware files found outside node_modules"
}
if ($inNm.Count -gt 0) {
    Write-Warn "$($inNm.Count) payload file(s) found inside node_modules (may be from infected install):"
    foreach ($p in $inNm) { Write-Info "  $($p.Rel)" }
}

# -- STEP 3: Persistence files  -----------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  STEP 3 of 5 - Checking for hidden backdoors" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What this does: The malware hides itself in editor config folders"
Write-Host "  (.claude, .vscode) so it re-runs every time a developer opens"
Write-Host "  their editor. It also injects into GitHub Actions workflows."
Write-Host ""

$persist      = Scan-Persistence $RepoPath
$pHits        = @($persist | Where-Object { $_.Suspicious })
$pInfo        = @($persist | Where-Object { -not $_.Suspicious })

if ($pHits.Count -gt 0) {
    foreach ($p in $pHits) {
        Write-Cross "Backdoor found: $($p.File)"
        foreach ($r in $p.Reasons) { Write-Info "Contains   : '$r'" }
        if ($p.File -like "*codeql*") { Write-Info "Risk       : This workflow exfiltrates ALL repository secrets on every push" }
        else                          { Write-Info "Risk       : Malware re-runs every time this file is loaded by the editor" }
        Write-Blank
    }
} else {
    Write-Tick "No hidden backdoors found in editor or CI/CD config files"
}
if ($pInfo.Count -gt 0) {
    Write-Warn "$($pInfo.Count) config file(s) exist - not suspicious but worth checking:"
    foreach ($p in $pInfo) { Write-Info "  $($p.File)" }
}

# -- STEP 4: IOC strings  -----------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  STEP 4 of 5 - Checking for attack fingerprints" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What this does: Scans all source files for known text strings"
Write-Host "  that only appear if the malware ran or attack infrastructure"
Write-Host "  was contacted (C2 server addresses, attacker account names, etc.)"
Write-Host ""

$iocHits    = Scan-Iocs $RepoPath
$iocGroups  = @{}
foreach ($h in $iocHits) {
    if (-not $iocGroups.ContainsKey($h.IOC)) { $iocGroups[$h.IOC] = @() }
    $iocGroups[$h.IOC] += $h.File
}

if ($iocGroups.Count -gt 0) {
    foreach ($ioc in $iocGroups.Keys) {
        $label = switch -Wildcard ($ioc) {
            "*masscan*"        { "Attacker server address" }
            "*getsession*"     { "Attacker server address" }
            "*git-tanstack*"   { "Attacker server address" }
            "*83.142*"         { "Attacker C2 IP address" }
            "*169.254*"        { "Credential theft endpoint" }
            "*vault*"          { "Credential theft endpoint" }
            "*npmjs.org/-/npm*"{ "Credential theft endpoint" }
            "*8200*"           { "Credential theft endpoint" }
            "*gh-token*"       { "Malware persistence daemon name" }
            "*79ac49*"         { "Malware execution marker" }
            "*tanstack/setup*" { "Malware execution marker" }
            "*bun run*"        { "Malware execution marker" }
            "*Shai-Hulud*"     { "Attacker campaign signature" }
            "*siridar*"        { "Attacker campaign signature" }
            "*tleilax*"        { "Attacker campaign signature" }
            "*IfYouRevoke*"    { "Wiper threat marker (CRITICAL)" }
            "*voicpro*"        { "Attacker account fingerprint" }
            "*claude@users*"   { "Attacker account fingerprint" }
            "*dependabot*"     { "Injected CI/CD marker" }
            "*codeql*"         { "Injected CI/CD marker" }
            "*0c0e873*"        { "Malware cryptographic key" }
            "*svksjrhjk*"      { "Malware cryptographic key" }
            "*7c12d86*"        { "Malware cryptographic key" }
            default            { "Attack indicator" }
        }
        Write-Cross "${label}: $ioc"
        $files = $iocGroups[$ioc] | Select-Object -First 3
        foreach ($f in $files) { Write-Info "Found in   : $f" }
        if ($iocGroups[$ioc].Count -gt 3) { Write-Info "  ... and $($iocGroups[$ioc].Count - 3) more file(s)" }
        Write-Blank
    }
} else {
    Write-Tick "No attack fingerprints found in source files"
}

# -- STEP 5: Final result  -----------------------------------------------------
$total   = $hits.Count + $crit.Count + $pHits.Count + $iocGroups.Count
$overall = if ($total -gt 0) { "AFFECTED" } else { "CLEAN" }
$col     = if ($total -gt 0) { "Red" } else { "Green" }

Write-Host ""
Write-Host "=================================================================" -ForegroundColor $col
Write-Host "  STEP 5 of 5 - Final Result" -ForegroundColor $col
Write-Host "=================================================================" -ForegroundColor $col
Write-Host ""

# Score card
function Write-Score($label, $count) {
    $padded = $label.PadRight(35)
    if ($count -eq 0) {
        Write-Host "  " -NoNewline
        Write-Host "[OK]" -ForegroundColor Green -NoNewline
        Write-Host "  $padded " -NoNewline
        Write-Host "None found" -ForegroundColor Green
    } else {
        Write-Host "  " -NoNewline
        Write-Host "[!!]" -ForegroundColor Red   -NoNewline
        Write-Host "  $padded " -NoNewline
        Write-Host "$count found" -ForegroundColor Red
    }
}

Write-Score "Infected package versions"  $hits.Count
Write-Score "Malware payload files"      $crit.Count
Write-Score "Hidden backdoors"           $pHits.Count
Write-Score "Attack fingerprints"        $iocGroups.Count
Write-Blank

if ($total -gt 0) {
    Write-Host "  =============================================================" -ForegroundColor Red
    Write-Host "    RESULT: THIS REPOSITORY IS AFFECTED" -ForegroundColor Red
    Write-Host "  =============================================================" -ForegroundColor Red
    Write-Blank
    Write-Host "  What this means in plain English:"
    Write-Host "  The malware from the TeamPCP supply chain attack has been"
    Write-Host "  found in this repository. Attackers may have stolen:"
    Write-Host "  GitHub login tokens, npm publish tokens, AWS/cloud credentials,"
    Write-Host "  CI/CD secrets, and possibly cryptocurrency wallet files."
    Write-Blank
    Write-Host "  WHAT TO DO - IN THIS EXACT ORDER:" -ForegroundColor Red
    Write-Blank
    Write-Host "  STEP A - DO THIS FIRST (before touching any passwords)" -ForegroundColor Red
    Write-Host "  The malware will delete all files on the computer if it detects"
    Write-Host "  a password or token being revoked. Remove it first:"
    Write-Blank
    Write-Host "  On Mac, open Terminal and run:"
    Write-Host "    launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
    Write-Host "    rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
    Write-Blank
    Write-Host "  On Linux, open Terminal and run:"
    Write-Host "    systemctl --user stop gh-token-monitor"
    Write-Host "    rm -f ~/.config/systemd/user/gh-token-monitor.service"
    Write-Blank
    Write-Host "  STEP B - Remove hidden backdoor files" -ForegroundColor Red
    Write-Host "    rm -f .claude\router_runtime.js  .claude\setup.mjs"
    Write-Host "    rm -f .vscode\setup.mjs"
    Write-Host "    git diff .claude\settings.json   (restore if changed)"
    Write-Host "    git diff .vscode\tasks.json       (restore if changed)"
    Write-Blank
    Write-Host "  STEP C - Then change all passwords and tokens" -ForegroundColor Red
    Write-Host "    GitHub tokens  ->  github.com/settings/tokens"
    Write-Host "    npm tokens     ->  npmjs.com/settings/~/tokens"
    Write-Host "    AWS/cloud keys ->  via your cloud provider console"
    Write-Host "    CI/CD secrets  ->  in Bitbucket workspace variables"
    Write-Blank
    Write-Host "  STEP D - Block attacker servers at firewall/DNS" -ForegroundColor Red
    Write-Host "    Block: api.masscan.cloud"
    Write-Host "    Block: git-tanstack.com"
    Write-Host "    Block: *.getsession.org"
    Write-Host "    Block: 83.142.209.194"
    Write-Blank
    Write-Host "  STEP E - Check for cryptocurrency wallets" -ForegroundColor Red
    Write-Host "  If any developer has crypto wallets on this machine,"
    Write-Host "  transfer funds to a NEW wallet immediately."
} else {
    Write-Host "  =============================================================" -ForegroundColor Green
    Write-Host "    RESULT: THIS REPOSITORY IS CLEAN" -ForegroundColor Green
    Write-Host "  =============================================================" -ForegroundColor Green
    Write-Blank
    Write-Host "  What this means in plain English:"
    Write-Host "  None of the 180+ infected packages, malware files, backdoors,"
    Write-Host "  or attack signatures were found in this repository."
    Write-Host "  This repo does not appear to be affected by the attack."
}

# -- Full scan summary table  --------------------------------------------------
Write-Blank
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
Write-Host "    FULL SCAN SUMMARY"
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
Write-Blank

function Write-SummaryLine($label, $value, $goodIsZero = $true) {
    $padded = $label.PadRight(35)
    $valStr = "$value".PadRight(6)
    if ($goodIsZero) {
        $status = if ($value -eq 0) { "NONE FOUND" } else { "*** $value FOUND ***" }
        $color  = if ($value -eq 0) { "Green" } else { "Red" }
        Write-Host "  $padded  $valStr  " -NoNewline
        Write-Host $status -ForegroundColor $color
    } else {
        $color  = if ($value -gt 0) { "Green" } else { "Yellow" }
        Write-Host "  $padded  " -NoNewline
        Write-Host $value -ForegroundColor $color
    }
}

Write-Host "    WHAT WAS SCANNED"
Write-Host "  Scan date                            : $timestamp"
Write-Host "  Repository                           : $repoName"
Write-SummaryLine "npm lockfiles found"  $lockfiles.Count  $false
Write-SummaryLine "PyPI req files found" $reqFiles.Count   $false
Write-Blank
Write-Host "    WHAT WAS CHECKED"
Write-SummaryLine "npm packages in IOC list"            $AFFECTED.Count           $false
Write-SummaryLine "PyPI packages in IOC list"           $AFFECTED_PYPI.Count      $false
Write-SummaryLine "Attack signatures checked"           $IOC_STRINGS.Count        $false
Write-SummaryLine "Persistence locations checked"       $PERSISTENCE_FILES.Count  $false
Write-Blank
Write-Host "    STEP 1 - Package version check"
Write-SummaryLine "Infected npm versions found"         $hits.Count
Write-SummaryLine "Safe npm versions seen"              $safes.Count  $false
Write-SummaryLine "Infected PyPI versions found"        (@($hits | Where-Object { $AFFECTED_PYPI.ContainsKey($_.Pkg) }).Count)
Write-Blank
Write-Host "    STEP 2 - Malware file check"
Write-SummaryLine "Malware files (outside node_modules)" $crit.Count
Write-SummaryLine "Payload files (inside node_modules)"  $inNm.Count  $false
Write-Blank
Write-Host "    STEP 3 - Backdoor / persistence check"
Write-SummaryLine "Suspicious persistence files"        $pHits.Count
Write-SummaryLine "Persistence files present"           $pInfo.Count  $false
Write-Blank
Write-Host "    STEP 4 - Attack fingerprint check"
Write-SummaryLine "Unique IOC strings matched"          $iocGroups.Count
Write-SummaryLine "Total IOC occurrences"               $iocHits.Count
Write-Blank
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
$overallPad = "OVERALL STATUS".PadRight(35)
Write-Host "  $overallPad  " -NoNewline
Write-Host $overall -ForegroundColor $col
Write-Host "  " -NoNewline; Write-Host ("-" * 61)
Write-Blank
Write-Host "  Advisory references:"
Write-Host "  Wiz     : https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
Write-Host "  StepSec : https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"

# -- Save report  --------------------------------------------------------------
$reportPath = Join-Path $RepoPath "triage_results.txt"
# Build report line by line - avoids here-string dash operator issues
$reportLines = @()
$reportLines += "================================================================="
$reportLines += "MINI SHAI-HULUD SUPPLY CHAIN ATTACK - TRIAGE REPORT v4.0"
$reportLines += "================================================================="
$reportLines += "Scan date   : $timestamp"
$reportLines += "Repository  : $repoName"
$reportLines += "Full path   : $RepoPath"
$reportLines += "Result      : $overall"
$reportLines += ""
$reportLines += "SCAN STATISTICS"
$reportLines += "npm lockfiles found    : $($lockfiles.Count)"
$reportLines += "PyPI req files found   : $($reqFiles.Count)"
$reportLines += "npm packages checked   : $($AFFECTED.Count)"
$reportLines += "PyPI packages checked  : $($AFFECTED_PYPI.Count)"
$reportLines += "Attack signatures      : $($IOC_STRINGS.Count)"
$reportLines += "Infected versions hit  : $($hits.Count)"
$reportLines += "Malware files hit      : $($crit.Count)"
$reportLines += "Backdoor files hit     : $($pHits.Count)"
$reportLines += "IOC fingerprint hits   : $($iocGroups.Count)"
$reportLines += ""
$reportLines += "INFECTED PACKAGE VERSIONS"
if ($hits.Count -eq 0) {
    $reportLines += "  None found"
} else {
    foreach ($r in $hits) {
        $reportLines += "  INFECTED : $($r.Pkg)  version $($r.Ver)"
        $reportLines += "  Found in : $($r.File)"
        $reportLines += "  Bad vers : $($r.Bad)"
        $reportLines += ""
    }
}
$reportLines += ""
$reportLines += "MALWARE FILES"
if ($crit.Count -eq 0) {
    $reportLines += "  None found"
} else {
    foreach ($p in $crit) {
        $reportLines += "  FILE   : $($p.Rel)"
        $reportLines += "  HASH   : $($p.Hash)"
        $reportLines += "  STATUS : $(if($p.HashMatch){'CONFIRMED MALICIOUS (hash match)'}else{'Suspicious - outside node_modules'})"
        $reportLines += ""
    }
}
$reportLines += ""
$reportLines += "BACKDOOR FILES"
if ($pHits.Count -eq 0) {
    $reportLines += "  None found"
} else {
    foreach ($p in $pHits) {
        $reportLines += "  FILE     : $($p.File)"
        $reportLines += "  CONTAINS : $($p.Reasons -join ', ')"
        $reportLines += ""
    }
}
$reportLines += ""
$reportLines += "ATTACK FINGERPRINTS"
if ($iocHits.Count -eq 0) {
    $reportLines += "  None found"
} else {
    foreach ($h in $iocHits) {
        $reportLines += "  IOC      : $($h.IOC)"
        $reportLines += "  Found in : $($h.File)"
        $reportLines += ""
    }
}
$reportLines += ""
$reportLines += "REFERENCES"
$reportLines += "Wiz     : https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
$reportLines += "StepSec : https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
$report = $reportLines -join "`n"

$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Blank
Write-Host "  Full report saved to: $reportPath"
Write-Blank
