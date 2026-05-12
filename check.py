#!/usr/bin/env python3
"""
Mini Shai-Hulud / TeamPCP — Supply Chain Attack Scanner
========================================================
Version  : 1.0
Campaign : TeamPCP npm worm — May 11-12 2026
Author   : SecOps Triage Tool
Checks   : 169 compromised npm packages, payload files, IOC strings

USAGE
-----
1. Run inside your repo (most common):
       cd /path/to/your/repo
       python check.py

2. Point it at a specific folder:
       python check.py /path/to/repo
       python check.py C:\\Users\\you\\projects\\my-repo

3. Scan multiple repos one by one:
       python check.py C:\\repos\\frontend
       python check.py C:\\repos\\backend
       python check.py C:\\repos\\dashboard

4. Save output to a file for evidence:
       python check.py /path/to/repo > results.txt

REQUIREMENTS
------------
- Python 3.6 or higher
- No pip installs needed — uses only built-in Python libraries
- Works on Windows, Mac, Linux

WHAT IT SCANS
-------------
- package-lock.json  (npm)
- yarn.lock          (Yarn)
- pnpm-lock.yaml     (pnpm)
- All .js .ts .json .yaml .mjs files for IOC strings
- Payload filenames: router_init.js, tanstack_runner.js,
                     router_runtime.js, setup.mjs
- Skips node_modules, .git, dist, build folders automatically

OUTPUT
------
- Prints results to terminal with colour coding
- Saves a triage_results.txt report in the scanned folder

REFERENCES
----------
Wiz     : https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
Aikido  : https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
StepSec : https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
"""

import os, json, re, sys
from datetime import datetime

# =============================================================================
# ALL 169 COMPROMISED PACKAGES AND BAD VERSIONS
# Source: Aikido / Wiz / StepSecurity advisories — May 12 2026
# =============================================================================
AFFECTED = {
    "@tanstack/history":["1.161.9","1.161.12"],
    "@tanstack/react-router":["1.169.5","1.169.8"],
    "@tanstack/router-core":["1.169.5","1.169.8"],
    "@tanstack/router-utils":["1.161.11","1.161.14"],
    "@tanstack/router-plugin":["1.167.38","1.167.41"],
    "@tanstack/virtual-file-routes":["1.161.10","1.161.13"],
    "@tanstack/router-generator":["1.166.45","1.166.48"],
    "@tanstack/start-server-core":["1.167.33","1.167.36"],
    "@tanstack/start-client-core":["1.168.5","1.168.8"],
    "@tanstack/start-storage-context":["1.166.38","1.166.41"],
    "@tanstack/start-plugin-core":["1.169.23","1.169.26"],
    "@tanstack/react-start-server":["1.166.55","1.166.58"],
    "@tanstack/react-start-client":["1.166.51","1.166.54"],
    "@tanstack/start-fn-stubs":["1.161.9","1.161.12"],
    "@tanstack/react-start":["1.167.68","1.167.71"],
    "@tanstack/react-start-rsc":["0.0.47","0.0.50"],
    "@tanstack/react-router-devtools":["1.166.16","1.166.19"],
    "@tanstack/router-devtools-core":["1.167.6","1.167.9"],
    "@tanstack/router-devtools":["1.166.16","1.166.19"],
    "@tanstack/router-ssr-query-core":["1.168.3","1.168.6"],
    "@tanstack/react-router-ssr-query":["1.166.15","1.166.18"],
    "@tanstack/router-cli":["1.166.46","1.166.49"],
    "@tanstack/zod-adapter":["1.166.12","1.166.15"],
    "@tanstack/eslint-plugin-router":["1.161.9"],
    "@tanstack/router-vite-plugin":["1.166.53","1.166.56"],
    "@tanstack/nitro-v2-vite-plugin":["1.154.12","1.154.15"],
    "@tanstack/solid-router":["1.169.5","1.169.8"],
    "@tanstack/solid-start":["1.167.65","1.167.68"],
    "@tanstack/solid-start-client":["1.166.50","1.166.53"],
    "@tanstack/solid-start-server":["1.166.54","1.166.57"],
    "@tanstack/solid-router-devtools":["1.166.16","1.166.19"],
    "@tanstack/start-static-server-functions":["1.166.44","1.166.47"],
    "@tanstack/vue-router":["1.169.5","1.169.8"],
    "@tanstack/solid-router-ssr-query":["1.166.15","1.166.18"],
    "@tanstack/valibot-adapter":["1.166.12","1.166.15"],
    "@tanstack/vue-start":["1.167.61","1.167.64"],
    "@tanstack/vue-start-server":["1.166.50","1.166.53"],
    "@tanstack/vue-router-ssr-query":["1.166.15","1.166.18"],
    "@tanstack/vue-router-devtools":["1.166.16","1.166.19"],
    "@tanstack/vue-start-client":["1.166.46","1.166.49"],
    "@tanstack/arktype-adapter":["1.166.12","1.166.15"],
    "@tanstack/eslint-plugin-start":["0.0.4","0.0.7"],
    "@mistralai/mistralai":["2.2.2","2.2.3","2.2.4"],
    "@mistralai/mistralai-gcp":["1.7.1","1.7.2","1.7.3"],
    "@mistralai/mistralai-azure":["1.7.1","1.7.2","1.7.3"],
    "@uipath/apollo-react":["4.24.5"],
    "@uipath/apollo-wind":["2.16.2"],
    "@uipath/cli":["1.0.1"],
    "@uipath/rpa-tool":["0.9.5"],
    "@uipath/apollo-core":["5.9.2"],
    "@uipath/filesystem":["1.0.1"],
    "@uipath/solutionpackager-tool-core":["0.0.34"],
    "@uipath/solution-tool":["1.0.1"],
    "@uipath/maestro-tool":["1.0.1"],
    "@uipath/codedapp-tool":["1.0.1"],
    "@uipath/agent-tool":["1.0.1"],
    "@uipath/orchestrator-tool":["1.0.1"],
    "@uipath/integrationservice-tool":["1.0.2"],
    "@uipath/rpa-legacy-tool":["1.0.1"],
    "@uipath/vertical-solutions-tool":["1.0.1"],
    "@uipath/flow-tool":["1.0.2"],
    "@uipath/codedagent-tool":["1.0.1"],
    "@uipath/common":["1.0.1"],
    "@uipath/resource-tool":["1.0.1"],
    "@uipath/auth":["1.0.1"],
    "@uipath/docsai-tool":["1.0.1"],
    "@uipath/case-tool":["1.0.1"],
    "@uipath/api-workflow-tool":["1.0.1"],
    "@uipath/test-manager-tool":["1.0.2"],
    "@uipath/robot":["1.3.4"],
    "@uipath/traces-tool":["1.0.1"],
    "@uipath/agent-sdk":["1.0.2"],
    "@uipath/integrationservice-sdk":["1.0.2"],
    "@uipath/maestro-sdk":["1.0.1"],
    "@uipath/data-fabric-tool":["1.0.2"],
    "@uipath/tasks-tool":["1.0.1"],
    "@uipath/insights-tool":["1.0.1"],
    "@uipath/insights-sdk":["1.0.1"],
    "@uipath/uipath-python-bridge":["1.0.1"],
    "@uipath/ap-chat":["1.5.7"],
    "@uipath/project-packager":["1.1.16"],
    "@uipath/packager-tool-case":["0.0.9"],
    "@uipath/packager-tool-workflowcompiler-browser":["0.0.34"],
    "@uipath/packager-tool-connector":["0.0.19"],
    "@uipath/packager-tool-workflowcompiler":["0.0.16"],
    "@uipath/packager-tool-webapp":["1.0.6"],
    "@uipath/packager-tool-apiworkflow":["0.0.19"],
    "@uipath/packager-tool-functions":["0.1.1"],
    "@uipath/widget.sdk":["1.2.3"],
    "@uipath/resources-tool":["0.1.11"],
    "@uipath/agent.sdk":["0.0.18"],
    "@uipath/codedagents-tool":["0.1.12"],
    "@uipath/aops-policy-tool":["0.3.1"],
    "@uipath/solution-packager":["0.0.35"],
    "@uipath/packager-tool-bpmn":["0.0.9"],
    "@uipath/tool-workflowcompiler":["0.0.12"],
    "@uipath/vss":["0.1.6"],
    "@uipath/solutionpackager-sdk":["1.0.11"],
    "@uipath/ui-widgets-multi-file-upload":["1.0.1"],
    "@uipath/access-policy-tool":["0.3.1"],
    "@uipath/context-grounding-tool":["0.1.1"],
    "@uipath/gov-tool":["0.3.1"],
    "@uipath/admin-tool":["0.1.1"],
    "@uipath/identity-tool":["0.1.1"],
    "@uipath/llmgw-tool":["1.0.1"],
    "@uipath/resourcecatalog-tool":["0.1.1"],
    "@uipath/functions-tool":["1.0.1"],
    "@uipath/access-policy-sdk":["0.3.1"],
    "@uipath/platform-tool":["1.0.1"],
    "@uipath/telemetry":["0.0.7"],
    "@squawk/types":["0.8.2","0.8.3","0.8.4"],
    "@squawk/mcp":["0.9.1","0.9.2","0.9.3","0.9.4"],
    "@squawk/weather":["0.5.6","0.5.7","0.5.8","0.5.9"],
    "@squawk/airspace":["0.8.1","0.8.2","0.8.3","0.8.4"],
    "@squawk/icao-registry-data":["0.8.4","0.8.5","0.8.6","0.8.7"],
    "@squawk/flightplan":["0.5.2","0.5.3","0.5.4","0.5.5"],
    "@squawk/airports":["0.6.2","0.6.3","0.6.4","0.6.5"],
    "@squawk/geo":["0.4.4","0.4.5","0.4.6","0.4.7"],
    "@squawk/procedure-data":["0.7.3","0.7.4","0.7.5","0.7.6"],
    "@squawk/navaid-data":["0.6.4","0.6.5","0.6.6","0.6.7"],
    "@squawk/fix-data":["0.6.4","0.6.5","0.6.6","0.6.7"],
    "@squawk/navaids":["0.4.2","0.4.3","0.4.4","0.4.5"],
    "@squawk/fixes":["0.3.2","0.3.3","0.3.4","0.3.5"],
    "@squawk/airport-data":["0.7.4","0.7.5","0.7.6","0.7.7"],
    "@squawk/airway-data":["0.5.4","0.5.5","0.5.6","0.5.7"],
    "@squawk/units":["0.4.3","0.4.4","0.4.5","0.4.6"],
    "@squawk/procedures":["0.5.2","0.5.3","0.5.4","0.5.5"],
    "@squawk/airways":["0.4.2","0.4.3","0.4.4","0.4.5"],
    "@squawk/icao-registry":["0.5.2","0.5.3","0.5.4","0.5.5"],
    "@squawk/notams":["0.3.6","0.3.7","0.3.8","0.3.9"],
    "@squawk/flight-math":["0.5.4","0.5.5","0.5.6","0.5.7"],
    "@squawk/airspace-data":["0.5.3","0.5.4","0.5.5","0.5.6"],
    "@tallyui/connector-medusa":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/theme":["0.2.1","0.2.2","0.2.3"],
    "@tallyui/storage-sqlite":["0.2.1","0.2.2","0.2.3"],
    "@tallyui/connector-vendure":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/core":["0.2.1","0.2.2","0.2.3"],
    "@tallyui/connector-woocommerce":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/components":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/pos":["0.1.1","0.1.2","0.1.3"],
    "@tallyui/database":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/connector-shopify":["1.0.1","1.0.2","1.0.3"],
    "@draftlab/auth":["0.24.1","0.24.2"],
    "@draftlab/db":["0.16.1"],
    "@draftlab/auth-router":["0.5.1","0.5.2"],
    "@draftauth/core":["0.13.1","0.13.2"],
    "@draftauth/client":["0.2.1","0.2.2"],
    "@taskflow-corp/cli":["0.1.24","0.1.25","0.1.26","0.1.27","0.1.28","0.1.29"],
    "@mesadev/sdk":["0.28.3"],
    "@mesadev/rest":["0.28.3"],
    "@mesadev/saguaro":["0.4.22"],
    "@ml-toolkit-ts/xgboost":["1.0.3","1.0.4"],
    "@ml-toolkit-ts/preprocessing":["1.0.2","1.0.3"],
    "@dirigible-ai/sdk":["0.6.2","0.6.3"],
    "@supersurkhet/cli":["0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7"],
    "@supersurkhet/sdk":["0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7"],
    "@tolka/cli":["1.0.2","1.0.3","1.0.4","1.0.5","1.0.6"],
    "@beproduct/nestjs-auth":["0.1.2","0.1.3","0.1.4","0.1.5","0.1.6","0.1.7",
                              "0.1.8","0.1.9","0.1.10","0.1.11","0.1.12","0.1.13",
                              "0.1.14","0.1.15","0.1.16","0.1.17","0.1.18","0.1.19"],
    "safe-action":["0.8.3","0.8.4"],
    "ts-dna":["3.0.1","3.0.2","3.0.3","3.0.4"],
    "cross-stitch":["1.1.3","1.1.4","1.1.5","1.1.6"],
    "cmux-agent-mcp":["0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8"],
    "agentwork-cli":["0.1.4","0.1.5"],
    "git-branch-selector":["1.3.3","1.3.4","1.3.5","1.3.6","1.3.7"],
    "wot-api":["0.8.1","0.8.2","0.8.3","0.8.4"],
    "git-git-git":["1.0.8","1.0.9","1.0.10","1.0.11","1.0.12"],
    "nextmove-mcp":["0.1.3","0.1.4","0.1.5","0.1.6","0.1.7"],
    "ml-toolkit-ts":["1.0.4","1.0.5"],
}

# Malicious files that should never appear outside node_modules
PAYLOAD_FILES = ["router_init.js","router_runtime.js","tanstack_runner.js","setup.mjs"]

# IOC strings — if found in any file, malware is present or ran
IOC_STRINGS = [
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "@tanstack/setup",
    "git-tanstack.com",
    "getsession.org",
    "A Mini Shai-Hulud",
    "gh-token-monitor",
    "83.142.209.194",
]

# Folders to skip entirely
SKIP_DIRS = {
    "node_modules",".git",".svn","dist","build",
    "__pycache__",".next",".nuxt","coverage",".cache","vendor"
}

# Terminal colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
NC     = "\033[0m"

# =============================================================================
# SCANNERS
# =============================================================================

def find_lockfiles(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f in ("package-lock.json","yarn.lock","pnpm-lock.yaml"):
                found.append(os.path.join(dirpath, f))
    return found


def scan_package_lock(path):
    results = []
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
    except Exception as e:
        print(f"  {YELLOW}Could not parse {path}: {e}{NC}")
        return results
    pkgs = data.get("packages", data.get("dependencies", {}))
    for raw, info in pkgs.items():
        name = raw.replace("node_modules/","").lstrip("/")
        if name in AFFECTED:
            ver    = info.get("version","unknown")
            status = "CONFIRMED HIT" if ver in AFFECTED[name] else "SAFE VERSION"
            results.append({"file":path,"package":name,"version":ver,
                            "status":status,"bad_versions":AFFECTED[name]})
    return results


def scan_yarn_lock(path):
    results = []
    try:
        content = open(path, encoding="utf-8", errors="ignore").read()
    except Exception as e:
        print(f"  {YELLOW}Could not read {path}: {e}{NC}")
        return results
    for pkg, bad_vers in AFFECTED.items():
        if pkg not in content:
            continue
        pat = re.compile(
            re.escape(pkg)+r'[^\n]*\n(?:[^\n]*\n){0,6}?\s+version\s+"?([^\s"\n]+)"?',
            re.MULTILINE)
        seen = set()
        for m in pat.finditer(content):
            ver = m.group(1).strip().strip('"')
            if ver in seen: continue
            seen.add(ver)
            status = "CONFIRMED HIT" if ver in bad_vers else "SAFE VERSION"
            results.append({"file":path,"package":pkg,"version":ver,
                            "status":status,"bad_versions":bad_vers})
    return results


def scan_pnpm_lock(path):
    results = []
    try:
        content = open(path, encoding="utf-8", errors="ignore").read()
    except Exception as e:
        print(f"  {YELLOW}Could not read {path}: {e}{NC}")
        return results
    for pkg, bad_vers in AFFECTED.items():
        if pkg not in content: continue
        for bv in bad_vers:
            idx = content.find(pkg)
            while idx != -1:
                if bv in content[idx:idx+300]:
                    results.append({"file":path,"package":pkg,"version":bv,
                                    "status":"CONFIRMED HIT","bad_versions":bad_vers})
                    break
                idx = content.find(pkg, idx+1)
    return results


def scan_payload_files(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git",".svn"}]
        for f in filenames:
            if f in PAYLOAD_FILES:
                full    = os.path.join(dirpath, f)
                outside = "node_modules" not in full
                found.append((outside, full))
    return found


def scan_ioc_strings(root):
    found = []
    exts  = {".json",".yaml",".yml",".js",".ts",".mjs",".cjs",
             ".sh",".env",".txt",".lock",".toml",".md"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if not any(fname.endswith(e) for e in exts): continue
            fpath = os.path.join(dirpath, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
                for ioc in IOC_STRINGS:
                    if ioc in content:
                        found.append((ioc, fpath))
            except Exception:
                pass
    return found

# =============================================================================
# MAIN
# =============================================================================

def main():
    # ------------------------------------------------------------------
    # Determine what to scan
    # ------------------------------------------------------------------
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    root = os.path.abspath(root)

    if not os.path.isdir(root):
        print(f"\n{RED}Error: '{root}' is not a folder.{NC}")
        print("Usage examples:")
        print("  python check.py                          # scan current folder")
        print("  python check.py /path/to/repo            # scan specific folder")
        print("  python check.py C:\\Users\\you\\my-repo  # Windows path")
        sys.exit(1)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{BOLD}{CYAN}{'='*62}{NC}")
    print(f"{BOLD}{CYAN}  Mini Shai-Hulud / TeamPCP — Supply Chain Scanner{NC}")
    print(f"{BOLD}{CYAN}  Date   : {ts}{NC}")
    print(f"{BOLD}{CYAN}  Folder : {root}{NC}")
    print(f"{BOLD}{CYAN}  Checks : {len(AFFECTED)} packages | payload files | IOC strings{NC}")
    print(f"{BOLD}{CYAN}{'='*62}{NC}\n")

    all_results = []

    # ------------------------------------------------------------------
    # 1. Lockfiles
    # ------------------------------------------------------------------
    print(f"{BOLD}[1/3] Finding and scanning lockfiles...{NC}")
    lockfiles = find_lockfiles(root)

    if not lockfiles:
        print(f"  {YELLOW}No lockfiles found.{NC}")
        print(f"  {YELLOW}Looked for: package-lock.json, yarn.lock, pnpm-lock.yaml{NC}")
        print(f"  {YELLOW}This repo may not be a JS/TS project or lockfile is not committed.{NC}")
    else:
        for lf in lockfiles:
            rel = os.path.relpath(lf, root)
            print(f"  Scanning: {rel}")
            if   lf.endswith("package-lock.json"): all_results.extend(scan_package_lock(lf))
            elif lf.endswith("yarn.lock"):          all_results.extend(scan_yarn_lock(lf))
            elif lf.endswith("pnpm-lock.yaml"):     all_results.extend(scan_pnpm_lock(lf))

    confirmed = [r for r in all_results if r["status"] == "CONFIRMED HIT"]
    safe_vers = [r for r in all_results if r["status"] == "SAFE VERSION"]

    # ------------------------------------------------------------------
    # 2. Payload files
    # ------------------------------------------------------------------
    print(f"\n{BOLD}[2/3] Scanning for malicious payload files...{NC}")
    payload_hits     = scan_payload_files(root)
    critical_payload = [(s,p) for s,p in payload_hits if s]
    info_payload     = [(s,p) for s,p in payload_hits if not s]

    for _,p in critical_payload:
        print(f"  {RED}[CRITICAL] Payload file outside node_modules: {os.path.relpath(p,root)}{NC}")
    for _,p in info_payload:
        print(f"  {YELLOW}[INFO] Payload file in node_modules: {os.path.relpath(p,root)}{NC}")
    if not payload_hits:
        print(f"  {GREEN}No payload files found.{NC}")

    # ------------------------------------------------------------------
    # 3. IOC strings
    # ------------------------------------------------------------------
    print(f"\n{BOLD}[3/3] Scanning files for IOC strings...{NC}")
    ioc_hits = scan_ioc_strings(root)
    for ioc,path in ioc_hits:
        print(f"  {RED}[HIT] '{ioc}' found in: {os.path.relpath(path,root)}{NC}")
    if not ioc_hits:
        print(f"  {GREEN}No IOC strings found.{NC}")

    # ------------------------------------------------------------------
    # Print results
    # ------------------------------------------------------------------
    total_hits = len(confirmed) + len(critical_payload) + len(ioc_hits)
    overall    = "AFFECTED" if total_hits > 0 else "CLEAN"
    col        = RED if total_hits > 0 else GREEN

    print(f"\n{BOLD}{CYAN}{'='*62}{NC}")
    print(f"{BOLD}  RESULTS{NC}")
    print(f"{BOLD}{CYAN}{'='*62}{NC}\n")

    if confirmed:
        print(f"{RED}{BOLD}  *** {len(confirmed)} CONFIRMED HIT(S) — affected package versions found ***{NC}\n")
        for r in confirmed:
            rel = os.path.relpath(r["file"], root)
            print(f"  {RED}[HIT]{NC}  {BOLD}{r['package']}@{r['version']}{NC}")
            print(f"         File         : {rel}")
            print(f"         All bad vers : {', '.join(r['bad_versions'])}\n")
    else:
        print(f"  {GREEN}{BOLD}Lockfile check — CLEAN. No affected versions found.{NC}\n")

    if safe_vers:
        print(f"  {YELLOW}Same packages present but on SAFE versions (not affected):{NC}")
        for r in safe_vers:
            rel = os.path.relpath(r["file"], root)
            print(f"  {YELLOW}[OK]{NC}  {r['package']}@{r['version']}  ({rel})")
        print()

    if critical_payload:
        print(f"{RED}{BOLD}  *** PAYLOAD FILES found outside node_modules ***{NC}")
        for _,p in critical_payload:
            print(f"  {RED}[CRITICAL]{NC} {os.path.relpath(p,root)}")
        print()

    if ioc_hits:
        print(f"{RED}{BOLD}  *** IOC STRINGS found in source files ***{NC}")
        for ioc,p in ioc_hits:
            print(f"  {RED}[HIT]{NC} '{ioc}' in {os.path.relpath(p,root)}")
        print()

    # ------------------------------------------------------------------
    # Summary box
    # ------------------------------------------------------------------
    print(f"\n{BOLD}{'='*62}{NC}")
    print(f"{BOLD}  SUMMARY{NC}")
    print(f"{'='*62}")
    print(f"  Scan date             : {ts}")
    print(f"  Folder scanned        : {root}")
    print(f"  Lockfiles found       : {len(lockfiles)}")
    print(f"  IOC packages checked  : {len(AFFECTED)}")
    print(f"  Confirmed pkg hits    : {RED if confirmed else GREEN}{len(confirmed)}{NC}")
    print(f"  Safe versions seen    : {len(safe_vers)}")
    print(f"  Payload files (crit)  : {RED if critical_payload else GREEN}{len(critical_payload)}{NC}")
    print(f"  IOC string hits       : {RED if ioc_hits else GREEN}{len(ioc_hits)}{NC}")
    print(f"  Overall status        : {col}{BOLD}{overall}{NC}")

    if total_hits > 0:
        print(f"""
{RED}{BOLD}  IMMEDIATE ACTIONS — DO IN THIS ORDER:{NC}
{RED}  1. Remove gh-token-monitor daemon FIRST (before revoking tokens)
     macOS: launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
            rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
     Linux: systemctl --user stop gh-token-monitor
            rm -f ~/.config/systemd/user/gh-token-monitor.service
  2. Delete payload files from .claude/ and .vscode/ directories
  3. Rotate: GitHub tokens, npm tokens, AWS/GCP creds, CI/CD secrets
  4. Block:  git-tanstack.com | *.getsession.org | 83.142.209.194{NC}""")
    else:
        print(f"\n{GREEN}{BOLD}  No action required. Safe to report as unaffected.{NC}")

    print(f"\n  Ref: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised\n")

    # ------------------------------------------------------------------
    # Save report to file
    # ------------------------------------------------------------------
    report_path = os.path.join(root, "triage_results.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("Mini Shai-Hulud / TeamPCP — Triage Report\n")
        f.write("="*62 + "\n")
        f.write(f"Date              : {ts}\n")
        f.write(f"Folder scanned    : {root}\n")
        f.write(f"Overall status    : {overall}\n\n")
        f.write(f"Lockfiles found   : {len(lockfiles)}\n")
        f.write(f"Packages checked  : {len(AFFECTED)}\n")
        f.write(f"Confirmed hits    : {len(confirmed)}\n")
        f.write(f"Safe versions     : {len(safe_vers)}\n")
        f.write(f"Payload files     : {len(critical_payload)}\n")
        f.write(f"IOC string hits   : {len(ioc_hits)}\n\n")
        if confirmed:
            f.write("CONFIRMED PACKAGE HITS:\n")
            for r in confirmed:
                f.write(f"  {r['package']}@{r['version']} — {os.path.relpath(r['file'],root)}\n")
        else:
            f.write("CONFIRMED PACKAGE HITS: None\n")
        if safe_vers:
            f.write("\nSAFE VERSIONS (package present, not bad version):\n")
            for r in safe_vers:
                f.write(f"  {r['package']}@{r['version']} — {os.path.relpath(r['file'],root)}\n")
        if critical_payload:
            f.write("\nPAYLOAD FILES FOUND:\n")
            for _,p in critical_payload:
                f.write(f"  {os.path.relpath(p,root)}\n")
        if ioc_hits:
            f.write("\nIOC STRINGS FOUND:\n")
            for ioc,p in ioc_hits:
                f.write(f"  '{ioc}' in {os.path.relpath(p,root)}\n")
        f.write(f"\nRef: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised\n")

    print(f"  Report saved to: triage_results.txt\n")

if __name__ == "__main__":
    main()
