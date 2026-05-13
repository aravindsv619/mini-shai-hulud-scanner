#!/usr/bin/env python3
"""
Mini Shai-Hulud / TeamPCP — Supply Chain Attack Scanner v4.0
=============================================================
USAGE:
  python check.py                      (scan current folder)
  python check.py C:\\path\\to\\repo   (scan specific folder)
  python check.py /path/to/repo > report.txt  (save to file)

No installs needed. Python 3.6+ only.
"""

import os, json, re, sys, hashlib
from datetime import datetime

# =============================================================================
# IOC DATABASE v4.0
# =============================================================================
AFFECTED_PYPI = {
    "guardrails-ai": ["0.10.1"],
    "mistralai":     ["2.4.6"],
}

AFFECTED = {
    "@cap-js/db-service":["2.10.1"],
    "@cap-js/postgres":["2.2.2"],
    "@cap-js/sqlite":["2.2.2"],
    "@tanstack/arktype-adapter":["1.166.12","1.166.15"],
    "@tanstack/eslint-plugin-router":["1.161.9","1.161.12"],
    "@tanstack/eslint-plugin-start":["0.0.4","0.0.7"],
    "@tanstack/history":["1.161.9","1.161.12"],
    "@tanstack/nitro-v2-vite-plugin":["1.154.12","1.154.15"],
    "@tanstack/react-router":["1.169.5","1.169.8"],
    "@tanstack/react-router-devtools":["1.166.16","1.166.19"],
    "@tanstack/react-router-ssr-query":["1.166.15","1.166.18"],
    "@tanstack/react-start":["1.167.68","1.167.71"],
    "@tanstack/react-start-client":["1.166.51","1.166.54"],
    "@tanstack/react-start-rsc":["0.0.47","0.0.50"],
    "@tanstack/react-start-server":["1.166.55","1.166.58"],
    "@tanstack/router-cli":["1.166.46","1.166.49"],
    "@tanstack/router-core":["1.169.5","1.169.8"],
    "@tanstack/router-devtools":["1.166.16","1.166.19"],
    "@tanstack/router-devtools-core":["1.167.6","1.167.9"],
    "@tanstack/router-generator":["1.166.45","1.166.48"],
    "@tanstack/router-plugin":["1.167.38","1.167.41"],
    "@tanstack/router-ssr-query-core":["1.168.3","1.168.6"],
    "@tanstack/router-utils":["1.161.11","1.161.14"],
    "@tanstack/router-vite-plugin":["1.166.53","1.166.56"],
    "@tanstack/solid-router":["1.169.5","1.169.8"],
    "@tanstack/solid-router-devtools":["1.166.16","1.166.19"],
    "@tanstack/solid-router-ssr-query":["1.166.15","1.166.18"],
    "@tanstack/solid-start":["1.167.65","1.167.68"],
    "@tanstack/solid-start-client":["1.166.50","1.166.53"],
    "@tanstack/solid-start-server":["1.166.54","1.166.57"],
    "@tanstack/start-client-core":["1.168.5","1.168.8"],
    "@tanstack/start-fn-stubs":["1.161.9","1.161.12"],
    "@tanstack/start-plugin-core":["1.169.23","1.169.26"],
    "@tanstack/start-server-core":["1.167.33","1.167.36"],
    "@tanstack/start-static-server-functions":["1.166.44","1.166.47"],
    "@tanstack/start-storage-context":["1.166.38","1.166.41"],
    "@tanstack/valibot-adapter":["1.166.12","1.166.15"],
    "@tanstack/virtual-file-routes":["1.161.10","1.161.13"],
    "@tanstack/vue-router":["1.169.5","1.169.8"],
    "@tanstack/vue-router-devtools":["1.166.16","1.166.19"],
    "@tanstack/vue-router-ssr-query":["1.166.15","1.166.18"],
    "@tanstack/vue-start":["1.167.61","1.167.64"],
    "@tanstack/vue-start-client":["1.166.46","1.166.49"],
    "@tanstack/vue-start-server":["1.166.50","1.166.53"],
    "@tanstack/zod-adapter":["1.166.12","1.166.15"],
    "@mistralai/mistralai":["2.2.2","2.2.3","2.2.4"],
    "@mistralai/mistralai-azure":["1.7.1","1.7.2","1.7.3"],
    "@mistralai/mistralai-gcp":["1.7.1","1.7.2","1.7.3"],
    "@opensearch-project/opensearch":["3.5.3","3.6.2","3.7.0","3.8.0"],
    "@squawk/airport-data":["0.7.4","0.7.5","0.7.6","0.7.7","0.7.8"],
    "@squawk/airports":["0.6.2","0.6.3","0.6.4","0.6.5","0.6.6"],
    "@squawk/airspace":["0.8.1","0.8.2","0.8.3","0.8.4","0.8.5"],
    "@squawk/airspace-data":["0.5.3","0.5.4","0.5.5","0.5.6","0.5.7"],
    "@squawk/airway-data":["0.5.4","0.5.5","0.5.6","0.5.7","0.5.8"],
    "@squawk/airways":["0.4.2","0.4.3","0.4.4","0.4.5","0.4.6"],
    "@squawk/fix-data":["0.6.4","0.6.5","0.6.6","0.6.7","0.6.8"],
    "@squawk/fixes":["0.3.2","0.3.3","0.3.4","0.3.5","0.3.6"],
    "@squawk/flight-math":["0.5.4","0.5.5","0.5.6","0.5.7","0.5.8"],
    "@squawk/flightplan":["0.5.2","0.5.3","0.5.4","0.5.5","0.5.6"],
    "@squawk/geo":["0.4.4","0.4.5","0.4.6","0.4.7","0.4.8"],
    "@squawk/icao-registry":["0.5.2","0.5.3","0.5.4","0.5.5","0.5.6"],
    "@squawk/icao-registry-data":["0.8.4","0.8.5","0.8.6","0.8.7","0.8.8"],
    "@squawk/mcp":["0.9.1","0.9.2","0.9.3","0.9.4","0.9.5"],
    "@squawk/navaid-data":["0.6.4","0.6.5","0.6.6","0.6.7","0.6.8"],
    "@squawk/navaids":["0.4.2","0.4.3","0.4.4","0.4.5","0.4.6"],
    "@squawk/notams":["0.3.6","0.3.7","0.3.8","0.3.9","0.3.10"],
    "@squawk/procedure-data":["0.7.3","0.7.4","0.7.5","0.7.6","0.7.7"],
    "@squawk/procedures":["0.5.2","0.5.3","0.5.4","0.5.5","0.5.6"],
    "@squawk/types":["0.8.1","0.8.2","0.8.3","0.8.4","0.8.5"],
    "@squawk/units":["0.4.3","0.4.4","0.4.5","0.4.6","0.4.7"],
    "@squawk/weather":["0.5.6","0.5.7","0.5.8","0.5.9","0.5.10"],
    "@tallyui/components":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/connector-medusa":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/connector-shopify":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/connector-vendure":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/connector-woocommerce":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/core":["0.2.1","0.2.2","0.2.3"],
    "@tallyui/database":["1.0.1","1.0.2","1.0.3"],
    "@tallyui/pos":["0.1.1","0.1.2","0.1.3"],
    "@tallyui/storage-sqlite":["0.2.1","0.2.2","0.2.3"],
    "@tallyui/theme":["0.2.1","0.2.2","0.2.3"],
    "@uipath/access-policy-sdk":["0.3.1"],
    "@uipath/access-policy-tool":["0.3.1"],
    "@uipath/admin-tool":["0.1.1"],
    "@uipath/agent-sdk":["1.0.2"],
    "@uipath/agent-tool":["1.0.1"],
    "@uipath/agent.sdk":["0.0.18"],
    "@uipath/aops-policy-tool":["0.3.1"],
    "@uipath/ap-chat":["1.5.7"],
    "@uipath/api-workflow-tool":["1.0.1"],
    "@uipath/apollo-core":["5.9.2"],
    "@uipath/apollo-react":["4.24.5"],
    "@uipath/apollo-wind":["2.16.2"],
    "@uipath/auth":["1.0.1"],
    "@uipath/case-tool":["1.0.1"],
    "@uipath/cli":["1.0.1"],
    "@uipath/codedagent-tool":["1.0.1"],
    "@uipath/codedagents-tool":["0.1.12"],
    "@uipath/codedapp-tool":["1.0.1"],
    "@uipath/common":["1.0.1"],
    "@uipath/context-grounding-tool":["0.1.1"],
    "@uipath/data-fabric-tool":["1.0.2"],
    "@uipath/docsai-tool":["1.0.1"],
    "@uipath/filesystem":["1.0.1"],
    "@uipath/flow-tool":["1.0.2"],
    "@uipath/functions-tool":["1.0.1"],
    "@uipath/gov-tool":["0.3.1"],
    "@uipath/identity-tool":["0.1.1"],
    "@uipath/insights-sdk":["1.0.1"],
    "@uipath/insights-tool":["1.0.1"],
    "@uipath/integrationservice-sdk":["1.0.2"],
    "@uipath/integrationservice-tool":["1.0.2"],
    "@uipath/llmgw-tool":["1.0.1"],
    "@uipath/maestro-sdk":["1.0.1"],
    "@uipath/maestro-tool":["1.0.1"],
    "@uipath/orchestrator-tool":["1.0.1"],
    "@uipath/packager-tool-apiworkflow":["0.0.19"],
    "@uipath/packager-tool-bpmn":["0.0.9"],
    "@uipath/packager-tool-case":["0.0.9"],
    "@uipath/packager-tool-connector":["0.0.19"],
    "@uipath/packager-tool-flow":["0.0.19"],
    "@uipath/packager-tool-functions":["0.1.1"],
    "@uipath/packager-tool-webapp":["1.0.6"],
    "@uipath/packager-tool-workflowcompiler":["0.0.16"],
    "@uipath/packager-tool-workflowcompiler-browser":["0.0.34"],
    "@uipath/platform-tool":["1.0.1"],
    "@uipath/project-packager":["1.1.16"],
    "@uipath/resource-tool":["1.0.1"],
    "@uipath/resourcecatalog-tool":["0.1.1"],
    "@uipath/resources-tool":["0.1.11"],
    "@uipath/robot":["1.3.4"],
    "@uipath/rpa-legacy-tool":["1.0.1"],
    "@uipath/rpa-tool":["0.9.5"],
    "@uipath/solution-packager":["0.0.35"],
    "@uipath/solution-tool":["1.0.1"],
    "@uipath/solutionpackager-sdk":["1.0.11"],
    "@uipath/solutionpackager-tool-core":["0.0.34"],
    "@uipath/tasks-tool":["1.0.1"],
    "@uipath/telemetry":["0.0.7"],
    "@uipath/test-manager-tool":["1.0.2"],
    "@uipath/tool-workflowcompiler":["0.0.12"],
    "@uipath/traces-tool":["1.0.1"],
    "@uipath/ui-widgets-multi-file-upload":["1.0.1"],
    "@uipath/uipath-python-bridge":["1.0.1"],
    "@uipath/vertical-solutions-tool":["1.0.1"],
    "@uipath/vss":["0.1.6"],
    "@uipath/widget.sdk":["1.2.3"],
    "@beproduct/nestjs-auth":["0.1.2","0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8","0.1.9","0.1.10","0.1.11","0.1.12","0.1.13","0.1.14","0.1.15","0.1.16","0.1.17","0.1.18","0.1.19"],
    "@dirigible-ai/sdk":["0.6.2","0.6.3"],
    "@draftauth/client":["0.2.1","0.2.2"],
    "@draftauth/core":["0.13.1","0.13.2"],
    "@draftlab/auth":["0.24.1","0.24.2"],
    "@draftlab/auth-router":["0.5.1","0.5.2"],
    "@draftlab/db":["0.16.1","0.16.2"],
    "@mesadev/rest":["0.28.3"],
    "@mesadev/saguaro":["0.4.22"],
    "@mesadev/sdk":["0.28.3"],
    "@ml-toolkit-ts/preprocessing":["1.0.2","1.0.3"],
    "@ml-toolkit-ts/xgboost":["1.0.3","1.0.4"],
    "@supersurkhet/cli":["0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7"],
    "@supersurkhet/sdk":["0.0.2","0.0.3","0.0.4","0.0.5","0.0.6","0.0.7"],
    "@taskflow-corp/cli":["0.1.24","0.1.25","0.1.26","0.1.27","0.1.28","0.1.29"],
    "@tolka/cli":["1.0.2","1.0.3","1.0.4","1.0.5","1.0.6"],
    "agentwork-cli":["0.1.4","0.1.5"],
    "cmux-agent-mcp":["0.1.3","0.1.4","0.1.5","0.1.6","0.1.7","0.1.8"],
    "cross-stitch":["1.1.3","1.1.4","1.1.5","1.1.6","1.1.7"],
    "git-branch-selector":["1.3.3","1.3.4","1.3.5","1.3.6","1.3.7"],
    "git-git-git":["1.0.8","1.0.9","1.0.10","1.0.11","1.0.12"],
    "guardrails-ai":["0.10.1"],
    "intercom-client":["7.0.4"],
    "lightning":["2.6.2","2.6.3"],
    "mbt":["1.2.48"],
    "mistralai":["2.4.6"],
    "ml-toolkit-ts":["1.0.4","1.0.5"],
    "nextmove-mcp":["0.1.3","0.1.4","0.1.5","0.1.6","0.1.7"],
    "safe-action":["0.8.3","0.8.4"],
    "ts-dna":["3.0.1","3.0.2","3.0.3","3.0.4","3.0.5"],
    "wot-api":["0.8.1","0.8.2","0.8.3","0.8.4"],
}

PAYLOAD_FILES = ["router_init.js","router_runtime.js","tanstack_runner.js","setup.mjs","opensearch_init.js"]
PAYLOAD_HASHES = {
    "router_init.js":     ["ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
                           "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"],
    "setup.mjs":          ["2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df"],
    "tanstack_runner.js": ["2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"],
}
IOC_STRINGS = [
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    "@tanstack/setup","bun run tanstack_runner.js",
    "0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa",
    "svksjrhjkcejg",
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b",
    "A Mini Shai-Hulud","Shai-Hulud: Here We Go Again",
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
    "siridar-ghola-567","tleilaxu-ornithopter-43",
    "voicproducoes","claude@users.noreply.github.com",
    "chore: update dependencies","dependabot/github_actions/format/",
    "gh-token-monitor","codeql_analysis.yml",
    "api.masscan.cloud","git-tanstack.com","getsession.org",
    "filev2.getsession.org","seed1.getsession.org","83.142.209.194",
    "169.254.169.254","169.254.170.2",
    "registry.npmjs.org/-/npm/v1/tokens",
    "vault.svc.cluster.local","127.0.0.1:8200","opensearch_init.js",
]
PERSISTENCE_FILES = [
    ".claude/settings.json",".claude/router_runtime.js",".claude/setup.mjs",
    ".vscode/tasks.json",".vscode/setup.mjs",
    ".github/workflows/codeql_analysis.yml",
]
SKIP_DIRS = {"node_modules",".git",".svn","dist","build","__pycache__",
             ".next",".nuxt","coverage",".cache","vendor"}

# Colours
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; N="\033[0m"
WH="\033[97m"

def sha256(path):
    h=hashlib.sha256()
    try:
        with open(path,"rb") as f:
            for chunk in iter(lambda:f.read(8192),b""): h.update(chunk)
        return h.hexdigest()
    except: return ""

def walk(root,skip=SKIP_DIRS):
    for dp,dns,fns in os.walk(root):
        dns[:]=[d for d in dns if d not in skip]
        yield dp,dns,fns

def find_lockfiles(root):
    r=[]
    for dp,_,fns in walk(root):
        for f in fns:
            if f in ("package-lock.json","yarn.lock","pnpm-lock.yaml"):
                r.append(os.path.join(dp,f))
    return r

def find_requirements(root):
    r=[]
    for dp,_,fns in walk(root):
        for f in fns:
            if f.startswith("requirements") and f.endswith(".txt"):
                r.append(os.path.join(dp,f))
    return r

def scan_npm_lock(path):
    results=[]
    try: data=json.load(open(path,encoding="utf-8",errors="ignore"))
    except: return results
    pkgs=data.get("packages",data.get("dependencies",{}))
    for raw,info in pkgs.items():
        name=raw.replace("node_modules/","").lstrip("/")
        if name in AFFECTED:
            ver=info.get("version","?")
            status="HIT" if ver in AFFECTED[name] else "SAFE"
            results.append({"file":path,"pkg":name,"ver":ver,"status":status,"bad":AFFECTED[name]})
    return results

def scan_yarn(path):
    results=[]
    try: c=open(path,encoding="utf-8",errors="ignore").read()
    except: return results
    for pkg,bads in AFFECTED.items():
        if pkg not in c: continue
        pat=re.compile(re.escape(pkg)+r'[^\n]*\n(?:[^\n]*\n){0,6}?\s+version\s+"?([^\s"\n]+)"?',re.M)
        seen=set()
        for m in pat.finditer(c):
            ver=m.group(1).strip().strip('"')
            if ver in seen: continue
            seen.add(ver)
            results.append({"file":path,"pkg":pkg,"ver":ver,
                            "status":"HIT" if ver in bads else "SAFE","bad":bads})
    return results

def scan_pnpm(path):
    results=[]
    try: c=open(path,encoding="utf-8",errors="ignore").read()
    except: return results
    for pkg,bads in AFFECTED.items():
        if pkg not in c: continue
        for bv in bads:
            idx=c.find(pkg)
            while idx!=-1:
                if bv in c[idx:idx+300]:
                    results.append({"file":path,"pkg":pkg,"ver":bv,"status":"HIT","bad":bads}); break
                idx=c.find(pkg,idx+1)
    return results

def scan_pypi(path):
    results=[]
    try: lines=open(path,encoding="utf-8",errors="ignore").readlines()
    except: return results
    for line in lines:
        line=line.strip()
        for pkg,bads in AFFECTED_PYPI.items():
            if pkg.lower() in line.lower():
                for bv in bads:
                    if bv in line:
                        results.append({"file":path,"pkg":pkg,"ver":bv,"status":"HIT","bad":bads})
    return results

def scan_payloads(root):
    found=[]
    for dp,_,fns in walk(root,skip={".git",".svn"}):
        for f in fns:
            if f in PAYLOAD_FILES:
                full=os.path.join(dp,f)
                outside="node_modules" not in full
                h=sha256(full)
                known=PAYLOAD_HASHES.get(f,[])
                found.append((outside,full,h,h in known))
    return found

def scan_persistence(root):
    found=[]
    for pf in PERSISTENCE_FILES:
        full=os.path.join(root,pf)
        if os.path.exists(full):
            try:
                c=open(full,encoding="utf-8",errors="ignore").read()
                checks=["router_runtime","tanstack_runner","setup.mjs","gh-token-monitor",
                        "bun run","git-tanstack","getsession","masscan","79ac49ee"]
                reasons=[x for x in checks if x in c]
                if "codeql_analysis.yml" in pf: reasons.append("unexpected codeql workflow")
                found.append((pf,full,bool(reasons),reasons))
            except: found.append((pf,full,False,[]))
    return found

def scan_iocs(root):
    found=[]
    exts={".json",".yaml",".yml",".js",".ts",".mjs",".cjs",".sh",".env",".txt",".lock",".toml",".md"}
    for dp,_,fns in walk(root):
        for fname in fns:
            if not any(fname.endswith(e) for e in exts): continue
            fpath=os.path.join(dp,fname)
            try:
                c=open(fpath,encoding="utf-8",errors="ignore").read()
                for ioc in IOC_STRINGS:
                    if ioc in c: found.append((ioc,fpath))
            except: pass
    return found

# =============================================================================
# PRETTY OUTPUT HELPERS
# =============================================================================

def box(title, color=C):
    w=65
    print(f"\n{color}{B}{'='*w}{N}")
    pad=(w-2-len(title))//2
    print(f"{color}{B}  {'':>{pad}}{title}{N}")
    print(f"{color}{B}{'='*w}{N}")

def section(title):
    print(f"\n{B}{WH}  ── {title} ──{N}")

def tick(msg):  print(f"  {G}✓{N}  {msg}")
def cross(msg): print(f"  {R}✗{N}  {msg}")
def warn(msg):  print(f"  {Y}!{N}  {msg}")
def info(msg):  print(f"     {msg}")
def blank():    print()

# =============================================================================
# MAIN
# =============================================================================
def main():
    root = sys.argv[1] if len(sys.argv)>1 else "."
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        print(f"\n{R}Folder not found: {root}{N}")
        print("Usage:  python check.py [path/to/repo]"); sys.exit(1)

    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    repo = os.path.basename(root)

    # ── Header ────────────────────────────────────────────────────────────────
    box("Mini Shai-Hulud Supply Chain Attack Scanner v4.0")
    print(f"")
    print(f"  {B}{'─'*61}{N}")
    print(f"  {B}  SCAN TARGET{N}")
    print(f"  {B}{'─'*61}{N}")
    print(f"  {B}Repository   :{N} {R}{B}{repo}{N}")
    print(f"  {B}Full path    :{N} {root}")
    print(f"  {B}Scan started :{N} {ts}")
    print(f"  {B}{'─'*61}{N}")
    print(f"")
    print(f"  {B}Checking     :{N} {len(AFFECTED)} npm packages  |  {len(AFFECTED_PYPI)} PyPI packages")
    print(f"               {len(IOC_STRINGS)} attack signatures  |  6 persistence locations")
    print(f"  {B}{'─'*61}{N}")

    all_pkg = []
    lockfiles = find_lockfiles(root)
    req_files = find_requirements(root)

    # ── STEP 1: Lockfiles ─────────────────────────────────────────────────────
    box("STEP 1 of 5 — Checking package files (lockfiles)", C)
    print(f"\n  What this does: Looks inside your project's dependency files")
    print(f"  to see if any of the 180+ infected packages were installed.\n")

    if not lockfiles and not req_files:
        warn("No package files found.")
        info("Looked for: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt")
        info("This repo may not be a JavaScript or Python project.")
        info("If it should have these files, check that they are committed to the repo.")
    else:
        for lf in lockfiles:
            rel=os.path.relpath(lf,root)
            print(f"  {C}Scanning:{N} {rel}")
            if lf.endswith("package-lock.json"): all_pkg.extend(scan_npm_lock(lf))
            elif lf.endswith("yarn.lock"):        all_pkg.extend(scan_yarn(lf))
            elif lf.endswith("pnpm-lock.yaml"):   all_pkg.extend(scan_pnpm(lf))
        for rf in req_files:
            rel=os.path.relpath(rf,root)
            print(f"  {C}Scanning:{N} {rel}")
            all_pkg.extend(scan_pypi(rf))

    hits   = [r for r in all_pkg if r["status"]=="HIT"]
    safes  = [r for r in all_pkg if r["status"]=="SAFE"]

    blank()
    if hits:
        for r in hits:
            cross(f"{B}{R}{r['pkg']}  version {r['ver']}{N}")
            info(f"Found in   : {os.path.relpath(r['file'],root)}")
            info(f"Why bad    : This exact version was infected by attackers")
            info(f"Bad list   : {', '.join(r['bad'])}")
            blank()
    else:
        tick("No infected package versions found in any lockfile")

    if safes:
        warn(f"Found {len(safes)} package(s) from infected namespaces — but on SAFE versions:")
        for r in safes:
            info(f"  {r['pkg']}  version {r['ver']}  ← this version is OK")

    # ── STEP 2: Payload files ─────────────────────────────────────────────────
    box("STEP 2 of 5 — Checking for malware files", C)
    print(f"\n  What this does: Searches for files that the malware drops")
    print(f"  onto the system after it runs. Finding these means the malware")
    print(f"  already executed on this machine or in CI/CD.\n")

    payload_hits = scan_payloads(root)
    crit = [(s,p,h,hm) for s,p,h,hm in payload_hits if s]
    nm   = [(s,p,h,hm) for s,p,h,hm in payload_hits if not s]

    if crit:
        for _,p,h,hm in crit:
            rel=os.path.relpath(p,root)
            cross(f"{B}{R}Malware file found: {os.path.basename(p)}{N}")
            info(f"Location   : {rel}")
            if hm: info(f"Confirmed  : Hash matches known malicious file — DEFINITE INFECTION")
            else:  info(f"Warning    : File found outside node_modules — needs investigation")
            info(f"SHA256     : {h}")
            blank()
    else:
        tick("No malware files found outside node_modules")

    if nm:
        warn(f"{len(nm)} payload file(s) found inside node_modules (may be from infected install):")
        for _,p,h,hm in nm:
            info(f"  {os.path.relpath(p,root)}")

    # ── STEP 3: Persistence files ─────────────────────────────────────────────
    box("STEP 3 of 5 — Checking for hidden backdoors", C)
    print(f"\n  What this does: The malware hides itself in editor config folders")
    print(f"  (.claude, .vscode) so it re-runs every time a developer opens")
    print(f"  their editor. It also injects into GitHub Actions workflows.\n")

    persist = scan_persistence(root)
    p_hits  = [(pf,full,s,r) for pf,full,s,r in persist if s]
    p_info  = [(pf,full,s,r) for pf,full,s,r in persist if not s]

    if p_hits:
        for pf,_,_,reasons in p_hits:
            cross(f"{B}{R}Backdoor found: {pf}{N}")
            for reason in reasons:
                info(f"Contains   : '{reason}'")
            if "codeql_analysis.yml" in pf:
                info(f"Risk       : This workflow exfiltrates ALL repository secrets on every push")
            else:
                info(f"Risk       : Malware re-runs every time this file is loaded by the editor")
            blank()
    else:
        tick("No hidden backdoors found in editor or CI/CD config files")

    if p_info:
        warn(f"{len(p_info)} config file(s) exist — not suspicious but worth checking:")
        for pf,_,_,_ in p_info:
            info(f"  {pf}")

    # ── STEP 4: IOC strings ───────────────────────────────────────────────────
    box("STEP 4 of 5 — Checking for attack fingerprints", C)
    print(f"\n  What this does: Scans all source files for known text strings")
    print(f"  that only appear if the malware ran or if attack infrastructure")
    print(f"  was contacted (C2 server addresses, attacker account names, etc.)\n")

    ioc_hits = scan_iocs(root)

    # Group by IOC for cleaner output
    ioc_groups = {}
    for ioc,path in ioc_hits:
        if ioc not in ioc_groups: ioc_groups[ioc]=[]
        ioc_groups[ioc].append(os.path.relpath(path,root))

    if ioc_groups:
        for ioc,paths in ioc_groups.items():
            # Give plain-English explanation per IOC type
            if "masscan" in ioc or "getsession" in ioc or "git-tanstack" in ioc or "83.142" in ioc:
                label="Attacker server address"
            elif "169.254" in ioc or "vault" in ioc or "npmjs.org/-/npm" in ioc or "8200" in ioc:
                label="Credential theft endpoint"
            elif "gh-token-monitor" in ioc:
                label="Malware persistence daemon name"
            elif "79ac49" in ioc or "tanstack/setup" in ioc or "bun run" in ioc:
                label="Malware execution marker"
            elif "Shai-Hulud" in ioc or "siridar" in ioc or "tleilax" in ioc:
                label="Attacker campaign signature"
            elif "IfYouRevoke" in ioc:
                label="Wiper threat marker (CRITICAL)"
            elif "voicproducoes" in ioc or "claude@users" in ioc:
                label="Attacker account fingerprint"
            elif "dependabot/github_actions/format" in ioc or "codeql" in ioc:
                label="Injected CI/CD marker"
            elif "0c0e873" in ioc or "svksjrhjk" in ioc or "7c12d86" in ioc:
                label="Malware cryptographic key"
            else:
                label="Attack indicator"
            cross(f"{B}{R}{label}:{N} {ioc}")
            for path in paths[:3]:
                info(f"Found in   : {path}")
            if len(paths)>3: info(f"  ... and {len(paths)-3} more file(s)")
            blank()
    else:
        tick("No attack fingerprints found in source files")

    # ── STEP 5: Summary ───────────────────────────────────────────────────────
    total = len(hits)+len(crit)+len(p_hits)+len(ioc_groups)
    overall = "AFFECTED" if total>0 else "CLEAN"
    col = R if total>0 else G

    box("STEP 5 of 5 — Final Result", col)

    blank()
    # Score card
    def score(label, count, good_label="None found", bad_label=None):
        if count==0: tick(f"{label:<35} {G}{good_label}{N}")
        else:        cross(f"{label:<35} {R}{count} found{N}")

    score("Infected package versions",    len(hits))
    score("Malware payload files",        len(crit))
    score("Hidden backdoors",             len(p_hits))
    score("Attack fingerprints",          len(ioc_groups))
    blank()

    if total>0:
        print(f"  {R}{B}{'='*61}{N}")
        print(f"  {R}{B}  RESULT: THIS REPOSITORY IS AFFECTED{N}")
        print(f"  {R}{B}{'='*61}{N}")
        blank()
        print(f"  {B}What this means in plain English:{N}")
        print(f"  The malware from the TeamPCP supply chain attack has been")
        print(f"  found in this repository. Attackers may have stolen:")
        print(f"  GitHub login tokens, npm publish tokens, AWS/cloud credentials,")
        print(f"  CI/CD secrets, and possibly cryptocurrency wallet files.")
        blank()
        print(f"  {R}{B}WHAT TO DO — IN THIS EXACT ORDER:{N}")
        blank()
        print(f"  {R}{B}STEP A — DO THIS FIRST (before touching any passwords){N}")
        print(f"  The malware will delete all files on the computer if it detects")
        print(f"  a password or token being revoked. Remove it first:")
        blank()
        print(f"  On Mac, open Terminal and run:")
        print(f"    launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist")
        print(f"    rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist")
        blank()
        print(f"  On Linux, open Terminal and run:")
        print(f"    systemctl --user stop gh-token-monitor")
        print(f"    rm -f ~/.config/systemd/user/gh-token-monitor.service")
        blank()
        print(f"  {R}{B}STEP B — Remove hidden backdoor files{N}")
        print(f"    rm -f .claude/router_runtime.js  .claude/setup.mjs")
        print(f"    rm -f .vscode/setup.mjs")
        print(f"    git diff .claude/settings.json   (restore if changed)")
        print(f"    git diff .vscode/tasks.json       (restore if changed)")
        blank()
        print(f"  {R}{B}STEP C — Then change all passwords and tokens{N}")
        print(f"    GitHub tokens  →  github.com/settings/tokens")
        print(f"    npm tokens     →  npmjs.com/settings/~/tokens")
        print(f"    AWS/cloud keys →  via your cloud provider console")
        print(f"    CI/CD secrets  →  in Bitbucket workspace variables")
        blank()
        print(f"  {R}{B}STEP D — Block attacker servers at firewall/DNS{N}")
        print(f"    Block: api.masscan.cloud")
        print(f"    Block: git-tanstack.com")
        print(f"    Block: *.getsession.org")
        print(f"    Block: 83.142.209.194")
        blank()
        print(f"  {R}{B}STEP E — Check for cryptocurrency wallets{N}")
        print(f"  If any developer has crypto wallets on this machine,")
        print(f"  transfer funds to a NEW wallet immediately.")
    else:
        print(f"  {G}{B}{'='*61}{N}")
        print(f"  {G}{B}  RESULT: THIS REPOSITORY IS CLEAN{N}")
        print(f"  {G}{B}{'='*61}{N}")
        blank()
        print(f"  {B}What this means in plain English:{N}")
        print(f"  None of the 180+ infected packages, malware files, backdoors,")
        print(f"  or attack signatures were found in this repository.")
        print(f"  This repo does not appear to be affected by the attack.")


    # ── Scan summary numbers ───────────────────────────────────────────────────
    # ── Full scan summary table ──────────────────────────────────────────────
    blank()
    print(f"  {B}{'─'*61}{N}")
    print(f"  {B}  FULL SCAN SUMMARY{N}")
    print(f"  {B}{'─'*61}{N}")
    blank()

    def status_line(label, value, is_count=True, good_is_zero=True):
        """Print a summary line with colour-coded status."""
        label_str = f"  {label:<35}"
        if is_count:
            val_str = str(value)
            if good_is_zero:
                status_str = f"{G}NONE FOUND{N}" if value == 0 else f"{R}*** {value} FOUND ***{N}"
            else:
                status_str = f"{G}{value}{N}" if value > 0 else f"{Y}0{N}"
            print(f"{B}{label_str}{N}  {val_str:<6}  {status_str}")
        else:
            print(f"{B}{label_str}{N}  {value}")

    print(f"  {B}  WHAT WAS SCANNED{N}")
    status_line("Scan date",            ts,              is_count=False)
    status_line("Repository",           repo,            is_count=False)
    status_line("npm lockfiles found",  len(lockfiles),  good_is_zero=False)
    status_line("PyPI req files found", len(req_files),  good_is_zero=False)
    blank()

    print(f"  {B}  WHAT WAS CHECKED{N}")
    status_line("npm packages in IOC list",   len(AFFECTED),    good_is_zero=False)
    status_line("PyPI packages in IOC list",  len(AFFECTED_PYPI), good_is_zero=False)
    status_line("Attack signatures checked",  len(IOC_STRINGS), good_is_zero=False)
    status_line("Persistence locations checked", len(PERSISTENCE_FILES), good_is_zero=False)
    blank()

    print(f"  {B}  STEP 1 — Package version check{N}")
    status_line("Infected npm versions found",  len(hits))
    status_line("Safe npm versions seen",        len(safes),     good_is_zero=False)
    status_line("Infected PyPI versions found",  len([r for r in hits if r['pkg'] in AFFECTED_PYPI]))
    blank()

    print(f"  {B}  STEP 2 — Malware file check{N}")
    status_line("Malware files (outside node_modules)", len(crit))
    status_line("Payload files (inside node_modules)",  len(nm),  good_is_zero=False)
    blank()

    print(f"  {B}  STEP 3 — Backdoor / persistence check{N}")
    status_line("Suspicious persistence files", len(p_hits))
    status_line("Persistence files present",    len(p_info), good_is_zero=False)
    blank()

    print(f"  {B}  STEP 4 — Attack fingerprint check{N}")
    status_line("Unique IOC strings matched",   len(ioc_groups))
    status_line("Total IOC occurrences",        len(ioc_hits))
    blank()

    print(f"  {B}{'─'*61}{N}")
    overall_label = f"  {'OVERALL STATUS':<35}"
    overall_val   = f"{col}{B}{overall}{N}"
    print(f"{B}{overall_label}{N}  {overall_val}")
    print(f"  {B}{'─'*61}{N}")

    blank()
    print(f"  Advisory references:")
    print(f"  Wiz     : https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised")
    print(f"  StepSec : https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem")

    # ── Save report ────────────────────────────────────────────────────────────
    report = os.path.join(root,"triage_results.txt")
    with open(report,"w",encoding="utf-8") as f:
        f.write("="*65+"\n")
        f.write("MINI SHAI-HULUD SUPPLY CHAIN ATTACK — TRIAGE REPORT v4.0\n")
        f.write("="*65+"\n")
        f.write(f"Scan date   : {ts}\n")
        f.write(f"Repository  : {repo}\n")
        f.write(f"Full path   : {root}\n")
        f.write(f"Result      : {overall}\n\n")
        f.write("-"*65+"\n")
        f.write("SCAN STATISTICS\n")
        f.write("-"*65+"\n")
        f.write(f"npm lockfiles found    : {len(lockfiles)}\n")
        f.write(f"PyPI req files found   : {len(req_files)}\n")
        f.write(f"npm packages checked   : {len(AFFECTED)}\n")
        f.write(f"PyPI packages checked  : {len(AFFECTED_PYPI)}\n")
        f.write(f"Attack signatures      : {len(IOC_STRINGS)}\n")
        f.write(f"Infected versions hit  : {len(hits)}\n")
        f.write(f"Malware files hit      : {len(crit)}\n")
        f.write(f"Backdoor files hit     : {len(p_hits)}\n")
        f.write(f"IOC fingerprint hits   : {len(ioc_groups)}\n\n")
        f.write("-"*65+"\n")
        f.write("INFECTED PACKAGE VERSIONS\n")
        f.write("-"*65+"\n")
        if hits:
            for r in hits:
                f.write(f"  INFECTED : {r['pkg']}  version {r['ver']}\n")
                f.write(f"  Found in : {os.path.relpath(r['file'],root)}\n")
                f.write(f"  Bad vers : {', '.join(r['bad'])}\n\n")
        else: f.write("  None found\n\n")
        f.write("-"*65+"\n")
        f.write("MALWARE FILES\n")
        f.write("-"*65+"\n")
        if crit:
            for _,p,h,hm in crit:
                f.write(f"  FILE   : {os.path.relpath(p,root)}\n")
                f.write(f"  HASH   : {h}\n")
                f.write(f"  STATUS : {'CONFIRMED MALICIOUS (hash match)' if hm else 'Suspicious - outside node_modules'}\n\n")
        else: f.write("  None found\n\n")
        f.write("-"*65+"\n")
        f.write("BACKDOOR FILES\n")
        f.write("-"*65+"\n")
        if p_hits:
            for pf,_,_,reasons in p_hits:
                f.write(f"  FILE     : {pf}\n")
                f.write(f"  CONTAINS : {', '.join(reasons)}\n\n")
        else: f.write("  None found\n\n")
        f.write("-"*65+"\n")
        f.write("ATTACK FINGERPRINTS\n")
        f.write("-"*65+"\n")
        if ioc_groups:
            for ioc,paths in ioc_groups.items():
                f.write(f"  IOC    : {ioc}\n")
                for path in paths: f.write(f"  Found  : {path}\n")
                f.write("\n")
        else: f.write("  None found\n\n")
        if total>0:
            f.write("="*65+"\n")
            f.write("ACTION REQUIRED\n")
            f.write("="*65+"\n")
            f.write("A. Remove malware daemon FIRST (before changing any passwords)\n")
            f.write("   Mac  : launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist\n")
            f.write("          rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist\n")
            f.write("   Linux: systemctl --user stop gh-token-monitor\n")
            f.write("          rm -f ~/.config/systemd/user/gh-token-monitor.service\n\n")
            f.write("B. Remove backdoor files:\n")
            f.write("   rm -f .claude/router_runtime.js .claude/setup.mjs\n")
            f.write("   rm -f .vscode/setup.mjs\n")
            f.write("   git diff .claude/settings.json (restore if changed)\n")
            f.write("   git diff .vscode/tasks.json    (restore if changed)\n\n")
            f.write("C. Change all passwords and tokens:\n")
            f.write("   GitHub tokens, npm tokens, AWS/cloud keys, CI/CD secrets\n\n")
            f.write("D. Block at firewall: api.masscan.cloud, git-tanstack.com,\n")
            f.write("   *.getsession.org, 83.142.209.194\n\n")
            f.write("E. Check and move any cryptocurrency wallets on affected machines\n\n")
        f.write("References:\n")
        f.write("  https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised\n")
        f.write("  https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem\n")

    blank()
    print(f"  {B}Full report saved to:{N} triage_results.txt")
    blank()

if __name__=="__main__":
    main()
