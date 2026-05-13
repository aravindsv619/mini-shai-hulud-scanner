# Mini Shai-Hulud Supply Chain Attack Scanner

A defensive security tool to check if a code repository is affected by the **TeamPCP / Mini Shai-Hulud** npm supply chain attack (May 11–12 2026).

Output is written in plain English so anyone — technical or non-technical — can understand the results immediately.

> **This tool is read-only. It never deletes, modifies, or connects to anything. It only reads files and reports what it finds.**

---

## What is This Attack?

In May 2026, a threat actor group called **TeamPCP** injected malware into **180 packages** across npm and PyPI including `@tanstack`, `@uipath`, `@mistralai`, `@squawk`, `@cap-js`, `@opensearch-project` and many others.

If a developer ran `npm install` while one of the infected versions was in their project, the malware:

- Stole GitHub tokens, npm tokens, AWS/cloud credentials, CI/CD secrets
- Stole cryptocurrency wallet files (`~/.bitcoin/wallet.dat`, `~/.ethereum/keystore/`)
- Installed a hidden background daemon (`gh-token-monitor`) that **deletes all files on the machine** if it detects a token being revoked
- Hid itself in `.claude/` and `.vscode/` config folders so it re-runs every time the developer opens their editor
- Injected a malicious GitHub Actions workflow (`codeql_analysis.yml`) to steal all repository secrets on every push
- Spread itself to other npm packages the developer had publish access to

---

## What This Tool Does NOT Do

| Action | Does it happen? |
|---|---|
| Read files to check for threats | ✓ Yes — read only |
| Save a `triage_results.txt` report | ✓ Yes — one new file |
| Delete any files | ✗ Never |
| Modify any files | ✗ Never |
| Connect to the internet | ✗ Never |
| Install anything | ✗ Never |
| Run any other programs | ✗ Never |
| Change any system settings | ✗ Never |

---

## What This Tool Checks

### Step 1 — Package version check
Scans `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and `requirements*.txt` for all **180 infected packages** across **17 namespaces**:

| Namespace | Packages checked |
|---|---|
| `@tanstack` | 42 |
| `@uipath` | 66 |
| `@squawk` | 22 |
| `@tallyui` | 10 |
| `@cap-js` | 3 |
| `@mistralai` | 3 |
| `@draftlab` | 3 |
| `@mesadev` | 3 |
| `@draftauth` | 2 |
| `@ml-toolkit-ts` | 2 |
| `@supersurkhet` | 2 |
| `@beproduct` | 1 |
| `@dirigible-ai` | 1 |
| `@opensearch-project` | 1 |
| `@taskflow-corp` | 1 |
| `@tolka` | 1 |
| Unscoped (`safe-action`, `ts-dna`, `mbt`, `lightning`, `intercom-client` etc.) | 15 |
| PyPI (`guardrails-ai`, `mistralai`) | 2 |
| **Total** | **180** |

### Step 2 — Malware file check
Looks for payload files dropped by the malware, with SHA256 hash verification:

| File | SHA256 |
|---|---|
| `router_init.js` | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` |
| `router_init.js` (variant 2) | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` |
| `setup.mjs` | `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df` |
| `tanstack_runner.js` | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` |
| `router_runtime.js` | detected by filename |
| `opensearch_init.js` | detected by filename |

### Step 3 — Backdoor / persistence check
Checks IDE and CI/CD config files used by the malware to re-run itself:

| File | Risk |
|---|---|
| `.claude/settings.json` | SessionStart hook — re-runs malware every Claude Code open |
| `.claude/router_runtime.js` | Malware payload in editor config |
| `.claude/setup.mjs` | Malware setup script in editor config |
| `.vscode/tasks.json` | folderOpen task — re-runs malware every VS Code open |
| `.vscode/setup.mjs` | Malware setup script in editor config |
| `.github/workflows/codeql_analysis.yml` | Exfiltrates ALL repository secrets on every push |

### Step 4 — Attack fingerprint check
Scans all source files for **32 known IOC strings**:

**C2 network infrastructure:**
- `api.masscan.cloud` — attacker C2 server
- `git-tanstack.com` — attacker C2 domain
- `filev2.getsession.org` — attacker file server
- `seed1.getsession.org` — Session messenger C2 node
- `83.142.209.194` — attacker C2 IP address

**Credential theft endpoints:**
- `169.254.169.254` — AWS EC2 metadata (IAM credential theft)
- `169.254.170.2` — ECS/Fargate metadata credential theft
- `registry.npmjs.org/-/npm/v1/tokens` — npm token theft
- `vault.svc.cluster.local` / `127.0.0.1:8200` — HashiCorp Vault theft

**Campaign signatures:**
- `79ac49eedf774dd4b0cfa308722bc463cfe5885c` — malicious orphan commit hash
- `A Mini Shai-Hulud` — campaign marker
- `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` — wiper threat token description
- `rm -rf ~/` — destructive wiper command
- `gh-token-monitor` — persistence daemon name
- `voicproducoes` — attacker GitHub account
- `claude@users.noreply.github.com` — dead-drop commit author
- `chore: update dependencies` — dead-drop commit message disguise
- `dependabot/github_actions/format/` — dead-drop branch pattern
- `0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa` — campaign cipher key
- `svksjrhjkcejg` — campaign PBKDF2 salt
- `siridar-ghola-567` / `tleilaxu-ornithopter-43` — worm marker repository names

---

## Files in This Repo

| File | Description |
|---|---|
| `check.py` | Python scanner — Mac, Linux, Windows |
| `check.ps1` | PowerShell scanner — Windows only, no Python needed |
| `README.md` | This file |

---

## Requirements

**check.py:**
- Python 3.6 or higher
- No pip installs needed — standard library only
- Works on Windows, Mac, Linux

**check.ps1:**
- PowerShell (built into every Windows machine)
- No Python needed
- Use if Python is blocked by IT policy

---

## Usage

**Python — scan current folder** (run from inside your repo):
```bash
python check.py
```

**Python — scan a specific folder:**
```bash
# Mac / Linux
python3 check.py /path/to/your/repo

# Windows
python check.py C:\Users\you\Downloads\my-repo
```

**Python — scan multiple repos:**
```bash
python check.py C:\repos\frontend
python check.py C:\repos\backend
python check.py C:\repos\dashboard
```

**Python — save output to a file:**
```bash
python check.py /path/to/repo > results.txt
```

**PowerShell — Windows (no Python needed):**
```powershell
powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\Users\you\Downloads\my-repo"
```

---

## Understanding the Output

The tool runs 5 checks and shows a full summary table at the end.

### Clean result:
```
=================================================================
  RESULT: THIS REPOSITORY IS CLEAN
=================================================================

  What this means in plain English:
  None of the 180 infected packages, malware files, backdoors,
  or attack signatures were found in this repository.

  FULL SCAN SUMMARY
  -----------------------------------------------------------------
  Repository                          :  my-repo
  npm lockfiles found                 :  1
  npm packages in IOC list            :  178
  PyPI packages in IOC list           :  2
  Attack signatures checked           :  32

  STEP 1 - Package version check
  Infected npm versions found         :  0      NONE FOUND
  Safe npm versions seen              :  0

  STEP 2 - Malware file check
  Malware files (outside node_modules):  0      NONE FOUND

  STEP 3 - Backdoor / persistence check
  Suspicious persistence files        :  0      NONE FOUND

  STEP 4 - Attack fingerprint check
  Unique IOC strings matched          :  0      NONE FOUND

  OVERALL STATUS                      :  CLEAN
  -----------------------------------------------------------------
```

### Affected result:
```
  ✗  @tanstack/react-router  version 1.169.5
     Found in   : package-lock.json
     Why bad    : This exact version was infected by attackers
     Bad list   : 1.169.5, 1.169.8

=================================================================
  RESULT: THIS REPOSITORY IS AFFECTED
=================================================================

  WHAT TO DO — IN THIS EXACT ORDER:
  STEP A — Remove malware daemon FIRST (before touching any passwords)
  STEP B — Remove hidden backdoor files
  STEP C — Change all passwords and tokens
  STEP D — Block attacker servers at firewall/DNS
  STEP E — Check for cryptocurrency wallets
```

A full report is automatically saved to `triage_results.txt` in the scanned folder.

---

## If You Find a Hit — Critical Warning

> ⚠️ **DO NOT revoke GitHub tokens or change any passwords until you have removed the malware daemon first.**
>
> The malware runs `rm -rf ~/` which deletes all files in the home folder when it detects a token being revoked. Remove the daemon first, then rotate credentials.

**Step A — Remove the daemon on Mac:**
```bash
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm -f ~/.local/bin/gh-token-monitor.sh
rm -rf ~/.config/gh-token-monitor
```

**Step A — Remove the daemon on Linux:**
```bash
systemctl --user stop gh-token-monitor
systemctl --user disable gh-token-monitor
rm -f ~/.config/systemd/user/gh-token-monitor.service
```

**Step A — Remove the daemon on Windows:**
```powershell
Get-ScheduledTask | Where-Object {$_.TaskName -like "*gh-token*"} | Unregister-ScheduledTask -Confirm:$false
```

**Step B — Remove backdoor files:**
```bash
rm -f .claude/router_runtime.js .claude/setup.mjs
git diff .claude/settings.json    # restore if modified
rm -f .vscode/setup.mjs
git diff .vscode/tasks.json       # restore if modified
```

**Step C — Rotate all credentials:**
```
GitHub tokens  →  github.com/settings/tokens
npm tokens     →  npmjs.com/settings/~/tokens
AWS/cloud keys →  via your cloud provider console
CI/CD secrets  →  in your pipeline workspace variables
```

**Step D — Block attacker infrastructure at firewall/DNS:**
```
api.masscan.cloud
git-tanstack.com
*.getsession.org
83.142.209.194
```

**Step E — Check cryptocurrency wallets:**
If any developer has crypto wallets on the affected machine, transfer funds to a new wallet immediately.

---

## Advisory References

- **Wiz:** https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- **Aikido:** https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- **StepSecurity:** https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem

---

## Disclaimer

For **defensive security purposes only.**
Run only against repositories you own or have explicit permission to scan.
This tool only reads files — it does not modify, delete, or connect to anything.

---

## License

MIT — free to use, copy, modify, and share for defensive security purposes.
