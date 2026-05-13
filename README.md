# Mini Shai-Hulud Supply Chain Attack Scanner

Defensive security tool to check if a repository is affected by the TeamPCP / Mini Shai-Hulud npm supply chain attack (May 11-12 2026).

This tool is READ-ONLY. It never deletes, modifies, or connects to anything. It only reads files and reports what it finds.

---

## What Is This Attack

In May 2026, a threat actor group called TeamPCP injected malware into 180 popular npm and PyPI packages. Any developer who ran npm install between May 11-12 2026 while one of the infected versions was in their project may have been affected.

The malware steals GitHub tokens, npm tokens, AWS credentials, CI/CD secrets, and cryptocurrency wallet files. It also installs a hidden daemon that deletes all files on the machine if tokens are revoked before it is safely removed.

---

## Files

| File | Description |
|---|---|
| check.py | Python scanner - works on Mac, Linux, Windows |
| check.ps1 | PowerShell scanner - Windows only, no Python needed |
| README.md | This file |
| developer_checklist.docx | Instructions document to share with developers |

---

## Requirements

**check.py**
- Python 3.6 or higher
- No pip installs needed - standard library only
- Works on Windows, Mac, Linux

**check.ps1**
- PowerShell - already built into every Windows machine
- No Python needed
- Use this if Python is blocked by IT policy

---

## How to Run

**Python - scan a specific repo folder**
```
python check.py /path/to/repo
python check.py C:\Users\you\Downloads\my-repo
```

**Python - scan current folder**
```
python check.py
```

**Python - scan multiple repos**
```
python check.py C:\repos\frontend
python check.py C:\repos\backend
python check.py C:\repos\dashboard
```

**Python - save output to file**
```
python check.py /path/to/repo > results.txt
```

**PowerShell - Windows**
```
powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\Users\you\Downloads\my-repo"
```

---

## What It Checks

| Step | What it does |
|---|---|
| Step 1 | Scans package-lock.json, yarn.lock, pnpm-lock.yaml for 178 infected npm versions |
| Step 2 | Scans requirements.txt for 2 infected PyPI versions |
| Step 3 | Searches for malware payload files with SHA256 hash verification |
| Step 4 | Checks .claude and .vscode folders for hidden backdoors |
| Step 5 | Scans source files for 30 known attack signatures |

---

## What the Output Means

**OVERALL STATUS: CLEAN**
No infected packages, malware files, or attack signatures found. No action needed.

**OVERALL STATUS: AFFECTED**
One or more infected items found. Do NOT change any tokens yet. Follow the remediation steps printed by the tool.

A report file called triage_results.txt is automatically saved inside the scanned folder.

---

## Critical Warning If Affected

DO NOT revoke GitHub tokens or change passwords until the malware daemon is removed first.

The malware runs rm -rf (deletes all files) when it detects a token being revoked.

Remove the daemon first on Mac:
```
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
```

Remove the daemon first on Linux:
```
systemctl --user stop gh-token-monitor
rm -f ~/.config/systemd/user/gh-token-monitor.service
```

Then rotate credentials and block at firewall:
```
api.masscan.cloud
git-tanstack.com
*.getsession.org
83.142.209.194
```

---

## Affected Package Namespaces (180 total)

@tanstack (42), @uipath (66), @squawk (22), @tallyui (10), @mistralai (3), @cap-js (3), @opensearch-project (1), @draftlab (3), @draftauth (2), @mesadev (3), @ml-toolkit-ts (2), @beproduct (1), @dirigible-ai (1), @supersurkhet (2), @taskflow-corp (1), @tolka (1), unscoped packages including safe-action, ts-dna, intercom-client, lightning, mbt and more, PyPI: guardrails-ai, mistralai

---

## Advisory References

- Wiz: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- Aikido: https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- StepSecurity: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem

---

## Disclaimer

For defensive security purposes only.
Run only against repositories you own or have explicit permission to scan.
