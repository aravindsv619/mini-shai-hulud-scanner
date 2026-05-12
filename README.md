# Mini Shai-Hulud Scanner

A defensive SecOps tool to check if a repository is affected
Mini Shai-Hulud npm supply chain attack
(May 11-12 2026).

## What is Mini Shai-Hulud
A self-spreading npm worm by threat actor TeamPCP that
compromised 169 packages including @tanstack, @uipath,
@mistralai and more. It steals GitHub tokens, npm tokens,
AWS credentials and CI/CD secrets.

## What this tool checks
- All 169 compromised npm packages and exact bad versions
- package-lock.json, yarn.lock, pnpm-lock.yaml
- Malicious payload files (router_init.js, tanstack_runner.js)
- IOC strings — C2 domains, orphan commit hash, worm markers
- Saves a triage_results.txt report automatically

## Files
| File | Description |
|---|---|
| check.py | Python version — Mac, Linux, Windows |
| check.ps1 | PowerShell version — Windows only, no Python needed |

## Requirements
- check.py  - Python 3.6+, no pip installs needed
- check.ps1 - PowerShell (built into Windows, no install needed)

## Usage - Python
```bash
# Scan current folder
python check.py

# Scan specific folder
python check.py /path/to/repo

# Windows
python check.py C:\Users\you\Downloads\my-repo

# Save output to file
python check.py /path/to/repo > results.txt
```

## Usage - PowerShell (Windows, no Python needed)
```powershell
# Scan specific folder
powershell -ExecutionPolicy Bypass -File check.ps1 -RepoPath "C:\Users\you\Downloads\my-repo"
```

## Output

CLEAN  - No action required. Safe to report as unaffected.
AFFECTED - See IR steps below immediately.

Report saved automatically as triage_results.txt in scanned folder.

## If AFFECTED - immediate actions in this order
1. Remove gh-token-monitor daemon BEFORE revoking any tokens
2. Delete payload files from .claude/ and .vscode/
3. Rotate GitHub tokens, npm tokens, AWS/GCP creds, CI/CD secrets
4. Block: git-tanstack.com, *.getsession.org, 83.142.209.194

## References
- https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem

## Disclaimer
For defensive security purposes only.
Run only against repositories you own or have permission to scan.
