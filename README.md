# Mini Shai-Hulud Scanner

Defensive SecOps tool to check if a repository is affected by the
TeamPCP / Mini Shai-Hulud npm supply chain attack (May 11-12 2026).

## What it checks
- All 169 compromised npm packages and their exact bad versions
- package-lock.json, yarn.lock, pnpm-lock.yaml
- Malicious payload files (router_init.js, tanstack_runner.js etc.)
- IOC strings (C2 domains, orphan commit hash, worm markers)

## Requirements
- Python 3.6 or higher
- No pip installs needed — standard library only
- Works on Windows, Mac, Linux

## Usage

Scan current folder (run from inside your repo):
    python check.py

Scan a specific repo folder:
    python check.py /path/to/repo
    python check.py C:\Users\you\my-repo

Scan multiple repos:
    python check.py C:\repos\frontend
    python check.py C:\repos\backend

Save output to file:
    python check.py /path/to/repo > results.txt

## References
- https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
