# pulld

**A lightweight, self-hosted GitHub webhook deployment daemon for Linux.**

Push to GitHub → your server redeploys automatically. No cloud services, no agents, no external dependencies — just Python 3 and systemd.

---

## Why pulld?

Platforms like Vercel and Render give you automatic Git-triggered deployments, but they require your code to live in their cloud. If you're running services on your own Linux server — a home lab, a VPS, a local dev machine — you'd normally have to SSH in and redeploy by hand.

pulld solves that. It runs as a systemd daemon, listens for push events from GitHub, validates them with an HMAC secret, and runs a deploy script you define. The whole thing is a single Python file with zero pip dependencies.

---

## Features

- **Zero dependencies** — pure Python 3 stdlib (`http.server`, `hmac`, `subprocess`, `threading`)
- **Per-project secrets** — each project has its own HMAC-SHA256 secret for GitHub to sign payloads with
- **Branch filtering** — only deploys on pushes to the watched branch (e.g. `main`)
- **Concurrent-safe** — per-project lock files prevent overlapping deploys if two pushes arrive in quick succession
- **Structured logging** — timestamped deploy logs per project at `/var/log/pulld/<project>.log`
- **Auto-detects stack** — generates a tailored starter deploy script for Node.js, Python, Docker, Rust, or a generic fallback
- **SSH deploy key setup** — automatically generates an ed25519 key, configures `known_hosts` and SSH config for private repos
- **UPnP port forwarding** — attempts automatic router port mapping via UPnP/IGD so you don't have to configure NAT manually
- **Public IP detection** — resolves your server's public IP to generate copy-paste-ready GitHub webhook URLs
- **CLI management** — `pullctl` covers the full lifecycle: add, remove, list, logs, secrets, config
- **Config hot-reload** — edits to the config take effect on the next request, no restart required
- **Systemd integration** — health-checked, auto-restarting, security-hardened, logs to `journald`
- **Port conflict detection** — on startup, identifies the process occupying the port and exits with a clear message

---

## Requirements

- Linux with systemd
- Python 3.7+
- Git

---

## Installation

```bash
git clone https://github.com/lukasdo-git/pulld.git
cd pulld
sudo bash install.sh
```

The installer:

1. Verifies prerequisites (root, Python 3.7+, Git)
2. Creates all required directories
3. Copies `pulld` and `pullctl` to `/usr/local/bin/`
4. Installs deploy script templates to `/usr/share/pulld/templates/`
5. Installs and enables the systemd service
6. Creates an initial config at `/etc/pulld/config.json`
7. Optionally opens port 9000 through ufw if it's active
8. Starts the daemon and polls `/health` to confirm it's up

Verify it's running:

```bash
curl http://localhost:9000/health
# → {"status": 200, "message": "pulld v1.0.0 — 0 project(s) registered"}
```

---

## Quick start

### Register a project

```bash
sudo pullctl add my-app --path /srv/my-app --branch main
```

This single command:

- Detects your stack (Node, Python, Docker, Rust) and writes a starter deploy script to `/etc/pulld/deploy/my-app.sh`
- Generates a cryptographically secure webhook secret
- Sets `git safe.directory` so the daemon can pull from the repo
- If the remote is SSH, generates an ed25519 deploy key and prints instructions to add it on GitHub
- Attempts UPnP port forwarding on your router (best-effort, never fatal)
- Prints the exact webhook URL and secret to paste into GitHub

Example output:

```
→  Detected project type: node
✓  Deploy script created: /etc/pulld/deploy/my-app.sh
✓  Project 'my-app' registered
✓  Service reloaded
✓  UPnP: port 9000 → 192.168.1.50:9000 (TCP) mapped on your router

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GitHub Webhook Setup — my-app
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. Open your GitHub repo → Settings → Webhooks → Add webhook

  2. Fill in the form:

     Payload URL     http://203.0.113.42:9000/webhook/my-app
     Content type    application/json
     Secret          a3f8c2...
     Events          ✓ Just the push event

  3. Click Add webhook.
```

### Edit the deploy script

```bash
nano /etc/pulld/deploy/my-app.sh
```

### Push a commit and watch it deploy

```bash
pullctl logs my-app -f
```

---

## CLI reference

| Command | Description |
|---|---|
| `pullctl add <name> --path <dir> [--branch <branch>] [--timeout <sec>]` | Register a project |
| `pullctl remove <name> [--keep-script] [--keep-logs]` | Unregister a project and clean up its files |
| `pullctl list` | List all projects with status, last deploy time, and paths |
| `pullctl logs <name> [-n <lines>] [-f]` | View or follow deploy logs |
| `pullctl status` | Show the daemon's systemd status |
| `pullctl secret <name>` | Print GitHub webhook setup instructions |
| `pullctl secret <name> --regenerate` | Rotate the webhook secret |
| `pullctl config [--port <port>] [--host <host>]` | View or update global daemon settings |

All commands that modify state require `sudo`. `pullctl logs` and `pullctl status` work without root.

---

## Deploy scripts

A deploy script is a plain bash file. It runs as the pulld service user with the repo directory as its working directory. Both stdout and stderr are captured to the project's log file.

The simplest possible deploy script:

```bash
#!/bin/bash
set -euo pipefail
git pull
npm ci --silent
pm2 restart my-app
```

A few things to keep in mind:

**`git pull` and credentials** — the repo must already be cloned. For SSH remotes, `pullctl add` generates a deploy key and configures SSH automatically — you just need to add the public key to GitHub. For HTTPS remotes, use a credential helper or a personal access token in the remote URL.

**Restarting services** — by default the daemon runs as root, so `systemctl restart`, `docker compose`, etc. work out of the box from your deploy script.

**Timeouts** — deploy scripts are killed after 300 seconds by default. Override per-project with `--timeout` when adding.

**Failures** — if the script exits with a non-zero code, it's logged as a failed deploy. The previous version of the app continues running.

---

## File layout

```
/usr/local/bin/pulld              # Daemon
/usr/local/bin/pullctl            # CLI tool
/etc/systemd/system/pulld.service # Systemd unit
/etc/pulld/config.json            # Project registry (chmod 600)
/etc/pulld/deploy/<name>.sh       # Per-project deploy scripts
/var/log/pulld/pulld.log          # Daemon log
/var/log/pulld/<name>.log         # Per-project deploy logs
/run/pulld/<name>.lock            # Per-project deploy locks (runtime)
/usr/share/pulld/templates/       # Starter deploy script templates
```

---

## Configuration

`/etc/pulld/config.json` is managed by `pullctl`, but you can edit it directly. The daemon re-reads it on every incoming request, so changes take effect immediately without a restart.

```json
{
  "_host": "0.0.0.0",
  "_port": 9000,

  "my-app": {
    "secret":        "your-hmac-secret",
    "repo_path":     "/srv/my-app",
    "deploy_script": "/etc/pulld/deploy/my-app.sh",
    "branch":        "main",
    "timeout":       300
  }
}
```

Keys prefixed with `_` are global daemon settings. All other keys are project entries. Config writes are atomic (write to `.tmp`, then rename) to prevent corruption.

---

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns daemon version and registered project count |
| `POST` | `/webhook/<project>` | GitHub webhook receiver |

---

## Security

**HMAC validation** — every webhook payload is verified against the project's secret using `hmac.compare_digest`, which is constant-time and resistant to timing attacks. Requests with a missing or invalid signature are rejected with a 401.

**Unknown projects** — requests to unregistered project names return 200 (not 404) to avoid leaking which projects are configured.

**Config permissions** — `/etc/pulld/config.json` is created with mode `600` and contains webhook secrets in plaintext, consistent with how tools like nginx and SSH store credentials. Protect access to this file accordingly.

**Systemd hardening** — the service unit sets `NoNewPrivileges=yes`, `PrivateTmp=yes`, and restricts write access to only the directories pulld needs (`/var/log/pulld`, `/run/pulld`, `/etc/pulld`).

**Running as root** — the default service runs as root so deploy scripts can freely call `systemctl restart`, `docker compose`, etc. To use a dedicated user, change `User=` in the service file and ensure that user has the required permissions.

---

## Networking

**UPnP port forwarding** — when you register a project, `pullctl` automatically attempts to configure a port mapping on your router via UPnP/IGD. This is best-effort — if your router doesn't support UPnP or it's disabled, you'll see a warning with instructions for manual port forwarding. This is only relevant for servers behind NAT (home labs, local machines). VPS and cloud servers don't need it.

**Public IP detection** — `pullctl` resolves your server's public IP (via ipify, ifconfig.me, or icanhazip) to generate accurate webhook URLs. If public IP detection fails (e.g. no internet during setup), it falls back to the LAN IP and warns you to substitute it.

---

## Uninstalling

```bash
sudo bash uninstall.sh
```

The uninstaller stops the service, removes the binaries and systemd unit, and prompts before deleting config and log directories.

---

## License

[MIT](LICENSE)
