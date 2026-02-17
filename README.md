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
- **Auto-detects stack** — generates a tailored starter deploy script for Node.js, Python, Docker, or Rust
- **CLI management** — `pullctl` covers the full lifecycle: add, remove, list, logs, secrets
- **Config hot-reload** — edits to the config take effect on the next request, no restart required
- **Systemd integration** — health-checked, auto-restarting, logs to `journald`
- **GitHub ping support** — correctly handles the ping GitHub sends when a webhook is first configured

---

## Requirements

- Linux with systemd
- Python 3.7+
- Git

That's it.

---

## Installation

```bash
git clone https://github.com/yourname/pulld.git
cd pulld
sudo bash install.sh
```

The installer:
1. Copies `pulld` and `pullctl` to `/usr/local/bin/`
2. Installs the systemd service and enables it on boot
3. Creates an initial config at `/etc/pulld/config.json`
4. Optionally opens port 9000 through ufw if it's active
5. Starts the daemon immediately

Verify it's running:
```bash
curl http://localhost:9000/health
# → {"status": 200, "message": "pulld v1.0.0 — 0 project(s) registered"}
```

---

## Registering a project

```bash
sudo pullctl add my-app --path /srv/my-app --branch main
```

That command:
- Detects your stack (Node, Python, Docker, etc.) and generates a starter deploy script at `/etc/pulld/deploy/my-app.sh`
- Generates a random webhook secret
- Registers the project in the config
- Prints the exact URL and secret to paste into GitHub

Example output:
```
→  Detected project type: node
✓  Deploy script created: /etc/pulld/deploy/my-app.sh
✓  Project 'my-app' registered
✓  Service reloaded

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

Then edit the deploy script to match your exact setup:
```bash
nano /etc/pulld/deploy/my-app.sh
```

Push a commit to trigger a test deploy:
```bash
pullctl logs my-app -f
```

---

## CLI Reference

| Command | Description |
|---|---|
| `pullctl add <name> --path <dir>` | Register a project |
| `pullctl remove <name>` | Unregister a project |
| `pullctl list` | List all projects and their status |
| `pullctl logs <name> [-f]` | View (or follow) deploy logs |
| `pullctl status` | Show the daemon's systemd status |
| `pullctl secret <name>` | Print GitHub webhook setup instructions |
| `pullctl secret <name> --regenerate` | Rotate the webhook secret |
| `pullctl config --port <port>` | Change the listening port |

All commands that modify state require `sudo`.

---

## File layout

```
/usr/local/bin/pulld          # Daemon binary
/usr/local/bin/pullctl        # CLI tool
/etc/systemd/system/pulld.service
/etc/pulld/config.json        # Project registry (chmod 600)
/etc/pulld/deploy/<name>.sh   # Per-project deploy scripts
/var/log/pulld/pulld.log   # Daemon log
/var/log/pulld/<name>.log     # Per-project deploy logs
/run/pulld/<name>.lock        # Per-project deploy locks
/usr/share/pulld/templates/   # Starter deploy script templates
```

---

## Config format

`/etc/pulld/config.json` is managed by `pullctl`, but you can edit it directly if needed. The daemon re-reads it on every incoming request, so no restart is required.

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

Keys prefixed with `_` are global daemon settings. All other keys are project names.

---

## Deploy scripts

A deploy script is a plain bash file. It runs with the repo directory as its working directory. stdout and stderr are both captured to the project's log file.

The simplest possible deploy script:
```bash
#!/bin/bash
set -euo pipefail
git pull
npm ci --silent
pm2 restart my-app
```

A few things to keep in mind:

**`git pull` and credentials** — the repo must already be cloned and git credentials must be set up for the user the daemon runs as. For SSH repos, generate a key for that user and add it to GitHub. For HTTPS repos, use a credential helper or a personal access token in the remote URL.

**Restarting systemd services from the script** — by default, the daemon runs as root (see the service file), so `systemctl restart` works out of the box.

**Build failures** — if the deploy script exits with a non-zero code, it's logged and pulld reports it as a failed deploy. The previous version of the app continues running.

---

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns daemon version and registered project count |
| `POST` | `/webhook/<project>` | GitHub webhook receiver |

---

## Security notes

**HMAC validation** — every webhook payload is verified against the project's secret using `hmac.compare_digest`, which is constant-time and resistant to timing attacks. Requests with a missing or invalid signature are rejected with a 401.

**Unknown projects** — requests for unregistered project names return a 200 (not 404) to avoid leaking information about which projects are configured.

**Config permissions** — `/etc/pulld/config.json` is written with `chmod 600` and contains webhook secrets in plaintext, which is standard practice for this type of tool (similar to how nginx or SSH configs store credentials). Protect access to the file accordingly.

**Running as root** — the default service runs as root to keep deploy scripts simple (they can freely call `systemctl restart`, `docker`, etc.). If you prefer a dedicated user, change `User=` in the service file and ensure that user has the necessary permissions for your deploy scripts.

---

## Uninstalling

```bash
sudo bash uninstall.sh
```

The uninstaller stops the service, removes the binaries and systemd unit, and asks before deleting config and logs.

---

## License

MIT
