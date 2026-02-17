#!/usr/bin/env python3
"""
pulld — Lightweight GitHub Webhook Deployment Daemon
Pure Python stdlib. No external dependencies required.

Architecture:
  GitHub push → POST /webhook/<project> → HMAC validation → deploy script (background thread)

Config:   /etc/pulld/config.json
Logs:     /var/log/pulld/<project>.log  +  /var/log/pulld/pulld.log
Locks:    /run/pulld/<project>.lock      (prevents concurrent deploys)
Scripts:  /etc/pulld/deploy/<project>.sh
"""

import sys
import os
import json
import hmac
import hashlib
import logging
import subprocess
import threading
import time
import signal
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

VERSION    = "1.0.0"
CONFIG_PATH = "/etc/pulld/config.json"
LOG_DIR    = "/var/log/pulld"
LOCK_DIR   = "/run/pulld"
DAEMON_LOG = "/var/log/pulld/pulld.log"

# Protects config re-reads during concurrent requests
_config_lock = threading.Lock()


# ──────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────

def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s  [%(levelname)-7s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger("pulld")
    logger.setLevel(logging.INFO)

    # File handler — persists across restarts
    fh = logging.FileHandler(DAEMON_LOG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Stdout handler — captured by journald when running as systemd service
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


log = _setup_logging()


# ──────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────

def load_config() -> dict:
    """
    Load and return the config from disk. Thread-safe.
    Config is re-read on every request so edits take effect without a restart.
    """
    with _config_lock:
        if not os.path.exists(CONFIG_PATH):
            return {}
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.error(f"Failed to parse config: {e}")
            return {}


# ──────────────────────────────────────────────────────────────────
# Security
# ──────────────────────────────────────────────────────────────────

def validate_signature(secret: str, payload: bytes, sig_header: str) -> bool:
    """
    Verify GitHub's HMAC-SHA256 webhook signature.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    expected = "sha256=" + mac
    return hmac.compare_digest(expected, sig_header)


# ──────────────────────────────────────────────────────────────────
# Deployment
# ──────────────────────────────────────────────────────────────────

def _lock_path(project: str) -> str:
    return os.path.join(LOCK_DIR, f"{project}.lock")


def _deploy_log_path(project: str) -> str:
    return os.path.join(LOG_DIR, f"{project}.log")


def run_deploy(project: str, cfg: dict, payload: dict) -> None:
    """
    Execute the deploy script for a project in a background thread.

    Concurrency: a per-project lock file prevents overlapping deploys.
    If a deploy is already running when a new push arrives, the new
    trigger is dropped and a warning is logged.
    """
    lock_path = _lock_path(project)
    log_path  = _deploy_log_path(project)

    # ── Acquire per-project lock (atomic create) ──────────────────
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    except FileExistsError:
        log.warning(f"[{project}] Deploy already in progress — skipping incoming trigger")
        return

    deploy_script = cfg["deploy_script"]
    repo_path     = cfg["repo_path"]
    timeout       = int(cfg.get("timeout", 300))

    commit_sha = payload.get("after", "unknown")[:7]
    branch     = payload.get("ref", "").replace("refs/heads/", "")
    pusher     = payload.get("pusher", {}).get("name", "unknown")

    log.info(f"[{project}] Deploy started — commit {commit_sha} on '{branch}' (by {pusher})")

    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        header = (
            f"\n{'━' * 64}\n"
            f"  Project  : {project}\n"
            f"  Commit   : {commit_sha}\n"
            f"  Branch   : {branch}\n"
            f"  Pusher   : {pusher}\n"
            f"  Started  : {timestamp}\n"
            f"{'━' * 64}\n\n"
        )

        with open(log_path, "a") as log_file:
            log_file.write(header)
            log_file.flush()

            result = subprocess.run(
                ["/bin/bash", deploy_script],
                cwd=repo_path,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )

            footer = (
                f"\n{'─' * 64}\n"
                f"  Exit code : {result.returncode}\n"
                f"  Finished  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{'─' * 64}\n"
            )
            log_file.write(footer)

        if result.returncode == 0:
            log.info(f"[{project}] Deploy successful ✓  (commit {commit_sha})")
        else:
            log.error(f"[{project}] Deploy failed — exit code {result.returncode}  (commit {commit_sha})")

    except subprocess.TimeoutExpired:
        msg = f"Deploy timed out after {timeout}s"
        log.error(f"[{project}] {msg}")
        with open(log_path, "a") as f:
            f.write(f"\n[TIMEOUT]  {msg}\n")

    except Exception as exc:
        log.error(f"[{project}] Unexpected error: {exc}")
        with open(log_path, "a") as f:
            f.write(f"\n[ERROR]  {exc}\n")

    finally:
        # Always release the lock, even if the deploy crashed
        try:
            os.remove(lock_path)
        except OSError:
            pass


# ──────────────────────────────────────────────────────────────────
# HTTP Request Handler
# ──────────────────────────────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):
    """
    Handles incoming HTTP requests from GitHub.

    Routes:
      GET  /health              — liveness check
      POST /webhook/<project>   — webhook endpoint
    """

    def log_message(self, fmt, *args):
        # Route access logs through our structured logger
        log.info("HTTP  " + (fmt % args))

    def _json(self, code: int, message: str) -> None:
        body = json.dumps({"status": code, "message": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── GET /health ───────────────────────────────────────────────
    def do_GET(self) -> None:
        if self.path == "/health":
            config   = load_config()
            projects = [k for k in config if not k.startswith("_")]
            self._json(200, f"pulld v{VERSION} — {len(projects)} project(s) registered")
        else:
            self._json(404, "not found")

    # ── POST /webhook/<project> ───────────────────────────────────
    def do_POST(self) -> None:
        parts = [p for p in urlparse(self.path).path.strip("/").split("/") if p]

        # Validate URL shape
        if len(parts) != 2 or parts[0] != "webhook":
            self._json(404, "invalid endpoint — expected /webhook/<project>")
            return

        project = parts[1]
        config  = load_config()

        if project not in config or project.startswith("_"):
            log.warning(f"Received webhook for unknown project: '{project}'")
            # Return 200 to avoid leaking project names via status codes
            self._json(200, "ok")
            return

        cfg = config[project]

        # ── Read raw body ─────────────────────────────────────────
        try:
            length       = int(self.headers.get("Content-Length", 0))
            payload_bytes = self.rfile.read(length)
        except (ValueError, OSError) as e:
            log.error(f"[{project}] Failed to read request body: {e}")
            self._json(400, "could not read body")
            return

        # ── Verify HMAC signature ─────────────────────────────────
        sig = self.headers.get("X-Hub-Signature-256", "")
        if not validate_signature(cfg["secret"], payload_bytes, sig):
            log.warning(f"[{project}] Signature validation failed — rejected")
            self._json(401, "signature mismatch")
            return

        # ── Parse JSON ────────────────────────────────────────────
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, "malformed JSON")
            return

        # ── Handle GitHub ping (sent when webhook is first added) ─
        if self.headers.get("X-GitHub-Event") == "ping":
            log.info(f"[{project}] Ping from GitHub — webhook configured correctly ✓")
            self._json(200, "pong")
            return

        # ── Check branch ──────────────────────────────────────────
        pushed_ref   = payload.get("ref", "")
        watched_ref  = f"refs/heads/{cfg.get('branch', 'main')}"

        if pushed_ref != watched_ref:
            log.info(f"[{project}] Ignoring push to '{pushed_ref}' (watching '{watched_ref}')")
            self._json(200, f"ignored push to {pushed_ref}")
            return

        # ── Verify deploy script exists ───────────────────────────
        script = cfg.get("deploy_script", "")
        if not os.path.isfile(script):
            log.error(f"[{project}] Deploy script not found: '{script}'")
            self._json(500, "deploy script not found")
            return

        # ── Respond immediately, deploy runs in background ────────
        self._json(200, f"deploy queued for {project}")

        thread = threading.Thread(
            target=run_deploy,
            args=(project, cfg, payload),
            daemon=True,
        )
        thread.start()


# ──────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────

def main() -> None:
    os.makedirs(LOG_DIR,  exist_ok=True)
    os.makedirs(LOCK_DIR, exist_ok=True)

    config = load_config()
    host   = config.get("_host", "0.0.0.0")
    port   = int(config.get("_port", 9000))

    log.info(f"pulld v{VERSION} starting")

    server = ThreadingHTTPServer((host, port), WebhookHandler)

    # Graceful shutdown on SIGTERM (sent by systemd on `systemctl stop`)
    def _on_sigterm(signum, frame):
        log.info("SIGTERM received — shutting down gracefully")
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _on_sigterm)

    projects = [k for k in config if not k.startswith("_")]
    if projects:
        log.info(f"Registered projects: {', '.join(projects)}")
    else:
        log.warning("No projects registered yet. Run: pullctl add <name> --path <repo>")

    log.info(f"Listening on {host}:{port}  |  Health check: http://{host}:{port}/health")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Interrupted — shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
