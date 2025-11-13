#!/usr/bin/env python3
"""
fcmpy - Local FCM push daemon + CLI around HTTP v1 API

Features:
  * HTTP endpoint for sending FCM pushes from SIP/XMPP/etc
  * Token storage in MySQL/MariaDB
  * Simple daily stats + log cleanup
  * Optional "keepalive" scheduler (random once/day per active token),
    automatically stopping if no keepalive reply is recorded for > N days
  * CLI management:
      --sample
      --install / --uninstall
      --list / --delete / --delete-inactive / --activate / --deactivate
      --add / --send / --stat
"""

import argparse
import datetime
import json
import os
import random
import socket
import sys
import threading
import time
import urllib.parse
from collections import defaultdict
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import psutil
import pymysql
import requests

# ---------------------------------------------------------------------
# Defaults / configuration
# ---------------------------------------------------------------------

DEFAULTS = {
    "SERVICE_ACCOUNT": "/var/secrets/fcmpy-service-account.json",
    "LISTEN_ADDR": "127.0.0.1",
    "LISTEN_PORT": 9090,
    "DB_HOST": "localhost",
    "DB_USER": "fcmpy",
    "DB_PASS": "change_me",
    "DB_NAME": "fcmpy",
    "ACCESS_TOKEN": "",
}

TEMPLATES_FILE = "/etc/fcmpy-templates.json"

# Runtime stats
START_TIME = time.time()
STATS = defaultdict(int)
STATS_LOCK = threading.Lock()

# Global template cache
TEMPLATES = {}

# Token cache for Google OAuth
TOKEN_CACHE = {"value": None, "exp": 0}

# Whether to run keepalive scheduler
KEEPALIVE_ENABLED = True
# Stop sending keepalives if there has been no reply for this many days
KEEPALIVE_MAX_SILENCE_DAYS = 7

ENV_FILE_PATH = "/etc/fcmpy.env"

def load_env_from_file(path=ENV_FILE_PATH):
    """
    Load KEY=VALUE pairs from a simple env file into os.environ,
    without overriding variables already set in the process env.
    Lines starting with '#' and empty lines are ignored.
    """
    if not os.path.exists(path):
        return

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # don't overwrite explicit environment or CLI overrides
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as e:
        print(f"[WARN] Failed to load env from {path}: {e}")

# ---------------------------------------------------------------------
# Argument parsing (for config, not for management commands)
# ---------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Local FCM daemon + CLI",
        add_help=False,          # we do manual help / commands
        allow_abbrev=False       # <- IMPORTANT: don't treat --list as --listen-*
    )
    p.add_argument("--service-account", default=os.getenv("SERVICE_ACCOUNT", DEFAULTS["SERVICE_ACCOUNT"]))
    p.add_argument("--listen-addr", default=os.getenv("LISTEN_ADDR", DEFAULTS["LISTEN_ADDR"]))
    p.add_argument("--listen-port", type=int, default=int(os.getenv("LISTEN_PORT", DEFAULTS["LISTEN_PORT"])))
    p.add_argument("--db-host", default=os.getenv("DB_HOST", DEFAULTS["DB_HOST"]))
    p.add_argument("--db-user", default=os.getenv("DB_USER", DEFAULTS["DB_USER"]))
    p.add_argument("--db-pass", default=os.getenv("DB_PASS", DEFAULTS["DB_PASS"]))
    p.add_argument("--db-name", default=os.getenv("DB_NAME", DEFAULTS["DB_NAME"]))
    p.add_argument("--access-token", default=os.getenv("ACCESS_TOKEN", DEFAULTS["ACCESS_TOKEN"]))

    # Ignore unknown CLI flags like --sample, --list, --stat, etc.
    args, _ = p.parse_known_args()
    return args

# Load config from /etc/fcmpy.env (if present) before parsing args
load_env_from_file()

args = parse_args()

CURRENT_CONFIG = {
    "service_account": args.service_account,
    "project_id": None,
    "db_host": args.db_host,
    "db_user": args.db_user,
    "db_name": args.db_name,
    "access_token": args.access_token,
}

# ---------------------------------------------------------------------
# Service account / Google access token
# ---------------------------------------------------------------------

def load_service_account(path):
    with open(path, "r") as f:
        return json.load(f)


# Service account and project ID are loaded lazily
sa = None
PROJECT_ID = None

def ensure_service_account_loaded():
    """
    Load Firebase service account JSON once, on demand.
    Returns True if loaded successfully, False otherwise.
    """
    global sa, PROJECT_ID
    if sa is not None and PROJECT_ID:
        return True

    try:
        sa_local = load_service_account(args.service_account)
        project_id = sa_local.get("project_id")
        if not project_id:
            print("❌ Missing project_id in service account JSON")
            return False
        sa = sa_local
        PROJECT_ID = project_id
        return True
    except Exception as e:
        print(f"❌ Failed to load service account: {e}")
        return False

def get_access_token():
    """Return cached OAuth token for FCM HTTP v1, refreshing when needed."""
    if not ensure_service_account_loaded():
        raise Exception("Service account is not loaded (SERVICE_ACCOUNT not set or file missing)")

    if TOKEN_CACHE["value"] and time.time() < TOKEN_CACHE["exp"] - 60:
        return TOKEN_CACHE["value"]

    now = int(time.time())
    payload = {
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }

    jwt_token = jwt.encode(payload, sa["private_key"], algorithm="RS256")
    r = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_token,
        },
        timeout=10,
    )
    data = r.json()
    if "access_token" not in data:
        raise Exception(f"Token request failed: {data}")
    TOKEN_CACHE["value"] = data["access_token"]
    TOKEN_CACHE["exp"] = time.time() + int(data.get("expires_in", 3600))
    return TOKEN_CACHE["value"]


def reload_service_account():
    """Reload service account from disk (used by /reload)."""
    global sa, PROJECT_ID
    try:
        sa_local = load_service_account(args.service_account)
        project_id = sa_local.get("project_id")
        if not project_id:
            print("[ERR reload_service_account] Missing project_id in service account JSON")
            return False
        sa = sa_local
        PROJECT_ID = project_id
        CURRENT_CONFIG["project_id"] = PROJECT_ID
        print(f"[RELOAD] Loaded service account for project: {PROJECT_ID}")
        return True
    except Exception as e:
        print(f"[ERR reload_service_account] {e}")
        return False



# ---------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------

def load_templates():
    """Load message templates from JSON file into TEMPLATES."""
    global TEMPLATES
    try:
        with open(TEMPLATES_FILE, "r") as f:
            TEMPLATES = json.load(f)
        print(f"[TEMPLATES] Loaded {len(TEMPLATES)} templates from {TEMPLATES_FILE}")
        return True
    except Exception as e:
        print(f"[WARN] Failed to load templates from {TEMPLATES_FILE}: {e}")
        # small default set
        TEMPLATES = {
            "call": {"title": "Incoming call from {caller}", "body": "Tap to open app", "priority": "high"},
            "message": {"title": "New message from {caller}", "body": "{body}", "priority": "normal"},
            "keepalive": {"title": "Background sync", "body": "Keeping connection alive", "priority": "high"},
            "default": {"title": "Notification", "body": "{body}", "priority": "normal"},
        }
        return False


load_templates()


# ---------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------

def db_connect():
    return pymysql.connect(
        host=args.db_host,
        user=args.db_user,
        password=args.db_pass,
        database=args.db_name,
        charset="utf8mb4",
    )


def create_database_tables():
    """Create / update required tables and columns."""
    ddl = [
        """
        CREATE TABLE IF NOT EXISTS fcm_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            token VARCHAR(255) NOT NULL,
            device_id VARCHAR(64) DEFAULT NULL,
            platform ENUM('android','ios','web') DEFAULT 'android',
            active TINYINT(1) DEFAULT 1,
            keepalive_last DATETIME NULL,
            keepalive_next DATETIME NULL,
            keepalive_replay DATETIME NULL,
            updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_user_token (username, token)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """,
        """
        CREATE TABLE IF NOT EXISTS fcm_push_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            caller VARCHAR(64),
            msg_type VARCHAR(32),
            token_hash CHAR(12),
            http_code INT,
            status VARCHAR(64),
            msg TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """,
        """
        CREATE TABLE IF NOT EXISTS fcm_stats_daily (
            id INT AUTO_INCREMENT PRIMARY KEY,
            date DATE NOT NULL UNIQUE,
            sent_ok INT DEFAULT 0,
            sent_fail INT DEFAULT 0,
            cleaned INT DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """,
    ]
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            for stmt in ddl:
                cur.execute(stmt)
            # safety: add missing columns if table existed before
            for sql in [
                "ALTER TABLE fcm_tokens ADD COLUMN keepalive_last DATETIME NULL",
                "ALTER TABLE fcm_tokens ADD COLUMN keepalive_next DATETIME NULL",
                "ALTER TABLE fcm_tokens ADD COLUMN keepalive_replay DATETIME NULL",
                "ALTER TABLE fcm_tokens ADD INDEX idx_keepalive_next (keepalive_next)",
            ]:
                try:
                    cur.execute(sql)
                except Exception:
                    pass
        conn.commit()
        conn.close()
        print("✅ Database tables verified/created.")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")


def get_user_tokens(username):
    """Return list of active tokens for a username."""
    try:
        with db_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT token FROM fcm_tokens WHERE active=1 AND username=%s",
                    (username,),
                )
                return [row[0] for row in cur.fetchall()]
    except Exception as e:
        print(f"[DB ERR get_user_tokens] {e}")
        return []


def log_push(username, caller, msg_type, token, http_code, status, msg):
    """Log push into fcm_push_log in background."""
    try:
        token_hash = sha256(token.encode()).hexdigest()[:12]
        threading.Thread(
            target=_log_push_bg,
            args=(username, caller, msg_type, token_hash, http_code, status, msg),
            daemon=True,
        ).start()
    except Exception as e:
        print(f"[LOG ERROR] {e}")


def _log_push_bg(username, caller, msg_type, token_hash, http_code, status, msg):
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fcm_push_log
                    (username, caller, msg_type, token_hash, http_code, status, msg)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (username, caller, msg_type, token_hash, http_code, status, msg),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERR log_push] {e}")


def cleanup_old_logs(days=30):
    """Delete entries older than N days from fcm_push_log."""
    print(f"[CLEANUP] Deleting log entries older than {days} days…")
    deleted = 0
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM fcm_push_log WHERE created_at < (NOW() - INTERVAL %s DAY)",
                (days,),
            )
            deleted = cur.rowcount
        conn.commit()
        conn.close()
        if deleted:
            print(f"[CLEANUP] Removed {deleted} log entries.")
    except Exception as e:
        print(f"[DB ERR cleanup_old_logs] {e}")
    return deleted


def save_daily_stats(cleaned_count=0):
    """Store accumulated in-memory stats into fcm_stats_daily."""
    try:
        today = datetime.date.today()
        with db_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO fcm_stats_daily (date, sent_ok, sent_fail, cleaned)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        sent_ok = sent_ok + VALUES(sent_ok),
                        sent_fail = sent_fail + VALUES(sent_fail),
                        cleaned = cleaned + VALUES(cleaned),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (today, STATS["sent_ok"], STATS["sent_fail"], cleaned_count),
                )
        conn.commit()
        print(f"[STATS] {today}: OK={STATS['sent_ok']} FAIL={STATS['sent_fail']} CLEANED={cleaned_count}")
        with STATS_LOCK:
            STATS.clear()
    except Exception as e:
        print(f"[DB ERR save_daily_stats] {e}")


def get_stats_today():
    """Return today's stats combined: runtime + DB."""
    today = datetime.date.today().isoformat()
    data = {
        "date": today,
        "sent_ok": STATS.get("sent_ok", 0),
        "sent_fail": STATS.get("sent_fail", 0),
        "cleaned": STATS.get("cleaned", 0),
    }
    try:
        with db_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT sent_ok, sent_fail, cleaned FROM fcm_stats_daily WHERE date=%s",
                    (today,),
                )
                row = cur.fetchone()
                if row:
                    data["sent_ok_db"], data["sent_fail_db"], data["cleaned_db"] = row
    except Exception as e:
        data["error"] = str(e)
    return data


def get_system_health():
    """Return process/system health info."""
    uptime = int(time.time() - START_TIME)
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    mem = psutil.virtual_memory()
    try:
        conn = db_connect()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "uptime_sec": uptime,
        "cpu_load_1m": round(load[0], 2),
        "cpu_load_5m": round(load[1], 2),
        "cpu_load_15m": round(load[2], 2),
        "mem_used_mb": round(mem.used / 1024 / 1024, 1),
        "mem_total_mb": round(mem.total / 1024 / 1024, 1),
        "mem_percent": mem.percent,
        "db_connected": db_ok,
    }


def reset_stats():
    """Reset in-memory counters to zero."""
    with STATS_LOCK:
        STATS["sent_ok"] = 0
        STATS["sent_fail"] = 0
        STATS["cleaned"] = 0
    print(f"[STATS] Counters reset at {datetime.datetime.now().isoformat()}")
    return {"status": "reset_ok", "time": datetime.datetime.now().isoformat()}


# ---------------------------------------------------------------------
# Push sending
# ---------------------------------------------------------------------

def send_push(token, username, msg_type, caller, extra_data=None):
    """
    Send one FCM HTTP v1 push to `token`.

    msg_type     -> template name (e.g. "call", "message", "keepalive", "default")
    caller       -> string used in templates and data
    extra_data   -> optional dict of extra key/values for data payload and template formatting
    """
    extra_data = extra_data or {}
    try:
        access_token = get_access_token()
        template = TEMPLATES.get(msg_type, TEMPLATES.get("default", {}))

        title_template = template.get("title", "Notification")
        body_template = template.get("body", "")

        fmt_ctx = {
            "caller": caller,
            "username": username,
            "body": extra_data.get("body", ""),
            "text": extra_data.get("body", ""),
        }

        title = title_template.format(**fmt_ctx)
        body = body_template.format(**fmt_ctx)
        priority = template.get("priority", "high")

        data = {
            "type": msg_type,
            "caller": caller,
            "username": username,
            "title": title,
            "body": body,
        }
        for k, v in extra_data.items():
            data[k] = str(v)

        payload = {
            "message": {
                "token": token,
                "android": {"priority": priority},
                "data": data,
            }
        }

        r = requests.post(
            f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=10,
        )

        ok = (r.status_code == 200)
        print(f"[{time.strftime('%H:%M:%S')}] Push->{username} ({token[:12]}...): {r.status_code} type={msg_type}")

        log_push(username, caller, msg_type, token, r.status_code, "OK" if ok else "FAIL", str(payload) + str(r.content))
        with STATS_LOCK:
            if ok:
                STATS["sent_ok"] += 1
            else:
                STATS["sent_fail"] += 1

    except Exception as e:
        print(f"[ERR Push {username}] {e}")
        try:
            log_push(username, caller, msg_type, token, 0, "EXC", str(e))
        except Exception:
            pass


# ---------------------------------------------------------------------
# Keepalive scheduler (optional)
# ---------------------------------------------------------------------

def next_random_keepalive(from_dt=None, days_min=1, days_max=1):
    """
    Return datetime between days_min and days_max days from now,
    at random HH:MM (per token).
    """
    if from_dt is None:
        from_dt = datetime.datetime.now()
    day_offset = random.randint(days_min, days_max)
    base = (from_dt + datetime.timedelta(days=day_offset)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    hh = random.randint(0, 23)
    mm = random.randint(0, 59)
    return base + datetime.timedelta(hours=hh, minutes=mm)


def keepalive_seed_batch(limit=200):
    """Assign initial keepalive_next for tokens that don't have it yet."""
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM fcm_tokens
                WHERE active=1
                  AND keepalive_next IS NULL
                  AND (keepalive_replay IS NULL
                       OR keepalive_replay >= NOW() - INTERVAL %s DAY)
                LIMIT %s
                """,
                (KEEPALIVE_MAX_SILENCE_DAYS, limit),
            )
            rows = cur.fetchall()
            if not rows:
                conn.close()
                return 0

            now = datetime.datetime.now()
            for (token_id,) in rows:
                nxt = next_random_keepalive(from_dt=now)
                cur.execute(
                    "UPDATE fcm_tokens SET keepalive_next=%s WHERE id=%s",
                    (nxt, token_id),
                )
        conn.commit()
        conn.close()
        print(f"[KEEPALIVE] Seeded {len(rows)} tokens with initial schedule")
        return len(rows)
    except Exception as e:
        print(f"[KEEPALIVE ERR seed] {e}")
        return 0


def keepalive_scheduler():
    """
    Background thread:
      * seed tokens with missing schedule
      * each minute, find due tokens (keepalive_next <= NOW())
      * send 'keepalive' push and move keepalive_next to random time tomorrow
      * stop sending if keepalive_replay is older than KEEPALIVE_MAX_SILENCE_DAYS
    """
    print("[KEEPALIVE] Scheduler started (random once per day per active token)")
    while True:
        try:
            keepalive_seed_batch()

            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, token
                    FROM fcm_tokens
                    WHERE active=1
                      AND keepalive_next IS NOT NULL
                      AND keepalive_next <= NOW()
                      AND (keepalive_replay IS NULL
                           OR keepalive_replay >= NOW() - INTERVAL %s DAY)
                    LIMIT 200
                    """,
                    (KEEPALIVE_MAX_SILENCE_DAYS,),
                )
                due = cur.fetchall()
            conn.close()

            if not due:
                time.sleep(60)
                continue

            now = datetime.datetime.now()
            updates = []

            for token_id, username, token in due:
                threading.Thread(
                    target=send_push,
                    args=(token, username, "keepalive", "system"),
                    daemon=True,
                ).start()
                updates.append((token_id, next_random_keepalive(from_dt=now)))

            conn = db_connect()
            with conn.cursor() as cur:
                for token_id, nxt in updates:
                    cur.execute(
                        """
                        UPDATE fcm_tokens
                        SET keepalive_last = NOW(), keepalive_next = %s
                        WHERE id = %s
                        """,
                        (nxt, token_id),
                    )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[KEEPALIVE ERR scheduler] {e}")
            time.sleep(60)
        else:
            time.sleep(60)


# ---------------------------------------------------------------------
# Cleanup scheduler (daily at 03:00)
# ---------------------------------------------------------------------

def cleanup_scheduler():
    print("[CLEANUP] Background thread running daily at 03:00")
    while True:
        now = datetime.datetime.now()
        target = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if target < now:
            target += datetime.timedelta(days=1)
        wait = (target - now).total_seconds()
        print(f"[CLEANUP] Next cleanup at {target}")
        time.sleep(wait)

        cleaned = cleanup_old_logs(days=30)
        with STATS_LOCK:
            STATS["cleaned"] = cleaned
        save_daily_stats(cleaned)


# ---------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def do_GET(self):
        if self.path.startswith("/stats"):
            if self.path.startswith("/stats/reset"):
                # optional protection with ACCESS_TOKEN
                auth_header = self.headers.get("X-Access-Key", "")
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)
                token_param = params.get("token", [""])[0]
                provided = auth_header or token_param
                if args.access_token and provided != args.access_token:
                    self._send_json({"error": "unauthorized"}, 403)
                    print(f"[SECURITY] Unauthorized stats reset from {self.client_address[0]}")
                    return
                result = reset_stats()
                self._send_json(result)
                return

            result = get_stats_today()
            system = get_system_health()
            result.update(system)
            self._send_json(result)
            return

        # health check
        self._send_json({"status": "ok", "msg": "fcmpy daemon running"}, 200)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            parsed_path = urllib.parse.urlparse(self.path)

            # /reload - reload templates + service account
            if parsed_path.path.startswith("/reload"):
                auth_header = self.headers.get("X-Access-Key", "")
                params = urllib.parse.parse_qs(parsed_path.query)
                token_param = params.get("token", [""])[0]
                provided = auth_header or token_param
                if args.access_token and provided != args.access_token:
                    self._send_json({"error": "unauthorized"}, 403)
                    print(f"[SECURITY] Unauthorized reload from {self.client_address[0]}")
                    return

                ok_tpl = load_templates()
                ok_sa = reload_service_account()
                # Test DB connection
                try:
                    conn = db_connect()
                    conn.close()
                    ok_db = True
                except Exception as e:
                    ok_db = False
                    print(f"[RELOAD] DB connection failed during reload test: {e}")
                self._send_json(
                    {
                        "status": "reloaded",
                        "templates": ok_tpl,
                        "service_account": ok_sa,
                        "db_connection": ok_db,
                        "time": datetime.datetime.now().isoformat(),
                    }
                )
                return

            # default POST: username + type + from -> push
            params = urllib.parse.parse_qs(body)
            username = params.get("username", [""])[0]
            msg_type = params.get("type", ["call"])[0]
            caller = params.get("from", ["unknown"])[0]
            body_text = params.get("body", [""])[0]

            tokens = get_user_tokens(username)
            if not tokens:
                self._send_json({"status": "no_tokens", "user": username})
                return

            extra = {"body": body_text} if body_text else {}
            for t in tokens:
                threading.Thread(
                    target=send_push,
                    args=(t, username, msg_type, caller, extra),
                    daemon=True,
                ).start()

            self._send_json({"status": "queued", "user": username, "tokens": len(tokens)})
        except Exception as e:
            print(f"[ERR Handler] {e}")
            self._send_json({"error": str(e)}, 500)


# ---------------------------------------------------------------------
# HTTP listener
# ---------------------------------------------------------------------

def start_listener(addr, port):
    try:
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        if family == socket.AF_INET6:
            HTTPServer.address_family = socket.AF_INET6
        server = HTTPServer((addr, port), Handler)
        print(f"[LISTEN] Serving on {addr}:{port}")
        server.serve_forever()
    except OSError as e:
        print(f"[ERROR] Failed to bind {addr}:{port}: {e}")


# ---------------------------------------------------------------------
# CLI helpers (list / delete / activate / etc)
# ---------------------------------------------------------------------

def cli_list_tokens():
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, platform, device_id, active, updated, keepalive_next, keepalive_replay
                FROM fcm_tokens
                ORDER BY updated DESC
                """
            )
            rows = cur.fetchall()
        conn.close()
    except Exception as e:
        print(f"[DB ERR list] {e}")
        return

    print("ID | user | platform | device_id | active | updated | keepalive_next | keepalive_replay")
    print("-" * 110)
    for row in rows:
        tid, user, platform, device_id, active, updated, keepalive_next, keepalive_replay = row
        print(
            f"{tid:4d} | {user:16s} | {platform:7s} | "
            f"{(device_id or '-')[:16]:16s} | {active} | {updated} | "
            f"{keepalive_next} | {keepalive_replay}"
        )


def cli_delete_token(token_id):
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fcm_tokens WHERE id=%s", (token_id,))
            affected = cur.rowcount
        conn.commit()
        conn.close()
        print(f"[CLI] Deleted {affected} rows for id={token_id}")
    except Exception as e:
        print(f"[DB ERR delete] {e}")


def cli_delete_inactive():
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fcm_tokens WHERE active=0")
            affected = cur.rowcount
        conn.commit()
        conn.close()
        print(f"[CLI] Deleted {affected} inactive tokens")
    except Exception as e:
        print(f"[DB ERR delete_inactive] {e}")


def cli_set_active(token_id, active):
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute("UPDATE fcm_tokens SET active=%s WHERE id=%s", (1 if active else 0, token_id))
            affected = cur.rowcount
        conn.commit()
        conn.close()
        print(f"[CLI] Updated {affected} rows for id={token_id} active={active}")
    except Exception as e:
        print(f"[DB ERR set_active] {e}")


def cli_send_by_id(token_id, template_name, body_text=None):
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute("SELECT username, token FROM fcm_tokens WHERE id=%s", (token_id,))
            row = cur.fetchone()
        conn.close()
        if not row:
            print(f"[CLI] Token id={token_id} not found")
            return
        username, token = row
        extra = {"body": body_text} if body_text else {}
        send_push(token, username, template_name, "cli", extra)
        print(f"[CLI] Sent template='{template_name}' to id={token_id} user={username}")
    except Exception as e:
        print(f"[CLI ERR send] {e}")


def cli_add_token(username, token, platform="android", device_id=None):
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fcm_tokens (username, token, platform, device_id, active)
                VALUES (%s,%s,%s,%s,1)
                ON DUPLICATE KEY UPDATE
                    platform=VALUES(platform),
                    device_id=VALUES(device_id),
                    active=1,
                    updated=CURRENT_TIMESTAMP
                """,
                (username, token, platform, device_id),
            )
        conn.commit()
        conn.close()
        print(f"[CLI] Added/updated token for user={username}")
    except Exception as e:
        print(f"[DB ERR add_token] {e}")


def cli_print_stat():
    stats = get_stats_today()
    sys_health = get_system_health()
    print("=== Stats (today) ===")
    for k in sorted(stats.keys()):
        print(f"{k:15s}: {stats[k]}")
    print("\n=== System ===")
    for k in sorted(sys_health.keys()):
        print(f"{k:15s}: {sys_health[k]}")


# ---------------------------------------------------------------------
# Sample config / templates + systemd service
# ---------------------------------------------------------------------

def create_sample_files():
    """Create sample env and templates if they do not exist."""
    env_path = "/etc/fcmpy.env-sample"
    tpl_path = "/etc/fcmpy-templates.json-sample"

    if not os.path.exists(env_path):
        env_sample = """# Sample configuration for fcmpy
SERVICE_ACCOUNT=/var/secrets/fcmpy-service-account.json
LISTEN_ADDR=127.0.0.1
LISTEN_PORT=9090

DB_HOST=localhost
DB_USER=fcmpy
DB_PASS=change_me
DB_NAME=fcmpy

ACCESS_TOKEN=change_me_admin_token
"""
        with open(env_path, "w") as f:
            f.write(env_sample)
        print(f"✅ Created {env_path}")
    else:
        print(f"ℹ {env_path} already exists, not overwriting")

    if not os.path.exists(tpl_path):
        tpl_sample = {
            "call": {
                "title": "Incoming call from {caller}",
                "body": "Tap to open app",
                "priority": "high",
            },
            "message": {
                "title": "New message from {caller}",
                "body": "{body}",
                "priority": "normal",
            },
            "keepalive": {
                "title": "Background sync",
                "body": "Keeping connection alive",
                "priority": "high",
            },
            "default": {
                "title": "Notification",
                "body": "{body}",
                "priority": "normal",
            },
        }
        with open(tpl_path, "w") as f:
            json.dump(tpl_sample, f, indent=2)
        print(f"✅ Created {tpl_path}")
    else:
        print(f"ℹ {tpl_path} already exists, not overwriting")


def install_service():
    """Install systemd unit for fcmpy."""
    service_path = "/etc/systemd/system/fcmpy.service"
    service_text = """[Unit]
Description=Local FCM Push Daemon (fcmpy)
After=network.target mariadb.service mysql.service

[Service]
Type=simple
EnvironmentFile=/etc/fcmpy.env
ExecStart=/usr/bin/python3 /usr/local/bin/fcmpy.py
User=www-data
Group=www-data
Restart=always
RestartSec=3
SyslogIdentifier=fcmpy
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/var/secrets

[Install]
WantedBy=multi-user.target
"""

    try:
        with open(service_path, "w") as f:
            f.write(service_text)
        os.chmod(service_path, 0o644)
        os.system("systemctl daemon-reload")
        os.system("systemctl enable --now fcmpy.service")
        print("✅ Installed and started systemd service fcmpy.service")
    except Exception as e:
        print(f"❌ Failed to install service: {e}")


def uninstall_service():
    """Uninstall systemd unit."""
    service_path = "/etc/systemd/system/fcmpy.service"
    try:
        os.system("systemctl stop fcmpy.service || true")
        os.system("systemctl disable fcmpy.service || true")
        if os.path.exists(service_path):
            os.remove(service_path)
        os.system("systemctl daemon-reload")
        print("✅ Uninstalled fcmpy.service")
    except Exception as e:
        print(f"❌ Uninstall failed: {e}")


def print_help():
    print(
        """
fcmpy - Local FCM push daemon

Usage:
  python3 fcmpy.py               # run daemon
  python3 fcmpy.py --sample      # create sample env/templates
  python3 fcmpy.py --install     # install systemd service
  python3 fcmpy.py --uninstall   # uninstall systemd service

Token management:
  python3 fcmpy.py --list
  python3 fcmpy.py --delete <id>
  python3 fcmpy.py --delete-inactive
  python3 fcmpy.py --deactivate <id>
  python3 fcmpy.py --activate <id>
  python3 fcmpy.py --add <username> <token> [platform] [device_id]
  python3 fcmpy.py --send <id> <template> [body]
  python3 fcmpy.py --stat
"""
    )


# ---------------------------------------------------------------------
# Main daemon entry
# ---------------------------------------------------------------------

def run_daemon():
    if not ensure_service_account_loaded():
        print("❌ Cannot start daemon: service account not configured.")
        sys.exit(1)

    create_database_tables()

    # addresses to listen on (comma-separated)
    listen_addrs = [a.strip() for a in str(args.listen_addr).split(",") if a.strip()]
    if "::1" not in listen_addrs:
        listen_addrs.append("::1")

    listen_port = args.listen_port
    print(
        f"🚀 fcmpy starting on {', '.join(listen_addrs)}:{listen_port} | "
        f"DB={args.db_user}@{args.db_host}/{args.db_name}"
    )

    # cleanup scheduler (daily)
    threading.Thread(target=cleanup_scheduler, daemon=True).start()

    # keepalive scheduler (optional)
    if KEEPALIVE_ENABLED:
        threading.Thread(target=keepalive_scheduler, daemon=True).start()

    # HTTP listeners
    for addr in listen_addrs:
        threading.Thread(target=start_listener, args=(addr, listen_port), daemon=True).start()

    # keep main thread alive
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    # management commands are simple flags; if none -> run daemon
    if len(sys.argv) == 1:
        run_daemon()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd in ("-h", "--help", "help"):
        print_help()
    elif cmd == "--sample":
        create_sample_files()
    elif cmd == "--install":
        install_service()
    elif cmd == "--uninstall":
        uninstall_service()
    elif cmd == "--list":
        cli_list_tokens()
    elif cmd == "--delete":
        if len(sys.argv) < 3:
            print("Usage: --delete <id>")
            sys.exit(1)
        cli_delete_token(int(sys.argv[2]))
    elif cmd == "--delete-inactive":
        cli_delete_inactive()
    elif cmd == "--deactivate":
        if len(sys.argv) < 3:
            print("Usage: --deactivate <id>")
            sys.exit(1)
        cli_set_active(int(sys.argv[2]), False)
    elif cmd == "--activate":
        if len(sys.argv) < 3:
            print("Usage: --activate <id>")
            sys.exit(1)
        cli_set_active(int(sys.argv[2]), True)
    elif cmd == "--send":
        if len(sys.argv) < 4:
            print("Usage: --send <id> <template_name> [body]")
            sys.exit(1)
        token_id = int(sys.argv[2])
        template_name = sys.argv[3]
        body_text = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else None
        cli_send_by_id(token_id, template_name, body_text)
    elif cmd == "--add":
        if len(sys.argv) < 4:
            print("Usage: --add <username> <token> [platform] [device_id]")
            sys.exit(1)
        username = sys.argv[2]
        token = sys.argv[3]
        platform = sys.argv[4] if len(sys.argv) > 4 else "android"
        device_id = sys.argv[5] if len(sys.argv) > 5 else None
        cli_add_token(username, token, platform, device_id)
    elif cmd == "--stat":
        cli_print_stat()
    else:
        print(f"Unknown command: {cmd}")
        print_help()
        sys.exit(1)
