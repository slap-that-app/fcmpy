# fcmpy

Small Python daemon + CLI for sending Firebase Cloud Messaging (FCM) HTTP v1 pushes
from local services (SIP proxy, XMPP server, whatever) using a simple HTTP API
and a MySQL / MariaDB backend.

It also supports optional "keepalive" pings: one random FCM data push per day,
per active device, to let mobile apps refresh tokens or sessions. If the app
stops replying to keepalives for more than 7 days, fcmpy automatically stops
sending them.

---

## Features

- HTTP API for sending FCM HTTP v1 messages
- MySQL / MariaDB storage for device tokens
- Per-username multiple tokens, platforms, device IDs
- JWT-based access to FCM (service account JSON)
- Daily log cleanup + aggregated daily stats
- Optional keepalive scheduler:
    - per-device random-time ping once per day
    - stops after `keepalive_replay` is older than 7 days
- CLI tools:
    - `--list`, `--delete`, `--delete-inactive`, `--activate`, `--deactivate`
    - `--add` to register tokens
    - `--send` to test templates
    - `--stat` to view stats
    - `--sample` to create sample config files
    - `--install`, `--uninstall` systemd service

---

## Architecture

- `fcmpy.py`
    - when run without arguments: starts daemon
    - when run with `--*` arguments: acts as a CLI tool
- Database tables:
    - `fcm_tokens`: tokens, platforms, keepalive metadata
    - `fcm_push_log`: push logs
    - `fcm_stats_daily`: daily aggregates

---

## Requirements

- Python 3.8+
- Packages:
    - `requests`
    - `PyJWT`
    - `pymysql`
    - `psutil`
- MySQL / MariaDB
- Firebase project + service account JSON with
  `https://www.googleapis.com/auth/firebase.messaging` scope.

Install packages:

```bash
apt install python3 python3-pip python3-psutil
pip install requests PyJWT pymysql
```

## Configuration

fcmpy reads settings from environment variables or from a systemd-style env
file, typically `/etc/fcmpy.env`.

Example `/etc/fcmpy.env`:

    SERVICE_ACCOUNT=/var/secrets/fcmpy-service-account.json
    LISTEN_ADDR=127.0.0.1
    LISTEN_PORT=9090

    DB_HOST=localhost
    DB_USER=fcmpy
    DB_PASS=change_me
    DB_NAME=fcmpy

    ACCESS_TOKEN=change_me_admin_token

You can generate sample files with:

    python3 fcmpy.py --sample

This creates:

    /etc/fcmpy.env-sample
    /etc/fcmpy-templates.json-sample

Then copy and edit them as needed:

    cp /etc/fcmpy.env-sample /etc/fcmpy.env
    cp /etc/fcmpy-templates.json-sample /etc/fcmpy-templates.json
    chmod 600 /etc/fcmpy.env


## Database schema

`fcmpy.py` can create / patch the tables automatically on start, but the main
`fcm_tokens` table looks like this:

    CREATE TABLE `fcm_tokens` (
        `id` INT(11) NOT NULL AUTO_INCREMENT,
        `username` VARCHAR(64) NOT NULL,
        `token` VARCHAR(255) NOT NULL,
        `device_id` VARCHAR(64) DEFAULT NULL,
        `platform` ENUM('android','ios','web') DEFAULT 'android',
        `active` TINYINT(1) DEFAULT 1,
        `keepalive_last` DATETIME NULL DEFAULT NULL,
        `keepalive_next` DATETIME NULL DEFAULT NULL,
        `keepalive_replay` DATETIME NULL DEFAULT NULL,
        `updated` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                 ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uniq_user_token` (`username`, `token`),
        KEY `idx_keepalive_next` (`keepalive_next`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

Other tables used by fcmpy:

    CREATE TABLE `fcm_push_log` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `username` VARCHAR(64) NOT NULL,
        `caller` VARCHAR(64),
        `msg_type` VARCHAR(32),
        `token_hash` CHAR(12),
        `http_code` INT,
        `status` VARCHAR(64),
        `msg` TEXT,
        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE `fcm_stats_daily` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `date` DATE NOT NULL UNIQUE,
        `sent_ok` INT DEFAULT 0,
        `sent_fail` INT DEFAULT 0,
        `cleaned` INT DEFAULT 0,
        `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

## Templates

Templates live in `/etc/fcmpy-templates.json`. They define how each message
type is turned into an FCM payload. Placeholders like `{caller}`, `{body}`,
`{username}` are filled by fcmpy before sending.

Minimal example:

    {
      "call": {
        "title": "Incoming call from {caller}",
        "body": "Tap to open app",
        "priority": "high"
      },
      "message": {
        "title": "New message from {caller}",
        "body": "{body}",
        "priority": "normal"
      },
      "keepalive": {
        "title": "Background sync",
        "body": "Keeping connection alive",
        "priority": "high"
      },
      "default": {
        "title": "Notification",
        "body": "{body}",
        "priority": "normal"
      }
    }

fcmpy will pick a template by `type` (e.g. `call`, `message`, `keepalive`),
falling back to `default` if the template is not found.

## Running the daemon

Copy `fcmpy.py` to some directory (for example `/usr/local/bin/fcmpy.py`):

    cp fcmpy.py /usr/local/bin/fcmpy.py
    chmod +x /usr/local/bin/fcmpy.py

Run in foreground for testing:

    python3 /usr/local/bin/fcmpy.py

The daemon will:

- Load Firebase service account JSON
- Connect to the database and create tables if needed
- Start HTTP listeners on `LISTEN_ADDR:LISTEN_PORT`
- Start background threads for:
  - Daily log cleanup and stats
  - Keepalive scheduler (if enabled)

### Systemd service

To install the service:

    python3 fcmpy.py --install

This creates and enables `/etc/systemd/system/fcmpy.service`.

Check logs:

    journalctl -u fcmpy.service -f

To uninstall:

    python3 fcmpy.py --uninstall


## HTTP API

By default, fcmpy listens on `LISTEN_ADDR:LISTEN_PORT`
(for example `127.0.0.1:9090`).

### Health check

    curl http://127.0.0.1:9090/

Response:

    {"status":"ok","msg":"fcmpy daemon running"}

### Stats

    curl http://127.0.0.1:9090/stats

Returns JSON with:

- today's in-memory stats (`sent_ok`, `sent_fail`, `cleaned`)
- DB-backed daily stats
- system health (uptime, load, memory, db_connected)

### Send push

Main POST endpoint uses `application/x-www-form-urlencoded` body.

Parameters:

- `username` – logical user ID (string)
- `type` – template name (`call`, `message`, `keepalive`, `default`, etc.)
- `from` – “caller” or any label
- `body` – optional text for `{body}` placeholder

Example:

    curl -X POST http://127.0.0.1:9090 \
      -d "username=alice&type=message&from=bob&body=Hello%20world"

fcmpy will:

1. Look up all `active=1` tokens for `username = 'alice'`
2. For each token:
  - Choose the `message` template
  - Substitute placeholders
  - Send FCM HTTP v1 request

### Reload

There is also a `/reload` POST endpoint to reload templates, service account
and test DB connectivity. To protect it, you can require `ACCESS_TOKEN` via:

- `X-Access-Key` header, or
- `?token=...` query parameter.


## Keepalive behaviour

fcmpy has an optional keepalive scheduler controlled by a boolean flag in
the code (`KEEPALIVE_ENABLED`) and a maximum silence window
(`KEEPALIVE_MAX_SILENCE_DAYS`, default 7).

Algorithm:

1. For each `active=1` token:
  - If `keepalive_next` is `NULL` and either:
    - `keepalive_replay` is `NULL`, or
    - `keepalive_replay >= NOW() - 7 days`
      then fcmpy sets `keepalive_next` to a **random time tomorrow**.
2. Every minute the scheduler:
  - Finds tokens where:
    - `active = 1`
    - `keepalive_next <= NOW()`
    - `keepalive_replay` is `NULL` or not older than 7 days
  - Sends a `keepalive` push for each token
  - Updates:
    - `keepalive_last = NOW()`
    - `keepalive_next = random time tomorrow`

App-side behaviour (recommended):

- Data-only FCM with `type="keepalive"` wakes the app.
- App performs a small HTTP request back to your backend, for example
  `POST /keepalive-reply`.
- Your backend (PHP, etc.) updates `keepalive_replay` for that token.
  The provided PHP helper does this with:

      $mgr->markKeepaliveReplyByToken($token);

If the app does **not** reply for more than 7 days:

- `keepalive_replay` becomes older than `NOW() - 7 days`.
- The keepalive scheduler stops selecting that token.
- No more background pings for that device until you update
  `keepalive_replay` or re-register the token.


## CLI usage

All CLI commands are run against the same config / DB. When you run
`fcmpy.py` with a `--*` flag, it acts as a one-shot management tool
instead of starting the daemon.

### List tokens

    python3 fcmpy.py --list

Shows:

- id
- username
- platform
- device_id
- active
- updated
- keepalive_next
- keepalive_replay

### Delete tokens

Delete by numeric id:

    python3 fcmpy.py --delete 42

Delete all inactive tokens:

    python3 fcmpy.py --delete-inactive

### Activate / deactivate token

    python3 fcmpy.py --deactivate 42
    python3 fcmpy.py --activate 42

### Add or update a token

    python3 fcmpy.py --add <username> <token> [platform] [device_id]

Example:

    python3 fcmpy.py --add alice AAAA12345 android device123

If the `(username, token)` pair already exists, fcmpy updates platform,
device_id and sets `active=1`.

### Send test notification

Send a test push for a specific token row:

    python3 fcmpy.py --send <id> <template_name> [body]

Example:

    python3 fcmpy.py --send 42 message "Hello from CLI"

This uses the template `message` from `fcmpy-templates.json`,
substitutes `{body}` and sends to the token stored in row `id=42`.

### Stats

Show compact stats + system health:

    python3 fcmpy.py --stat

Output includes:

- `sent_ok`, `sent_fail`, `cleaned` for today (in memory + DB)
- uptime, CPU load, memory usage, DB connectivity flag.


## PHP helper

A small PHP class is provided to simplify integration with web applications
using PDO. It manages token registration, activation, deletion and
keepalive replies.

Example class file: `FcmTokenManager.php`

Basic table (matches fcmpy):

    CREATE TABLE `fcm_tokens` (
        `id` INT(11) NOT NULL AUTO_INCREMENT,
        `username` VARCHAR(64) NOT NULL,
        `token` VARCHAR(255) NOT NULL,
        `device_id` VARCHAR(64) DEFAULT NULL,
        `platform` ENUM('android','ios','web') DEFAULT 'android',
        `active` TINYINT(1) DEFAULT 1,
        `keepalive_last` DATETIME NULL DEFAULT NULL,
        `keepalive_next` DATETIME NULL DEFAULT NULL,
        `keepalive_replay` DATETIME NULL DEFAULT NULL,
        `updated` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                 ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uniq_user_token` (`username`, `token`),
        KEY `idx_keepalive_next` (`keepalive_next`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

Minimal usage:

    <?php
    require 'FcmTokenManager.php';

    $pdo = new PDO(
        'mysql:host=localhost;dbname=fcmpy;charset=utf8mb4',
        'fcmpy',
        'change_me',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]
    );

    $mgr = new FcmTokenManager($pdo);

    // Register or update token
    $mgr->save('alice', 'AAAA12345', 'device123', 'android');

    // Get all active tokens for user
    $list = $mgr->getByUsername('alice');

    // Deactivate a token
    $mgr->deactivate('AAAA12345');

    // Cleanup inactive tokens older than 30 days
    $removed = $mgr->cleanupInactive(30);

    // Mark keepalive reply (e.g. in /keepalive-reply endpoint)
    $mgr->markKeepaliveReplyByToken('AAAA12345');

## Credits

This project were drafted with the assistance of an AI coding assistant (ChatGPT).
