#!/usr/bin/env python3
"""
push-to-turso.py — Push scan results to Turso database + optional home server.

Pushes to Turso (primary). Also pushes to HOME_SERVER_URL if set (backup).
All operations are best-effort with continue-on-error in the workflow.

Usage:
    TURSO_TOKEN=xxx TURSO_DB_URL=libsql://... python3 push-to-turso.py <final_results_dir>

Environment:
    TURSO_TOKEN       — Turso database auth token
    TURSO_DB_URL      — Turso database URL (libsql:// or https://)
    HOME_SERVER_URL   — Optional: URL of home server (e.g. https://scan-db.example.com)
                        If set, all data is also POSTed to {HOME_SERVER_URL}/ingest/*
"""
import json
import os
import sys
import urllib.request
import urllib.error

BATCH_SIZE = 100  # Keeps us under SQLite's 999-parameter limit


# ===================================================================
#  Turso helpers
# ===================================================================

def get_http_url(db_url):
    """Convert libsql:// URL to HTTPS pipeline endpoint."""
    http_url = db_url.replace("libsql://", "https://")
    http_url = http_url.rstrip("/")
    if not http_url.endswith("/v2/pipeline"):
        http_url += "/v2/pipeline"
    return http_url


def turso_pipeline(auth_token, http_url, requests):
    """Execute SQL statements via Turso HTTP API. Returns parsed response or None."""
    payload = json.dumps({"requests": requests}).encode()
    req = urllib.request.Request(
        http_url,
        data=payload,
        headers={
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  Turso HTTP {e.code}: {body[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Turso request error: {e}", file=sys.stderr)
        return None


def turso_sql(auth_token, http_url, sql, args=None):
    """Execute a single SQL statement with optional positional args on Turso."""
    stmt = {"sql": sql}
    if args:
        stmt["args"] = args
    return turso_pipeline(auth_token, http_url, [{"type": "execute", "stmt": stmt}])


# ===================================================================
#  Home server helpers
# ===================================================================

def home_post(home_url, endpoint, data):
    """POST data to home server endpoint. Returns True on success."""
    url = f"{home_url.rstrip('/')}/ingest/{endpoint}"
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  Home server HTTP {e.code}: {body[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Home server error: {e}", file=sys.stderr)
        return None


# ===================================================================
#  Schema
# ===================================================================

SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_date TEXT,
        blocks_processed INTEGER,
        unique_hosts INTEGER,
        potential_cameras INTEGER,
        scan_duration_seconds INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS hosts (
        ip TEXT PRIMARY KEY,
        first_seen TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS http_banners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        port INTEGER,
        title TEXT,
        server TEXT,
        status_code INTEGER,
        url TEXT,
        scan_date TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS cameras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        port INTEGER,
        type TEXT,
        confidence INTEGER,
        source TEXT,
        title TEXT,
        server TEXT,
        url TEXT,
        scan_date TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS whois (
        subnet TEXT PRIMARY KEY,
        org TEXT,
        netname TEXT,
        country TEXT,
        asn TEXT,
        last_updated TEXT DEFAULT (datetime('now'))
    )""",
    "CREATE INDEX IF NOT EXISTS idx_http_banners_scan_date ON http_banners(scan_date)",
    "CREATE INDEX IF NOT EXISTS idx_http_banners_ip ON http_banners(ip)",
    "CREATE INDEX IF NOT EXISTS idx_cameras_scan_date ON cameras(scan_date)",
    "CREATE INDEX IF NOT EXISTS idx_cameras_ip ON cameras(ip)",
    "CREATE INDEX IF NOT EXISTS idx_cameras_confidence ON cameras(confidence DESC)",
]


def init_schema(auth_token, http_url, home_url):
    """Create tables on Turso + home server."""
    print("  Initializing schema on Turso...")
    for sql in SCHEMA_STATEMENTS:
        turso_sql(auth_token, http_url, sql)

    if home_url:
        # Home server auto-creates schema on startup, just health-check it
        try:
            req = urllib.request.Request(f"{home_url.rstrip('/')}/health")
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = json.loads(resp.read())
            print(f"  Home server schema OK: {status.get('status')}")
        except Exception as e:
            print(f"  Home server health check failed: {e}", file=sys.stderr)


# ===================================================================
#  Insert functions — push to Turso + home server
# ===================================================================

def insert_scan_record(auth_token, http_url, home_url, results_dir):
    """Record this scan run on Turso + home server."""
    summary_file = os.path.join(results_dir, "scan_summary.json")
    if not os.path.exists(summary_file):
        print("  No scan_summary.json found, skipping scan record")
        return

    try:
        with open(summary_file) as f:
            summary = json.load(f)
    except Exception as e:
        print(f"  Failed to read scan summary: {e}", file=sys.stderr)
        return

    # Turso
    sql = """INSERT INTO scans (scan_date, blocks_processed, unique_hosts, potential_cameras, scan_duration_seconds)
             VALUES (?, ?, ?, ?, ?)"""
    args = [
        summary.get("scan_date", ""),
        summary.get("blocks_processed", 0),
        summary.get("unique_hosts_found", 0),
        summary.get("potential_cameras", 0),
        summary.get("scan_duration_seconds", 0),
    ]
    if turso_sql(auth_token, http_url, sql, args):
        print(f"  Scan record pushed to Turso: {summary.get('scan_date', '?')}")

    # Home server
    if home_url:
        home_post(home_url, "scans", {
            "scan_date": summary.get("scan_date", ""),
            "blocks_processed": summary.get("blocks_processed", 0),
            "unique_hosts": summary.get("unique_hosts_found", 0),
            "potential_cameras": summary.get("potential_cameras", 0),
            "scan_duration_seconds": summary.get("scan_duration_seconds", 0),
        })


def insert_hosts(auth_token, http_url, home_url, results_dir):
    """Upsert all live hosts on Turso + home server."""
    hosts_file = os.path.join(results_dir, "all_hosts.txt")
    if not os.path.exists(hosts_file):
        print("  No all_hosts.txt found, skipping")
        return

    print("  Inserting hosts...")
    ips = []
    with open(hosts_file) as f:
        for line in f:
            ip = line.strip()
            if ip:
                ips.append(ip)

    # Turso (batched)
    turso_total = 0
    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, datetime('now'), datetime('now'))"] * len(batch))
        sql = f"""INSERT INTO hosts (ip, first_seen, last_seen) VALUES {placeholders}
                  ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen"""
        if turso_sql(auth_token, http_url, sql, batch):
            turso_total += len(batch)
    print(f"  {turso_total} hosts pushed to Turso")

    # Home server (single POST — it handles batching internally)
    if home_url:
        home_post(home_url, "hosts", {"hosts": ips})


def insert_http_banners(auth_token, http_url, home_url, results_dir, scan_date):
    """Insert HTTP banner data on Turso + home server."""
    banners_file = os.path.join(results_dir, "all_http_banners.json")
    if not os.path.exists(banners_file):
        print("  No all_http_banners.json found, skipping")
        return

    print("  Inserting HTTP banners...")
    rows = []
    with open(banners_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = entry.get("host", entry.get("ip", ""))
            port = entry.get("port", 0)
            title = entry.get("title", "") or ""
            server = entry.get("server", "") or ""
            status = entry.get("status_code", 0)
            url = entry.get("url", "") or ""
            if not ip:
                continue
            rows.append((ip, port, title, server, status, url, scan_date))

    # Turso (batched)
    turso_total = 0
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, ?, ?, ?, ?, ?, ?)"] * len(batch))
        sql = f"INSERT INTO http_banners (ip, port, title, server, status_code, url, scan_date) VALUES {placeholders}"
        args = [val for row in batch for val in row]
        if turso_sql(auth_token, http_url, sql, args):
            turso_total += len(batch)
    print(f"  {turso_total} HTTP banners pushed to Turso")

    # Home server
    if home_url:
        banner_list = [
            {"ip": r[0], "port": r[1], "title": r[2], "server": r[3],
             "status_code": r[4], "url": r[5], "scan_date": r[6]}
            for r in rows
        ]
        home_post(home_url, "banners", {"banners": banner_list})


def insert_cameras(auth_token, http_url, home_url, results_dir, scan_date):
    """Insert camera detections on Turso + home server."""
    candidates = [
        os.path.join(results_dir, "all_cameras.json"),
        os.path.join(results_dir, "all_cameras_enriched.json"),
        os.path.join(os.path.dirname(results_dir), "camera_report", "all_cameras_enriched.json"),
    ]
    cam_file = None
    for c in candidates:
        if os.path.exists(c):
            cam_file = c
            break
    if not cam_file:
        print("  No camera data found, skipping")
        return

    print(f"  Inserting camera detections (from {os.path.basename(cam_file)})...")
    try:
        with open(cam_file) as f:
            content = f.read().strip()
            if content.startswith("["):
                items = json.loads(content)
            else:
                items = []
                for line in content.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            items.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    except Exception as e:
        print(f"  Failed to read camera file: {e}", file=sys.stderr)
        return

    rows = []
    for entry in items:
        if isinstance(entry, str):
            try:
                entry = json.loads(entry)
            except json.JSONDecodeError:
                continue
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip", "")
        port = entry.get("port", 0)
        ctype = entry.get("type", "camera")
        confidence = entry.get("confidence", 0)
        source = entry.get("source", "scan")
        title = entry.get("title", "") or ""
        server = entry.get("server", "") or ""
        url = entry.get("url", "") or ""
        if not ip:
            continue
        rows.append((ip, port, ctype, confidence, source, title, server, url, scan_date))

    # Turso (batched)
    turso_total = 0
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, ?, ?, ?, ?, ?, ?, ?, ?)"] * len(batch))
        sql = "INSERT INTO cameras (ip, port, type, confidence, source, title, server, url, scan_date) VALUES " + placeholders
        args = [val for row in batch for val in row]
        if turso_sql(auth_token, http_url, sql, args):
            turso_total += len(batch)
    print(f"  {turso_total} cameras pushed to Turso")

    # Home server
    if home_url:
        cam_list = [
            {"ip": r[0], "port": r[1], "type": r[2], "confidence": r[3],
             "source": r[4], "title": r[5], "server": r[6], "url": r[7], "scan_date": r[8]}
            for r in rows
        ]
        home_post(home_url, "cameras", {"cameras": cam_list})


def insert_whois(auth_token, http_url, home_url, results_dir):
    """Upsert WHOIS data on Turso + home server."""
    whois_file = os.path.join(results_dir, "all_whois.json")
    if not os.path.exists(whois_file):
        print("  No all_whois.json found, skipping")
        return

    print("  Inserting WHOIS data...")
    rows = []
    with open(whois_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            subnet = entry.get("subnet", "")
            org = entry.get("org", "") or ""
            netname = entry.get("netname", "") or ""
            country = entry.get("country", "") or ""
            asn = entry.get("asn", "") or ""
            if not subnet:
                continue
            rows.append((subnet, org, netname, country, asn))

    # Turso (batched)
    turso_total = 0
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, ?, ?, ?, ?, datetime('now'))"] * len(batch))
        sql = f"""INSERT INTO whois (subnet, org, netname, country, asn, last_updated)
                  VALUES {placeholders}
                  ON CONFLICT(subnet) DO UPDATE SET
                      org = excluded.org,
                      netname = excluded.netname,
                      country = excluded.country,
                      asn = excluded.asn,
                      last_updated = excluded.last_updated"""
        args = [val for row in batch for val in row]
        if turso_sql(auth_token, http_url, sql, args):
            turso_total += len(batch)
    print(f"  {turso_total} WHOIS records pushed to Turso")

    # Home server
    if home_url:
        whois_list = [
            {"subnet": r[0], "org": r[1], "netname": r[2], "country": r[3], "asn": r[4]}
            for r in rows
        ]
        home_post(home_url, "whois", {"whois": whois_list})


# ===================================================================
#  Main
# ===================================================================

def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "final_results"

    auth_token = os.environ.get("TURSO_TOKEN", "")
    db_url = os.environ.get("TURSO_DB_URL", "")
    home_url = os.environ.get("HOME_SERVER_URL", "")

    if not auth_token or not db_url:
        print("Skipping Turso push: TURSO_TOKEN and TURSO_DB_URL not both set", file=sys.stderr)
    else:
        http_url = get_http_url(db_url)
        print(f"Pushing scan results to Turso...")
        print(f"  HTTP endpoint: {http_url}")

    if home_url:
        print(f"Also pushing to home server: {home_url}")
    else:
        print("No HOME_SERVER_URL set — skipping home server backup")

    if not auth_token or not db_url:
        # No Turso configured — nothing to do
        return

    # Get scan date for reference
    scan_date = ""
    summary_file = os.path.join(results_dir, "scan_summary.json")
    if os.path.exists(summary_file):
        try:
            with open(summary_file) as f:
                summary = json.load(f)
            scan_date = summary.get("scan_date", "")
        except Exception:
            pass

    # Initialize schema
    init_schema(auth_token, http_url, home_url)

    # Push data in order
    insert_scan_record(auth_token, http_url, home_url, results_dir)
    insert_hosts(auth_token, http_url, home_url, results_dir)
    insert_http_banners(auth_token, http_url, home_url, results_dir, scan_date)
    insert_cameras(auth_token, http_url, home_url, results_dir, scan_date)
    insert_whois(auth_token, http_url, home_url, results_dir)

    print("Done — scan results pushed!")


if __name__ == "__main__":
    main()
