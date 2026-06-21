#!/usr/bin/env python3
"""
push-to-turso.py — Push scan results to the Turso database.

Reads final scan results and upserts them into Turso via the HTTP API (v2/pipeline).
All data operations are best-effort with continue-on-error in the workflow.

Usage:
    TURSO_TOKEN=xxx TURSO_DB_URL=libsql://... python3 push-to-turso.py <final_results_dir>

Environment:
    TURSO_TOKEN    — Turso database auth token
    TURSO_DB_URL   — Turso database URL (libsql:// or https://)
"""
import json
import os
import sys
import urllib.request
import urllib.error

BATCH_SIZE = 100  # Keeps us under SQLite's 999-parameter limit


def get_http_url(db_url):
    """Convert libsql:// URL to HTTPS pipeline endpoint."""
    http_url = db_url.replace("libsql://", "https://")
    http_url = http_url.rstrip("/")
    if not http_url.endswith("/v2/pipeline"):
        http_url += "/v2/pipeline"
    return http_url


def pipeline(auth_token, http_url, requests):
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
        # Log but don't crash — this is best-effort
        print(f"  HTTP {e.code}: {body[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Request error: {e}", file=sys.stderr)
        return None


def exec_sql(auth_token, http_url, sql, args=None):
    """Execute a single SQL statement with optional positional args."""
    stmt = {"sql": sql}
    if args:
        stmt["args"] = args
    return pipeline(auth_token, http_url, [{"type": "execute", "stmt": stmt}])


def init_schema(auth_token, http_url):
    """Create tables if they don't exist."""
    print("  Initializing schema...")
    statements = [
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
        """CREATE INDEX IF NOT EXISTS idx_http_banners_scan_date
            ON http_banners(scan_date)""",
        """CREATE INDEX IF NOT EXISTS idx_http_banners_ip
            ON http_banners(ip)""",
        """CREATE INDEX IF NOT EXISTS idx_cameras_scan_date
            ON cameras(scan_date)""",
        """CREATE INDEX IF NOT EXISTS idx_cameras_ip
            ON cameras(ip)""",
        """CREATE INDEX IF NOT EXISTS idx_cameras_confidence
            ON cameras(confidence DESC)""",
    ]
    results = []
    for sql in statements:
        r = exec_sql(auth_token, http_url, sql)
        if r:
            results.append(r)
    if results:
        print("  Schema OK")
    else:
        print("  Schema init returned no results (tables likely already exist)")


def insert_scan_record(auth_token, http_url, results_dir):
    """Record this scan run."""
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

    sql = """INSERT INTO scans (scan_date, blocks_processed, unique_hosts, potential_cameras, scan_duration_seconds)
             VALUES (?, ?, ?, ?, ?)"""
    args = [
        summary.get("scan_date", ""),
        summary.get("blocks_processed", 0),
        summary.get("unique_hosts_found", 0),
        summary.get("potential_cameras", 0),
        summary.get("scan_duration_seconds", 0),
    ]
    r = exec_sql(auth_token, http_url, sql, args)
    if r:
        print(f"  Scan record inserted: {summary.get('scan_date', '?')}")


def insert_hosts(auth_token, http_url, results_dir):
    """Upsert all live hosts (ip → last_seen updated each run)."""
    hosts_file = os.path.join(results_dir, "all_hosts.txt")
    if not os.path.exists(hosts_file):
        print("  No all_hosts.txt found, skipping")
        return

    print("  Inserting hosts...")
    # Read all IPs
    ips = []
    with open(hosts_file) as f:
        for line in f:
            ip = line.strip()
            if ip:
                ips.append(ip)

    total = 0
    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, datetime('now'), datetime('now'))"] * len(batch))
        sql = f"""INSERT INTO hosts (ip, first_seen, last_seen) VALUES {placeholders}
                  ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen"""
        args = batch  # each ? gets an IP
        r = exec_sql(auth_token, http_url, sql, args)
        if r:
            total += len(batch)

    print(f"  {total} hosts upserted")


def insert_http_banners(auth_token, http_url, results_dir, scan_date):
    """Insert HTTP banner data from httpx results."""
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

    total = 0
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, ?, ?, ?, ?, ?, ?)"] * len(batch))
        sql = f"INSERT INTO http_banners (ip, port, title, server, status_code, url, scan_date) VALUES {placeholders}"
        args = [val for row in batch for val in row]
        r = exec_sql(auth_token, http_url, sql, args)
        if r:
            total += len(batch)

    print(f"  {total} HTTP banners inserted")


def insert_cameras(auth_token, http_url, results_dir, scan_date):
    """Insert camera detections."""
    # Try multiple possible locations
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
                # NDJSON: one JSON object per line
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

    total = 0
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        placeholders = ", ".join(["(?, ?, ?, ?, ?, ?, ?, ?, ?)"] * len(batch))
        sql = """INSERT INTO cameras (ip, port, type, confidence, source, title, server, url, scan_date)
                 VALUES """ + placeholders
        args = [val for row in batch for val in row]
        r = exec_sql(auth_token, http_url, sql, args)
        if r:
            total += len(batch)

    print(f"  {total} cameras inserted")


def insert_whois(auth_token, http_url, results_dir):
    """Upsert WHOIS data per subnet."""
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

    total = 0
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
        r = exec_sql(auth_token, http_url, sql, args)
        if r:
            total += len(batch)

    print(f"  {total} WHOIS records upserted")


def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "final_results"

    auth_token = os.environ.get("TURSO_TOKEN", "")
    db_url = os.environ.get("TURSO_DB_URL", "")

    if not auth_token or not db_url:
        print("Skipping Turso push: TURSO_TOKEN and TURSO_DB_URL not both set", file=sys.stderr)
        return  # Not an error — optional step

    http_url = get_http_url(db_url)
    print(f"Pushing scan results to Turso...")
    print(f"  HTTP endpoint: {http_url}")

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
    init_schema(auth_token, http_url)

    # Push data in order
    insert_scan_record(auth_token, http_url, results_dir)
    insert_hosts(auth_token, http_url, results_dir)
    insert_http_banners(auth_token, http_url, results_dir, scan_date)
    insert_cameras(auth_token, http_url, results_dir, scan_date)
    insert_whois(auth_token, http_url, results_dir)

    print("Done — scan results pushed to Turso!")


if __name__ == "__main__":
    main()
