#!/usr/bin/env python3
"""
push-to-turso.py — Push scan results to Turso database + optional home server.

Independently pushes to ALL configured destinations. If one fails, others still
get their data. Never let one destination's failure block another.

Usage:
    TURSO_TOKEN=xxx TURSO_DB_URL=libsql://... python3 push-to-turso.py <final_results_dir>

Environment:
    TURSO_TOKEN       — Turso database auth token
    TURSO_DB_URL      — Turso database URL (libsql:// or https://)
    HOME_SERVER_URL   — URL of home server (e.g. https://scan-db.example.com)
                        All data is POSTed to {HOME_SERVER_URL}/ingest/*
"""
import json
import os
import sys
import urllib.request
import urllib.error

BATCH_SIZE = 100


# ===================================================================
#  Data collection — reads results ONCE, returns structured dicts
# ===================================================================

def collect_data(results_dir):
    """Read all result files and return structured data for pushing."""
    data = {}

    # Scan record
    summary_file = os.path.join(results_dir, "scan_summary.json")
    if os.path.exists(summary_file):
        try:
            with open(summary_file) as f:
                summary = json.load(f)
            data["scan"] = {
                "scan_date": summary.get("scan_date", ""),
                "blocks_processed": summary.get("blocks_processed", 0),
                "unique_hosts": summary.get("unique_hosts_found", 0),
                "potential_cameras": summary.get("potential_cameras", 0),
                "scan_duration_seconds": summary.get("scan_duration_seconds", 0),
            }
        except Exception as e:
            print(f"  Failed to read scan summary: {e}", file=sys.stderr)

    # Hosts
    hosts_file = os.path.join(results_dir, "all_hosts.txt")
    if os.path.exists(hosts_file):
        with open(hosts_file) as f:
            data["hosts"] = [line.strip() for line in f if line.strip()]
    else:
        print("  No all_hosts.txt found, skipping hosts")

    # HTTP banners
    banners_file = os.path.join(results_dir, "all_http_banners.json")
    if os.path.exists(banners_file):
        data["banners"] = []
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
                scan_date = data.get("scan", {}).get("scan_date", "")
                if ip:
                    data["banners"].append({
                        "ip": ip, "port": port, "title": title,
                        "server": server, "status_code": status,
                        "url": url, "scan_date": scan_date,
                    })
    else:
        print("  No all_http_banners.json found, skipping HTTP banners")

    # Cameras
    cam_candidates = [
        os.path.join(results_dir, "all_cameras.json"),
        os.path.join(results_dir, "all_cameras_enriched.json"),
        os.path.join(os.path.dirname(results_dir), "camera_report", "all_cameras_enriched.json"),
    ]
    cam_file = None
    for c in cam_candidates:
        if os.path.exists(c):
            cam_file = c
            break
    if cam_file:
        try:
            with open(cam_file) as f:
                content = f.read().strip()
                if content.startswith("["):
                    items = json.loads(content)
                else:
                    items = [json.loads(line) for line in content.split("\n") if line.strip()]
            data["cameras"] = []
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
                scan_date = data.get("scan", {}).get("scan_date", "")
                if ip:
                    data["cameras"].append({
                        "ip": ip, "port": port, "type": ctype,
                        "confidence": confidence, "source": source,
                        "title": title, "server": server,
                        "url": url, "scan_date": scan_date,
                    })
        except Exception as e:
            print(f"  Failed to read camera file: {e}", file=sys.stderr)
    else:
        print("  No camera data found, skipping cameras")

    # WHOIS
    whois_file = os.path.join(results_dir, "all_whois.json")
    if os.path.exists(whois_file):
        data["whois"] = []
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
                if subnet:
                    data["whois"].append({
                        "subnet": subnet, "org": org, "netname": netname,
                        "country": country, "asn": asn,
                    })
    else:
        print("  No all_whois.json found, skipping WHOIS")

    return data


# ===================================================================
#  Turso push — fully isolated
# ===================================================================

def get_http_url(db_url):
    http_url = db_url.replace("libsql://", "https://")
    http_url = http_url.rstrip("/")
    if not http_url.endswith("/v2/pipeline"):
        http_url += "/v2/pipeline"
    return http_url


def turso_api(auth_token, http_url, requests):
    payload = json.dumps({"requests": requests}).encode()
    req = urllib.request.Request(
        http_url, data=payload,
        headers={
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  Turso HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Turso error: {e}", file=sys.stderr)
        return None


def turso_sql(auth_token, http_url, sql, args=None):
    stmt = {"sql": sql}
    if args:
        stmt["args"] = args
    return turso_api(auth_token, http_url, [{"type": "execute", "stmt": stmt}])


def push_to_turso(auth_token, db_url, data):
    """Push all data to Turso. Errors are logged but never thrown."""
    try:
        http_url = get_http_url(db_url)
        print("\n--- Pushing to Turso ---")

        # Schema
        schema = [
            "CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_date TEXT, blocks_processed INTEGER, unique_hosts INTEGER, potential_cameras INTEGER, scan_duration_seconds INTEGER, created_at TEXT DEFAULT (datetime('now')))",
            "CREATE TABLE IF NOT EXISTS hosts (ip TEXT PRIMARY KEY, first_seen TEXT DEFAULT (datetime('now')), last_seen TEXT DEFAULT (datetime('now')))",
            "CREATE TABLE IF NOT EXISTS http_banners (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, title TEXT, server TEXT, status_code INTEGER, url TEXT, scan_date TEXT, created_at TEXT DEFAULT (datetime('now')))",
            "CREATE TABLE IF NOT EXISTS cameras (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, type TEXT, confidence INTEGER, source TEXT, title TEXT, server TEXT, url TEXT, scan_date TEXT, created_at TEXT DEFAULT (datetime('now')))",
            "CREATE TABLE IF NOT EXISTS whois (subnet TEXT PRIMARY KEY, org TEXT, netname TEXT, country TEXT, asn TEXT, last_updated TEXT DEFAULT (datetime('now')))",
            "CREATE INDEX IF NOT EXISTS idx_banners_scan_date ON http_banners(scan_date)",
            "CREATE INDEX IF NOT EXISTS idx_banners_ip ON http_banners(ip)",
            "CREATE INDEX IF NOT EXISTS idx_cameras_scan_date ON cameras(scan_date)",
            "CREATE INDEX IF NOT EXISTS idx_cameras_ip ON cameras(ip)",
            "CREATE INDEX IF NOT EXISTS idx_cameras_confidence ON cameras(confidence DESC)",
        ]
        for sql in schema:
            turso_sql(auth_token, http_url, sql)

        # Scan record
        if "scan" in data:
            s = data["scan"]
            turso_sql(auth_token, http_url,
                "INSERT INTO scans (scan_date, blocks_processed, unique_hosts, potential_cameras, scan_duration_seconds) VALUES (?, ?, ?, ?, ?)",
                [s["scan_date"], s["blocks_processed"], s["unique_hosts"], s["potential_cameras"], s["scan_duration_seconds"]])
            print(f"  Turso: scan record inserted: {s['scan_date']}")

        # Hosts (batched)
        if "hosts" in data:
            total = 0
            ips = data["hosts"]
            for i in range(0, len(ips), BATCH_SIZE):
                batch = ips[i:i + BATCH_SIZE]
                ph = ", ".join(["(?, datetime('now'), datetime('now'))"] * len(batch))
                if turso_sql(auth_token, http_url,
                    f"INSERT INTO hosts (ip, first_seen, last_seen) VALUES {ph} ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen",
                    batch):
                    total += len(batch)
            print(f"  Turso: {total} hosts upserted")

        # HTTP banners (batched)
        if "banners" in data:
            total = 0
            for i in range(0, len(data["banners"]), BATCH_SIZE):
                batch = data["banners"][i:i + BATCH_SIZE]
                ph = ", ".join(["(?, ?, ?, ?, ?, ?, ?)"] * len(batch))
                args = [v for b in batch for v in [b["ip"], b["port"], b["title"], b["server"], b["status_code"], b["url"], b["scan_date"]]]
                sql = f"INSERT INTO http_banners (ip, port, title, server, status_code, url, scan_date) VALUES {ph}"
                if turso_sql(auth_token, http_url, sql, args):
                    total += len(batch)
            print(f"  Turso: {total} HTTP banners inserted")

        # Cameras (batched)
        if "cameras" in data:
            total = 0
            for i in range(0, len(data["cameras"]), BATCH_SIZE):
                batch = data["cameras"][i:i + BATCH_SIZE]
                ph = ", ".join(["(?, ?, ?, ?, ?, ?, ?, ?, ?)"] * len(batch))
                args = [v for b in batch for v in [b["ip"], b["port"], b["type"], b["confidence"], b["source"], b["title"], b["server"], b["url"], b["scan_date"]]]
                sql = f"INSERT INTO cameras (ip, port, type, confidence, source, title, server, url, scan_date) VALUES {ph}"
                if turso_sql(auth_token, http_url, sql, args):
                    total += len(batch)
            print(f"  Turso: {total} cameras inserted")

        # WHOIS (batched upsert)
        if "whois" in data:
            total = 0
            for i in range(0, len(data["whois"]), BATCH_SIZE):
                batch = data["whois"][i:i + BATCH_SIZE]
                ph = ", ".join(["(?, ?, ?, ?, ?, datetime('now'))"] * len(batch))
                args = [v for b in batch for v in [b["subnet"], b["org"], b["netname"], b["country"], b["asn"]]]
                sql = f"""INSERT INTO whois (subnet, org, netname, country, asn, last_updated) VALUES {ph}
                          ON CONFLICT(subnet) DO UPDATE SET org=excluded.org, netname=excluded.netname, country=excluded.country, asn=excluded.asn, last_updated=excluded.last_updated"""
                if turso_sql(auth_token, http_url, sql, args):
                    total += len(batch)
            print(f"  Turso: {total} WHOIS records upserted")

        return True
    except Exception as e:
        print(f"  Turso push failed (continuing to next destination): {e}", file=sys.stderr)
        return False


# ===================================================================
#  Home server push — fully isolated
# ===================================================================

def home_api(home_url, endpoint, data):
    url = f"{home_url.rstrip('/')}/ingest/{endpoint}"
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  Home server HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Home server error: {e}", file=sys.stderr)
        return None


def push_to_home(home_url, data):
    """Push all data to home server. Errors are logged but never thrown."""
    try:
        print("\n--- Pushing to Home Server ---")

        if "scan" in data:
            r = home_api(home_url, "scans", data["scan"])
            if r:
                print(f"  Home: scan record inserted")

        if "hosts" in data:
            r = home_api(home_url, "hosts", {"hosts": data["hosts"]})
            if r:
                print(f"  Home: {r.get('inserted', 0)} hosts upserted")

        if "banners" in data:
            r = home_api(home_url, "banners", {"banners": data["banners"]})
            if r:
                print(f"  Home: {r.get('inserted', 0)} HTTP banners inserted")

        if "cameras" in data:
            r = home_api(home_url, "cameras", {"cameras": data["cameras"]})
            if r:
                print(f"  Home: {r.get('inserted', 0)} cameras inserted")

        if "whois" in data:
            r = home_api(home_url, "whois", {"whois": data["whois"]})
            if r:
                print(f"  Home: {r.get('inserted', 0)} WHOIS records upserted")

        return True
    except Exception as e:
        print(f"  Home server push failed: {e}", file=sys.stderr)
        return False


# ===================================================================
#  Main — collect data once, push to each destination independently
# ===================================================================

def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "final_results"

    print("Collecting scan data...")
    data = collect_data(results_dir)
    print(f"  Collected: {len(data.get('hosts', []))} hosts, "
          f"{len(data.get('banners', []))} banners, "
          f"{len(data.get('cameras', []))} cameras, "
          f"{len(data.get('whois', []))} whois records")

    # Push to Turso (if configured)
    auth_token = os.environ.get("TURSO_TOKEN", "")
    db_url = os.environ.get("TURSO_DB_URL", "")
    if auth_token and db_url:
        push_to_turso(auth_token, db_url, data)
    else:
        print("\n--- Skipping Turso: TURSO_TOKEN and TURSO_DB_URL not both set (this is fine) ---")

    # Push to home server (if configured) — completely independent
    home_url = os.environ.get("HOME_SERVER_URL", "")
    if home_url:
        push_to_home(home_url, data)
    else:
        print("\n--- Skipping Home Server: HOME_SERVER_URL not set (this is fine) ---")

    print("\nDone — scan results pushed to all configured destinations!")


if __name__ == "__main__":
    main()
