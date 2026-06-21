#!/usr/bin/env python3
"""
scanner-db-server — Home server for receiving and querying internet scan results.

Runs behind Cloudflare Tunnel (no static IP needed).
Receives data from GitHub Actions via push-to-turso.py.
Stores everything in a local SQLite database.

Quick start:
    pip install -r requirements.txt
    python app.py                    # runs on :9900
    cloudflared tunnel --url http://localhost:9900

Endpoints:
    GET  /health          → {"status": "ok"}
    GET  /stats           → {"hosts": N, "banners": N, "cameras": N, "whois": N, "scans": N}
    POST /ingest/scans    → {"scan_date": "...", "blocks_processed": 4, ...}
    POST /ingest/hosts    → {"hosts": ["1.2.3.4", "5.6.7.8", ...]}
    POST /ingest/banners  → {"banners": [{"ip":..., "port":..., ...}, ...]}
    POST /ingest/cameras  → {"cameras": [{"ip":..., "port":..., ...}, ...]}
    POST /ingest/whois    → {"whois": [{"subnet":..., "org":..., ...}, ...]}
    GET  /query?sql=...   → Raw SQL query (read-only, for exploration)
"""
import sqlite3
import os
from contextlib import closing

from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel
from typing import Optional

DB_PATH = os.environ.get("SCANNER_DB", "scanner.db")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "9900"))

app = FastAPI(title="Scanner Database Server", version="1.0.0")


# ---------- Schema ----------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date TEXT,
    blocks_processed INTEGER,
    unique_hosts INTEGER,
    potential_cameras INTEGER,
    scan_duration_seconds INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS http_banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    title TEXT,
    server TEXT,
    status_code INTEGER,
    url TEXT,
    scan_date TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cameras (
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
);

CREATE TABLE IF NOT EXISTS whois (
    subnet TEXT PRIMARY KEY,
    org TEXT,
    netname TEXT,
    country TEXT,
    asn TEXT,
    last_updated TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_banners_scan_date ON http_banners(scan_date);
CREATE INDEX IF NOT EXISTS idx_banners_ip ON http_banners(ip);
CREATE INDEX IF NOT EXISTS idx_cameras_scan_date ON cameras(scan_date);
CREATE INDEX IF NOT EXISTS idx_cameras_ip ON cameras(ip);
CREATE INDEX IF NOT EXISTS idx_cameras_confidence ON cameras(confidence DESC);
"""


def get_db():
    """Get a SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ---------- Startup ----------

@app.on_event("startup")
def startup():
    with closing(get_db()) as conn:
        conn.executescript(SCHEMA_SQL)
    print(f"Scanner DB server ready — storing data in {DB_PATH}")


# ---------- Models ----------

class ScanRecord(BaseModel):
    scan_date: str = ""
    blocks_processed: int = 0
    unique_hosts: int = 0
    potential_cameras: int = 0
    scan_duration_seconds: int = 0


class HostsPayload(BaseModel):
    hosts: list[str]


class BannerEntry(BaseModel):
    ip: str
    port: int = 0
    title: str = ""
    server: str = ""
    status_code: int = 0
    url: str = ""
    scan_date: str = ""


class BannersPayload(BaseModel):
    banners: list[BannerEntry]


class CameraEntry(BaseModel):
    ip: str
    port: int = 0
    type: str = "camera"
    confidence: int = 0
    source: str = "scan"
    title: str = ""
    server: str = ""
    url: str = ""
    scan_date: str = ""


class CamerasPayload(BaseModel):
    cameras: list[CameraEntry]


class WhoisEntry(BaseModel):
    subnet: str
    org: str = ""
    netname: str = ""
    country: str = ""
    asn: str = ""


class WhoisPayload(BaseModel):
    whois: list[WhoisEntry]


# ---------- Endpoints ----------

@app.get("/health")
def health():
    return {"status": "ok", "db": DB_PATH}


@app.get("/stats")
def stats():
    with closing(get_db()) as conn:
        hosts = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        banners = conn.execute("SELECT COUNT(*) FROM http_banners").fetchone()[0]
        cameras = conn.execute("SELECT COUNT(*) FROM cameras").fetchone()[0]
        whois = conn.execute("SELECT COUNT(*) FROM whois").fetchone()[0]
        scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        last_scan = conn.execute(
            "SELECT scan_date FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return {
        "hosts": hosts,
        "http_banners": banners,
        "cameras": cameras,
        "whois_subnets": whois,
        "total_scans": scans,
        "last_scan_date": last_scan[0] if last_scan else None,
    }


@app.post("/ingest/scans")
def ingest_scan(data: ScanRecord):
    with closing(get_db()) as conn:
        conn.execute(
            """INSERT INTO scans (scan_date, blocks_processed, unique_hosts, potential_cameras, scan_duration_seconds)
               VALUES (?, ?, ?, ?, ?)""",
            (data.scan_date, data.blocks_processed, data.unique_hosts,
             data.potential_cameras, data.scan_duration_seconds),
        )
        conn.commit()
    return {"inserted": 1}


@app.post("/ingest/hosts")
def ingest_hosts(data: HostsPayload):
    with closing(get_db()) as conn:
        conn.executemany(
            """INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, datetime('now'), datetime('now'))
               ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen""",
            [(ip,) for ip in data.hosts],
        )
        conn.commit()
    return {"inserted": len(data.hosts)}


@app.post("/ingest/banners")
def ingest_banners(data: BannersPayload):
    with closing(get_db()) as conn:
        conn.executemany(
            """INSERT INTO http_banners (ip, port, title, server, status_code, url, scan_date)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(b.ip, b.port, b.title, b.server, b.status_code, b.url, b.scan_date) for b in data.banners],
        )
        conn.commit()
    return {"inserted": len(data.banners)}


@app.post("/ingest/cameras")
def ingest_cameras(data: CamerasPayload):
    with closing(get_db()) as conn:
        conn.executemany(
            """INSERT INTO cameras (ip, port, type, confidence, source, title, server, url, scan_date)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(c.ip, c.port, c.type, c.confidence, c.source, c.title, c.server, c.url, c.scan_date) for c in data.cameras],
        )
        conn.commit()
    return {"inserted": len(data.cameras)}


@app.post("/ingest/whois")
def ingest_whois(data: WhoisPayload):
    with closing(get_db()) as conn:
        conn.executemany(
            """INSERT INTO whois (subnet, org, netname, country, asn, last_updated)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(subnet) DO UPDATE SET
                   org = excluded.org,
                   netname = excluded.netname,
                   country = excluded.country,
                   asn = excluded.asn,
                   last_updated = excluded.last_updated""",
            [(w.subnet, w.org, w.netname, w.country, w.asn) for w in data.whois],
        )
        conn.commit()
    return {"inserted": len(data.whois)}


@app.get("/query")
def query(sql: str = Query(..., description="SQL query (SELECT only)")):
    sql_upper = sql.strip().upper()
    if not sql_upper.startswith("SELECT") and not sql_upper.startswith("PRAGMA"):
        raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")
    try:
        with closing(get_db()) as conn:
            cursor = conn.execute(sql)
            rows = [dict(row) for row in cursor.fetchall()]
        return {"results": rows, "count": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- Main ----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
