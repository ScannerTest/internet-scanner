# 📡 Internet Scanner - Shodan Alternative on GitHub Actions

A distributed internet-wide scanner powered by GitHub Actions. Splits the entire IPv4 space into parallel scanning jobs, with checkpointing, banner grabbing, and camera/IoT device detection.

**⚠️ DISCLAIMER**: This tool is for educational/security research purposes. Using GitHub Actions for network scanning violates GitHub's Acceptable Use Policy and will likely result in account suspension. **Use a disposable account.** All commits are made with anonymous credentials.

## 🚀 Quick Start

```bash
# Trigger a scan (1 block = ~16M IPs, ~2.5 hours at 100k pps)
gh workflow run "Internet Scanner" -f blocks=1 -f rate=100000 -f resume=no -f whois=no

# 4 blocks (64M IPs, runs automatically on cron)
gh workflow run "Internet Scanner" -f blocks=4 -f rate=100000 -f resume=yes -f whois=no

# Full scan with WHOIS (256 blocks = full IPv4)
gh workflow run "Internet Scanner" -f blocks=256 -f rate=100000 -f resume=yes -f whois=yes

# Check results: GitHub UI → Actions → workflow run → merge job → artifacts
```

**Cron schedule**: Runs automatically every 7 hours (`0 */7 * * *`) with 4 blocks at 100k pps, resume enabled.

## 🏗️ Architecture

```
                    ┌──────────────────────────────┐
                    │         INIT Job              │
                    │  Splits IPv4 into N blocks    │
                    │  Checks for previous state    │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │    SCAN Matrix (× N blocks)   │
                    │  ┌─────────────────────────┐ │
                    │  │  masscan (port scan)     │ │
                    │  │  httpx (HTTP banners)    │ │
                    │  │  zgrab2 (proto banners)  │ │
                    │  │  nuclei (camera detect)  │ │
                    │  │  camera analysis         │ │
                    │  └─────────┬───────────────┘ │
                    │            │  [if: always()]  │
                    │  ◄─── Saves artifacts ─────► │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │     WHOIS Job (optional)      │
                    │  Subnet-cached IP lookups     │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │     MERGE Job                 │
                    │  Combines all block results   │
                    │  Deduplicates, enriches       │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │     REPORT Job                │
                    │  Camera/IoT detection report  │
                    │  Final summary + artifacts    │
                    └──────────────────────────────┘
```

## 🎯 Port Selection (27 ports)

| Category | Ports | Why |
|----------|-------|-----|
| **Cameras/IoT** | 554, 8554, 1935, 8000, 8080, 81, 82, 88, 23 | RTSP streams, web cams, Telnet IoT |
| **Web Services** | 80, 443, 8443, 3000, 5000, 9090, 9443, 8008, 8888 | General web discovery |
| **Databases** | 3306, 5432, 27017, 6379, 9200 | Unsecured data stores |
| **Remote Access** | 22, 3389, 5900, 21 | SSH, RDP, VNC, FTP |

Masscan scans **all ports in one pass** — adding more ports doesn't increase scan time, only result volume.

## 💾 Durability & Checkpointing

**No work is ever lost.** The system is designed so that failures, cancellations, and timeouts never waste previous work:

- **`if: always()`**: Every step saves artifacts even on failure
- **masscan `--resume`**: Built-in scan state persistence via checkpoints
- **State tracking**: JSON state per block tracks completion status
- **Resume mode**: Re-running with `resume=yes` skips completed blocks
- **Recovery workflow**: `gh workflow run "Recovery" -f mode=auto` detects and retries failed blocks + WHOIS lookups
- **Anonymous commits**: All pushes use `anon-user <anon@example.com>`

## 🚦 Scan Parameters

| Parameter | Options | Description |
|-----------|---------|-------------|
| `blocks` | 1-256 | Number of /8 blocks to scan (256 = full IPv4) |
| `rate` | 1000-100000 | Masscan packet rate (higher = faster) |
| `resume` | yes/no | Skip already-completed blocks |
| `whois` | yes/no | Run WHOIS lookups on discovered IPs |

Default rate is **100,000 pps** — hitting ~99 kpps on GHA runners. Each /8 block (~16.7M IPs, 27 ports) completes in ~2.5 hours.

## 📊 Output Artifacts

After a run, download these artifacts from the Actions UI:

- `final-results/all_hosts.txt` — All discovered live IPs
- `final-results/all_cameras.json` — Camera-detected devices (deduplicated)
- `final-results/scan_summary.json` — Summary statistics
- `final-results/top_ports.csv` — Port frequency analysis
- `camera_report/FINAL_REPORT.md` — Human-readable camera report
- `camera_report/no_auth_cameras.json` — High-confidence no-auth cameras
- `scan-state` — State file for future resumption

## 🏠 Self-Hosted Database Server

The scanner can push results to your own database server for persistent storage
and querying. Runs as a Docker container behind Cloudflare Tunnel on your machine.

### Prerequisites

- Docker
- cloudflared (for the tunnel)
- A domain with DNS managed by Cloudflare (for a permanent tunnel URL)

### Quick Start

```bash
# 1. Clone on your server
git clone git@github.com:ScannerTest/internet-scanner.git
cd internet-scanner

# 2. Build and run the container (listens on port 8080)
docker build -t scanner-db server/
docker run -d --name scanner-db --restart unless-stopped \
  -v /path/to/data:/data \
  -p 9900:9900 \
  scanner-db

# 3. Create a permanent Cloudflare Tunnel
# (Set this up in your Cloudflare dashboard → Zero Trust → Tunnels)
cloudflared tunnel create scanner-db
cloudflared tunnel route dns scanner-db scanner.1110777.xyz

# 4. Create tunnel config file at ~/.cloudflared/config.yml:
# tunnel: <tunnel-uuid>
# credentials-file: /root/.cloudflared/<tunnel-uuid>.json
# ingress:
#   - hostname: scanner.1110777.xyz
#     service: http://localhost:9900
#   - service: http_status:404

# 5. Run the tunnel as a service
sudo cloudflared service install

# 6. Update the GitHub secret with your permanent URL
gh secret set HOME_SERVER_URL -b "https://scanner.1110777.xyz"
```

### Verify it's working

```bash
curl https://scanner.1110777.xyz/health
# → {"status":"ok","db":"/data/scanner.db"}

curl https://scanner.1110777.xyz/stats
# → {"hosts":0,"http_banners":0,"cameras":0,"whois_subnets":0,"total_scans":0,...}

curl https://scanner.1110777.xyz/
# → <!DOCTYPE html><html...> (dashboard HTML)
```

### 📖 Recovering from scratch (container goes down)

If the container dies, the server reboots, or you need to set it up on a new machine:

```bash
# 1. Clone the repo and enter server directory
git clone git@github.com:ScannerTest/internet-scanner.git
cd internet-scanner/server

# 2. Build the Docker image
docker build -t scanner-db .

# 3. Create data directory (this holds your SQLite DB - data survives rebuilds)
mkdir -p ~/scanner-db/data

# 4. Run the container
#    -v binds the data directory so the DB persists across container restarts
#    -p exposes port 9900 (what Cloudflare Tunnel connects to)
#    -e API_TOKEN is the Bearer token used by push-to-turso.py to authenticate
docker run -d --name scanner-db --restart unless-stopped \
  -v ~/scanner-db/data:/data \
  -p 9900:9900 \
  -e API_TOKEN=scan-fbe7eebc3d7447fcbec2f676 \
  scanner-db

# 5. Verify it's running
curl http://localhost:9900/health
curl http://localhost:9900/

# 6. Make sure your Cloudflare Tunnel is running and points to localhost:9900
#    (your tunnel config at ~/.cloudflared/config.yml should have:
#      service: http://localhost:9900)
sudo systemctl status cloudflared
```

**That's it.** The container auto-starts on boot (`--restart unless-stopped`).
The database at `~/scanner-db/data/scanner.db` persists across rebuilds.
If you need the API token for a fresh setup, it's set both in the container and
in GitHub's `HOME_SERVER_TOKEN` secret.

### Dashboard

The server comes with a built-in dashboard at the root URL:

| Page | Description |
|------|-------------|
| `/` | Overview with stats cards, scan chart, recent scans |
| `/cameras` | Camera detections table, sorted by confidence |
| `/banners` | HTTP banner fingerprints |
| `/hosts` | All discovered IPs |
| `/whois` | Subnet ownership data |

All dashboard pages read directly from the local SQLite database.
No API endpoint needed — just open the URL in a browser.

### Env vars to set on GitHub (Settings → Secrets and variables → Actions)

| Secret | Description |
|--------|-------------|
| `TURSO_TOKEN` | Turso database auth token (primary cloud backup) |
| `TURSO_DB_URL` | Turso database URL (e.g. `libsql://...`) |
| `HOME_SERVER_URL` | Your permanent tunnel URL (e.g. `https://scanner.1110777.xyz`) |
| `HOME_SERVER_TOKEN` | Bearer token for home server auth (matches API_TOKEN in the container) |

## 🛠 Files

```
.github/workflows/
├── scan.yml         # Main scanning workflow (cron: every 7h)
└── recovery.yml     # Recovery/resume workflow
scripts/
├── scan-block.sh         # Core scanning engine (masscan → httpx → zgrab2 → nuclei)
├── merge-results.sh      # Combines block results
├── camera-detect.sh      # Camera/IoT fingerprinting
├── whois-cached.sh       # WHOIS with subnet caching + rate limiting
├── generate-ranges.py    # Splits IPv4 into balanced CIDR blocks
├── generate-matrix.py    # Creates GHA matrix from blocks
├── check-recovery.py     # Detects what needs recovery
├── extract-retry-ips.py  # Extracts failed WHOIS IPs for retry
├── set-scan-state.py     # Aggregates completed block states
config/
└── ports.txt             # Target ports (editable, 27 ports)
templates/
└── camera-templates.yaml # Nuclei templates for camera detection
```

## 🔧 Recovery

If a scan gets interrupted (account banned, timeout, etc.):

```bash
# Auto-detect and fix everything
gh workflow run "Recovery" -f mode=auto

# Retry failed WHOIS lookups only
gh workflow run "Recovery" -f mode=whois

# Resume incomplete scan blocks only
gh workflow run "Recovery" -f mode=resume
```

## 💡 Recommended Test Flow

1. **Start tiny**: `blocks=1 rate=100000` — scans one /8 block (16M IPs, ~2.5h)
2. **Check results**: Verify artifacts are generated properly
3. **Scale gradually**: 4 → 16 → 64 → 256 blocks
4. **Use recovery**: If banned, recovery workflow picks up partial results
5. **WHOIS later**: Add `-f whois=yes` when you want IP ownership data

## ⚠️  Known Risks

- **Account ban**: GitHub will detect masscan traffic and ban the account (hours, maybe minutes)
- **IP blocks**: GHA runner IPs are public and frequently blocked by CDNs/firewalls
- **Rate limits**: GITHUB_TOKEN limited to 1,000 req/h; masscan hits ~99 kpps on GHA runners
- **6-hour job timeout**: Each scan job must complete within 6 hours (currently ~2.5h per block)
- **Artifact expiry**: 90 day retention (GitHub default)

## 📝 License

MIT
