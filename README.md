# 📡 Internet Scanner - Shodan Alternative on GitHub Actions

A distributed internet-wide scanner powered by GitHub Actions. Splits the entire IPv4 space into parallel scanning jobs, with checkpointing, banner grabbing, and camera/IoT device detection.

**⚠️ DISCLAIMER**: This tool is for educational/security research purposes. Using GitHub Actions for network scanning violates GitHub's Acceptable Use Policy and will likely result in account suspension. Use a disposable account.

## 🚀 Quick Start

1. **Fork/Clone this repo**
2. **Trigger a scan**:
   ```
   gh workflow run "Internet Scanner" -f blocks=1 -f rate=1000
   ```
3. **Check results**: Go to Actions → workflow run → `merge` job → artifacts

## 🏗️ Architecture

```
                    ┌──────────────────────────────┐
                    │         INIT Job              │
                    │  Splits IPv4 into N blocks    │
                    │  Checks for previous state     │
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

## 🎯 Port Selection (~45 ports)

| Category | Ports | Why |
|----------|-------|-----|
| **Cameras/IoT** | 554, 8554, 8000, 8080, 81, 23, 1935 | RTSP streams, web cams, Telnet IoT |
| **Web Services** | 80, 443, 8443, 3000, 5000, 9090, 9443 | General web discovery |
| **Databases** | 3306, 5432, 27017, 6379, 9200, 5984, 1433, 1521 | Unsecured data stores |
| **Remote Access** | 22, 3389, 5900-5903, 21 | SSH, RDP, VNC, FTP |
| **Industrial** | 502, 102 | SCADA/ICS protocols |

Masscan scans **all ports in one pass** — adding more ports doesn't increase scan time, only result volume.

## 💾 Durability & Checkpointing

**No work is ever lost.** The system is designed so that failures, cancellations, and timeouts never waste previous work:

- **`if: always()`**: Every step saves artifacts even on failure
- **masscan `--resume`**: Built-in scan state persistence
- **State tracking**: JSON state per block tracks completion
- **Resume mode**: Re-running with `resume=yes` skips completed blocks
- **Recovery workflow**: Retries failed WHOIS and incomplete scans

## 🚦 Scan Parameters

| Parameter | Options | Description |
|-----------|---------|-------------|
| `blocks` | 1-256 | Number of /8 blocks to scan (256 = full IPv4) |
| `rate` | 1000-50000 | Masscan packet rate (slower = stealthier) |
| `resume` | yes/no | Skip already-completed blocks |
| `whois` | yes/no | Run WHOIS lookups on discovered IPs |

## 📊 Output Artifacts

After a run, download these artifacts:
- `final-results/all_hosts.txt` - All discovered live IPs
- `final-results/all_cameras.json` - Camera-detected devices
- `final-results/scan_summary.json` - Summary statistics
- `final-results/top_ports.csv` - Port frequency analysis
- `camera_report/FINAL_REPORT.md` - Human-readable camera report
- `scan-state` - State file for future resumption

## 🔧 Recovery

If a scan gets interrupted (account banned, timeout, etc.):

```bash
# Retry failed WHOIS lookups
gh workflow run "Recovery" -f mode=whois

# Resume incomplete scan blocks
gh workflow run "Recovery" -f mode=resume

# Auto-detect and fix everything
gh workflow run "Recovery" -f mode=auto
```

## 💡 Recommended Test Flow

1. **Start tiny**: `blocks=1 rate=1000` — scans one /8 block (16M IPs, ~30 min)
2. **Check results**: Verify artifacts are generated properly
3. **Scale gradually**: 4 → 16 → 64 → 256 blocks
4. **Use recovery**: If banned, recovery workflow picks up partial results

## 📝 License

MIT
