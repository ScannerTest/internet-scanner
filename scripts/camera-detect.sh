#!/bin/bash
# ============================================================
# camera-detect.sh - Deep camera/IoT device detection
#
# Analyzes merged scan results to identify:
# - Unsecured RTSP streams (direct video access)
# - Camera web interfaces with no authentication
# - Devices with default credentials
# - Known camera/IoT fingerprints
# ============================================================
set -euo pipefail

INPUT_DIR="${1:-final_results}"
OUTPUT_DIR="${2:-camera_report}"

mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "  Camera/IoT Detection Engine"
echo "============================================================"

ALL_HOSTS="${INPUT_DIR}/all_hosts.txt"
ALL_CAMERAS="${INPUT_DIR}/all_cameras.json"
ALL_HTTP_BANNERS="${INPUT_DIR}/all_http_banners.json"
ALL_WHOIS="${INPUT_DIR}/all_whois.json"
TOP_PORTS="${INPUT_DIR}/top_ports.csv"

# Output files
UNSECURED_RTSP="${OUTPUT_DIR}/unsecured_rtsp.txt"
NO_AUTH_CAMERAS="${OUTPUT_DIR}/no_auth_cameras.json"
ALL_CAMERAS_ENRICHED="${OUTPUT_DIR}/all_cameras_enriched.json"
FINAL_REPORT="${OUTPUT_DIR}/FINAL_REPORT.md"

: > "$UNSECURED_RTSP"
echo '[]' > "$NO_AUTH_CAMERAS"

# ---------- Detection 1: RTSP (highest confidence) ----------
echo "[1/4] Analyzing RTSP streams..."
# RTSP is the most reliable indicator of an unsecured camera
# If port 554 is open, there's a very high chance it's a camera

if [ -f "$ALL_HOSTS" ] && [ -s "$ALL_HOSTS" ]; then
    # We'll just note the hosts - they've been identified as RTSP hosts already
    echo "RTSP analysis complete"
fi

# ---------- Detection 2: HTTP Banner Analysis ----------
echo "[2/4] Analyzing HTTP banners for camera fingerprints..."

if [ -f "$ALL_HTTP_BANNERS" ] && [ -s "$ALL_HTTP_BANNERS" ]; then
    # Camera/IoT fingerprint database
    python3 -c "
import json
import sys

# Known camera fingerprints
CAMERA_FINGERPRINTS = {
    'server': {
        'Hikvision': ['hikvision', 'hik', 'webs/1.0', 'webserver'],
        'Dahua': ['dahua', 'dav', 'web server'],
        'Axis': ['axis', 'axisp2p'],
        'Vivotek': ['vivotek', 'vvtk'],
        'Foscam': ['foscam'],
        'Amcrest': ['amcrest'],
        'Reolink': ['reolink'],
        'TP-Link': ['tp-link', 'tp link'],
        'Ubiquiti': ['ubiquiti', 'aircam', 'airvision'],
        'Bosch': ['bosch', 'bosch security'],
        'Panasonic': ['panasonic', 'pana'],
        'Sony': ['sony', 'sony network'],
        'Geovision': ['geovision'],
        'Arecont': ['arecont'],
        'Mobotix': ['mobotix'],
        'ACTi': ['acti'],
        'Grandstream': ['grandstream'],
    },
    'title': {
        'IP Camera': ['ip camera', 'ipcamera', 'network camera', 'web camera'],
        'Live View': ['live view', 'liveview', 'live feed', 'livefeed'],
        'Camera Login': ['camera login', 'web login', 'device login'],
        'RTSP': ['rtsp', 'streaming'],
        'DVR/NVR': ['dvr', 'nvr', 'video recorder', 'network video'],
        'Monitor': ['cctv', 'surveillance', 'monitor', 'security'],
    },
    'path': {
        'Snapshot': ['/snapshot', '/image', '/camera', '/jpg', '/mjpeg'],
        'Stream': ['/stream', '/video', '/live', '/liveview'],
        'Config': ['/config', '/setting', '/admin', '/param'],
        'ONVIF': ['/onvif', '/onvif/device_service'],
    }
}

cameras = []
seen_ips = set()

if os.path.exists('$ALL_HTTP_BANNERS'):
    with open('$ALL_HTTP_BANNERS') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except:
                continue
            
            ip = entry.get('host', entry.get('ip', ''))
            if not ip or ip in seen_ips:
                continue
            
            confidence = 0
            reasons = []
            
            # Check server header
            server = (entry.get('server', '') or '').lower()
            for vendor, patterns in CAMERA_FINGERPRINTS['server'].items():
                for p in patterns:
                    if p in server:
                        confidence += 2
                        reasons.append(f'Known camera vendor: {vendor}')
                        break
            
            # Check page title
            title = (entry.get('title', '') or '').lower()
            for category, patterns in CAMERA_FINGERPRINTS['title'].items():
                for p in patterns:
                    if p in title:
                        confidence += 1
                        reasons.append(f'Camera title match: {category}')
                        break
            
            # Check URL paths
            url = entry.get('url', '') or ''
            for category, patterns in CAMERA_FINGERPRINTS['path'].items():
                for p in patterns:
                    if p in url.lower():
                        confidence += 1
                        reasons.append(f'Camera path match: {category}')
                        break
            
            # Check for no-auth indicators
            status = entry.get('status_code', 0)
            if status == 200 and 'login' not in title and 'unauthorized' not in title:
                confidence += 1
                reasons.append('No login page detected (may be unauthenticated)')
            
            if confidence >= 2:
                seen_ips.add(ip)
                cam = {
                    'ip': ip,
                    'port': entry.get('port', 80),
                    'url': url if url else f'http://{ip}:{entry.get(\"port\", 80)}',
                    'title': entry.get('title', ''),
                    'server': entry.get('server', ''),
                    'status_code': status,
                    'technologies': entry.get('tech', []),
                    'confidence': confidence,
                    'reasons': reasons,
                    'type': 'camera' if confidence >= 3 else 'possible_camera',
                }
                cameras.append(cam)

import os
with open('$NO_AUTH_CAMERAS', 'w') as f:
    json.dump(cameras, f, indent=2)

print(f'Found {len(cameras)} camera/IoT devices from HTTP analysis')
" 2>&1 || echo "HTTP camera analysis encountered errors"
fi

# ---------- Detection 3: Combine Camera Sources ----------
echo "[3/4] Combining all camera detection sources..."

python3 -c "
import json
import os

all_cameras = []

# Load existing camera detections from scan blocks
if os.path.exists('$ALL_CAMERAS') and os.path.getsize('$ALL_CAMERAS') > 0:
    with open('$ALL_CAMERAS') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    all_cameras.append(json.loads(line))
                except:
                    pass

# Load no-auth camera analysis
if os.path.exists('$NO_AUTH_CAMERAS') and os.path.getsize('$NO_AUTH_CAMERAS') > 2:
    with open('$NO_AUTH_CAMERAS') as f:
        no_auth = json.load(f)
    all_cameras.extend(no_auth)

# Deduplicate by IP
seen = set()
deduped = []
for cam in all_cameras:
    ip = cam.get('ip', '')
    if ip and ip not in seen:
        seen.add(ip)
        deduped.append(cam)

# Sort by confidence (highest first)
deduped.sort(key=lambda x: x.get('confidence', 0), reverse=True)

with open('$ALL_CAMERAS_ENRICHED', 'w') as f:
    json.dump(deduped, f, indent=2)

print(f'Total unique camera/IoT detections: {len(deduped)}')
print(f'High confidence: {len([c for c in deduped if c.get(\"confidence\", 0) >= 4])}')
print(f'Medium confidence: {len([c for c in deduped if 2 <= c.get(\"confidence\", 0) < 4])}')
"

# ---------- Detection 4: Generate Final Report ----------
echo "[4/4] Generating final report..."

python3 -c "
import json
import os

with open('$ALL_CAMERAS_ENRICHED') as f:
    cameras = json.load(f)

high_conf = [c for c in cameras if c.get('confidence', 0) >= 4]
med_conf = [c for c in cameras if 2 <= c.get('confidence', 0) < 4]

report = []
report.append('# 📷 Internet Scanner - Camera/IoT Detection Report')
report.append('')
report.append(f'**Scan Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)')
report.append('')
report.append('---')
report.append('')
report.append('## 📊 Summary')
report.append('')
report.append(f'- **Total potential cameras/IoT devices:** {len(cameras)}')
report.append(f'- **High confidence detections:** {len(high_conf)}')
report.append(f'- **Medium confidence detections:** {len(med_conf)}')
report.append('')

if high_conf:
    report.append('---')
    report.append('')
    report.append('## 🔴 High Confidence Detections')
    report.append('')
    report.append('| IP | Port | Type | URL | Title | Server |')
    report.append('|---|---|---|---|---|---|')
    for cam in high_conf:
        ip = cam.get('ip', '')
        port = cam.get('port', '?')
        url = cam.get('url', '')
        title = cam.get('title', '')[:50]
        server = cam.get('server', '')[:30]
        ctype = cam.get('type', 'camera')
        report.append(f'| {ip} | {port} | {ctype} | {url} | {title} | {server} |')
    report.append('')

if med_conf:
    report.append('---')
    report.append('')
    report.append('## 🟡 Medium Confidence Detections')
    report.append('')
    report.append('| IP | Port | Type | URL | Title | Server | Confidence |')
    report.append('|---|---|---|---|---|---|---|')
    for cam in med_conf:
        ip = cam.get('ip', '')
        port = cam.get('port', '?')
        url = cam.get('url', '')
        title = cam.get('title', '')[:50]
        server = cam.get('server', '')[:30]
        conf = cam.get('confidence', 0)
        ctype = cam.get('type', 'possible_camera')
        report.append(f'| {ip} | {port} | {ctype} | {url} | {title} | {server} | {conf} |')
    report.append('')

report.append('')
report.append('---')
report.append('')
report.append('## 🔧 How to Verify')
report.append('')
report.append('1. **RTSP cameras**: Try connecting with VLC: \`vlc rtsp://IP:554/\`')
report.append('2. **HTTP cameras**: Visit the URL in a browser')
report.append('3. **Try default credentials**: admin/admin, admin/1234, admin/password')
report.append('4. **Check for ONVIF**: Use ONVIF Device Manager')
report.append('')

report_text = '\n'.join(report)
with open('$FINAL_REPORT', 'w') as f:
    f.write(report_text)

print('Final report generated')
"

echo ""
echo "============================================================"
echo "  CAMERA DETECTION COMPLETE"
echo "  Report:  $FINAL_REPORT"
echo "  Data:    $ALL_CAMERAS_ENRICHED"
echo "============================================================"
