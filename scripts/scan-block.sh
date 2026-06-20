#!/bin/bash
# ============================================================
# scan-block.sh - Scan a single CIDR block with full checkpointing
# 
# This script is the core scanning engine. It:
# 1. Checks for existing checkpoints (resume support)
# 2. Runs masscan for all ports in parallel
# 3. Extracts live hosts and runs HTTP banner grabbing via httpx
# 4. Runs protocol-specific banner grabbing via zgrab2
# 5. Runs nuclei template matching for camera/IoT detection
# 6. Saves ALL results + checkpoint state
# 7. NEVER loses work - even on crash/failure
# ============================================================
set -euo pipefail

# ---------- Configuration ----------
BLOCK_ID="${1:-}"
CIDR="${2:-}"
PORTS_FILE="${3:-config/ports.txt}"
RESULTS_DIR="${4:-results}"
CHECKPOINT_DIR="${5:-checkpoints}"
MASSCAN_RATE="${MASSCAN_RATE:-10000}"
MASSCAN_RETRIES="${MASSCAN_RETRIES:-1}"

if [ -z "$BLOCK_ID" ] || [ -z "$CIDR" ]; then
    echo "Usage: $0 <block_id> <cidr> [ports_file] [results_dir] [checkpoint_dir]"
    exit 1
fi

mkdir -p "$RESULTS_DIR" "$CHECKPOINT_DIR"

# File paths
CHECKPOINT_FILE="${CHECKPOINT_DIR}/checkpoint_${BLOCK_ID}.json"
STATE_FILE="${RESULTS_DIR}/state_${BLOCK_ID}.json"
MASSCAN_OUT="${RESULTS_DIR}/masscan_${BLOCK_ID}.json"
HTTP_BANNERS="${RESULTS_DIR}/http_banners_${BLOCK_ID}.json"
NUCLEI_OUT="${RESULTS_DIR}/nuclei_${BLOCK_ID}.json"
ALL_LIVE_HOSTS="${RESULTS_DIR}/live_hosts_${BLOCK_ID}.txt"
CAMERAS_OUT="${RESULTS_DIR}/cameras_${BLOCK_ID}.json"
SUMMARY_OUT="${RESULTS_DIR}/summary_${BLOCK_ID}.json"

# ---------- Helper: Save state ----------
save_state() {
    local status="$1"
    local message="${2:-}"
    local completed_scan="${3:-false}"
    local completed_banners="${4:-false}"
    local completed_nuclei="${5:-false}"
    
    cat > "$STATE_FILE" <<EOF
{
  "block_id": $BLOCK_ID,
  "cidr": "$CIDR",
  "status": "$status",
  "message": "$message",
  "completed_scan": $completed_scan,
  "completed_banners": $completed_banners,
  "completed_nuclei": $completed_nuclei,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hosts_found": $(wc -l < "$ALL_LIVE_HOSTS" 2>/dev/null || echo 0)
}
EOF
}

# ---------- Step 1: Port Scanning with masscan ----------
step_masscan() {
    echo "[BLOCK $BLOCK_ID] Starting masscan on $CIDR..."

    # Remove comments, blank lines, and whitespace from port list
    PORTS=$(grep -v '^\s*#' "$PORTS_FILE" | grep -v '^\s*$' | awk '{print $1}' | paste -sd,)

    echo "[BLOCK $BLOCK_ID] Ports: $PORTS"
    echo "[BLOCK $BLOCK_ID] Rate: $MASSCAN_RATE pps"

    # Check for existing checkpoint to resume
    RESUME_ARGS=""
    if [ -f "$CHECKPOINT_FILE" ]; then
        echo "[BLOCK $BLOCK_ID] Found checkpoint, resuming..."
        RESUME_ARGS="--resume $CHECKPOINT_FILE"
    fi

    # Run masscan
    if ! masscan "$CIDR" \
        -p"$PORTS" \
        --rate="$MASSCAN_RATE" \
        --retries="$MASSCAN_RETRIES" \
        --wait 10 \
        $RESUME_ARGS \
        -oJ "$MASSCAN_OUT" \
        2>&1; then
        echo "[BLOCK $BLOCK_ID] masscan encountered an issue (may be partial results)"
    fi

    # Save checkpoint for resume (even partial masscan output is useful)
    if [ -f "$MASSCAN_OUT" ]; then
        cp "$MASSCAN_OUT" "$CHECKPOINT_FILE" 2>/dev/null || true
    fi

    # Extract live IPs from masscan results
    if [ -f "$MASSCAN_OUT" ]; then
        grep -oP '"ip":"\K[^"]+' "$MASSCAN_OUT" 2>/dev/null | sort -u > "$ALL_LIVE_HOSTS" || true
    fi

    HOST_COUNT=$(wc -l < "$ALL_LIVE_HOSTS" 2>/dev/null || echo 0)
    echo "[BLOCK $BLOCK_ID] masscan complete: $HOST_COUNT live hosts found"

    save_state "scan_complete" "masscan done: $HOST_COUNT hosts" true false false
    return 0
}

# ---------- Step 2: HTTP Banner Grabbing with httpx ----------
step_http_banners() {
    echo "[BLOCK $BLOCK_ID] Starting HTTP banner grabbing..."

    HTTP_PORTS="80,443,8080,8443,8000,3000,5000,8008,8888,9090,9443,81,82,88,90"

    if [ ! -f "$MASSCAN_OUT" ] || [ ! -s "$MASSCAN_OUT" ]; then
        echo "[BLOCK $BLOCK_ID] No masscan results, skipping HTTP banners"
        return 0
    fi

    # Build httpx target list from masscan output
    HTTP_TARGETS="${RESULTS_DIR}/http_targets_${BLOCK_ID}.txt"
    # Truncate file first (critical for resume scenarios - don't accumulate)
    > "$HTTP_TARGETS"
    for port in $(echo "$HTTP_PORTS" | tr ',' ' '); do
        # Match masscan JSONL: {"ip":"1.2.3.4","port":80,...}
        grep -oP '"ip":"\K[^"]+(?=.*"port":'"$port"'[,}])' "$MASSCAN_OUT" 2>/dev/null | \
            awk -v p="$port" '{print $1":"p}' >> "$HTTP_TARGETS" 2>/dev/null || true
    done

    if [ ! -s "$HTTP_TARGETS" ]; then
        echo "[BLOCK $BLOCK_ID] No HTTP targets found"
        echo '[]' > "$HTTP_BANNERS"
        save_state "banners_complete" "no HTTP targets" true true false
        return 0
    fi

    # Run httpx for HTTP banner grabbing
    if ! httpx -l "$HTTP_TARGETS" \
        -title -status-code -server -tech-detect \
        -json -o "$HTTP_BANNERS" \
        -threads 50 -timeout 5 -retries 1 \
        2>&1; then
        echo "[BLOCK $BLOCK_ID] httpx encountered errors (partial results saved)"
    fi

    BANNER_COUNT=$(wc -l < "$HTTP_BANNERS" 2>/dev/null || echo 0)
    echo "[BLOCK $BLOCK_ID] HTTP banners saved: ${BANNER_COUNT} entries"
    save_state "banners_complete" "HTTP banners done" true true false
}

# ---------- Step 3: Protocol Banner Grabbing ----------
step_proto_banners() {
    echo "[BLOCK $BLOCK_ID] Starting protocol banner grabbing..."

    if [ ! -f "$MASSCAN_OUT" ] || [ ! -s "$MASSCAN_OUT" ]; then
        echo "[BLOCK $BLOCK_ID] No masscan results, skipping protocol banners"
        return 0
    fi

    # Helper: extract IPs for a given port from masscan output
    extract_ips_for_port() {
        local port="$1"
        local outfile="$2"
        grep -oP '"ip":"\K[^"]+(?=.*"port":'"$port"'[,}])' "$MASSCAN_OUT" 2>/dev/null | \
            sort -u > "$outfile" || true
    }

    # Extract targets for each protocol
    extract_ips_for_port 22  "${RESULTS_DIR}/ssh_${BLOCK_ID}.txt"
    extract_ips_for_port 23  "${RESULTS_DIR}/telnet_${BLOCK_ID}.txt"
    extract_ips_for_port 21  "${RESULTS_DIR}/ftp_${BLOCK_ID}.txt"
    extract_ips_for_port 3389 "${RESULTS_DIR}/rdp_${BLOCK_ID}.txt"
    extract_ips_for_port 554 "${RESULTS_DIR}/rtsp_${BLOCK_ID}.txt"
    extract_ips_for_port 5900 "${RESULTS_DIR}/vnc_${BLOCK_ID}.txt"
    extract_ips_for_port 5901 "${RESULTS_DIR}/vnc_${BLOCK_ID}.txt"   # append
    extract_ips_for_port 5902 "${RESULTS_DIR}/vnc_${BLOCK_ID}.txt"   # append
    extract_ips_for_port 5903 "${RESULTS_DIR}/vnc_${BLOCK_ID}.txt"   # append

    # Run zgrab2 for protocols it supports (SSH, Telnet, FTP, etc.)
    # zgrab2 outputs JSON per line

    if [ -s "${RESULTS_DIR}/ssh_${BLOCK_ID}.txt" ]; then
        echo "[BLOCK $BLOCK_ID] Grabbing SSH banners..."
        zgrab2 ssh -f "${RESULTS_DIR}/ssh_${BLOCK_ID}.txt" \
            -o "${RESULTS_DIR}/ssh_banners_${BLOCK_ID}.json" 2>/dev/null || true
    fi

    if [ -s "${RESULTS_DIR}/telnet_${BLOCK_ID}.txt" ]; then
        echo "[BLOCK $BLOCK_ID] Grabbing Telnet banners..."
        zgrab2 telnet -f "${RESULTS_DIR}/telnet_${BLOCK_ID}.txt" \
            -o "${RESULTS_DIR}/telnet_banners_${BLOCK_ID}.json" 2>/dev/null || true
    fi

    if [ -s "${RESULTS_DIR}/ftp_${BLOCK_ID}.txt" ]; then
        echo "[BLOCK $BLOCK_ID] Grabbing FTP banners..."
        zgrab2 ftp -f "${RESULTS_DIR}/ftp_${BLOCK_ID}.txt" \
            -o "${RESULTS_DIR}/ftp_banners_${BLOCK_ID}.json" 2>/dev/null || true
    fi

    # RTSP probe (zgrab2 doesn't support RTSP well, use netcat directly)
    if [ -s "${RESULTS_DIR}/rtsp_${BLOCK_ID}.txt" ]; then
        echo "[BLOCK $BLOCK_ID] Probing RTSP streams..."
        while IFS= read -r ip; do
            {
                printf "DESCRIBE rtsp://%s:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n" "$ip"
                sleep 1
            } | nc -w 3 "$ip" 554 2>/dev/null || true
        done < "${RESULTS_DIR}/rtsp_${BLOCK_ID}.txt" > "${RESULTS_DIR}/rtsp_responses_${BLOCK_ID}.txt" 2>/dev/null || true
    fi

    echo "[BLOCK $BLOCK_ID] Protocol banners saved"
    save_state "proto_banners_complete" "protocol banners done" true true false
}

# ---------- Step 4: Camera/IoT Detection with nuclei ----------
step_nuclei_scan() {
    echo "[BLOCK $BLOCK_ID] Starting nuclei camera/IoT detection..."

    if [ ! -f "$MASSCAN_OUT" ] || [ ! -s "$MASSCAN_OUT" ]; then
        echo "[BLOCK $BLOCK_ID] No masscan results, skipping nuclei"
        echo '[]' > "$NUCLEI_OUT"
        return 0
    fi

    # Extract all IPs for nuclei scanning
    grep -oP '"ip":"\K[^"]+' "$MASSCAN_OUT" 2>/dev/null | \
        sort -u > "${RESULTS_DIR}/nuclei_targets_${BLOCK_ID}.txt" || true

    if [ ! -s "${RESULTS_DIR}/nuclei_targets_${BLOCK_ID}.txt" ]; then
        echo "[BLOCK $BLOCK_ID] No nuclei targets found"
        echo '[]' > "$NUCLEI_OUT"
        return 0
    fi

    # Build nuclei template arguments
    TEMPLATE_DIR="${GITHUB_WORKSPACE:-$PWD}/templates"
    NUCLEI_ARGS="-t ${TEMPLATE_DIR}/camera-templates.yaml"

    # Also try to use nuclei's built-in IoT templates
    for NUCLEI_DIR in "${HOME}/nuclei-templates" "/root/nuclei-templates" "/opt/nuclei-templates"; do
        if [ -d "${NUCLEI_DIR}/iot" ]; then
            NUCLEI_ARGS="$NUCLEI_ARGS -t ${NUCLEI_DIR}/iot"
            break
        fi
    done

    if ! nuclei -l "${RESULTS_DIR}/nuclei_targets_${BLOCK_ID}.txt" \
        $NUCLEI_ARGS \
        -json -o "$NUCLEI_OUT" \
        -timeout 5 -retries 1 \
        -concurrency 25 \
        2>&1; then
        echo "[BLOCK $BLOCK_ID] nuclei encountered errors (partial results saved)"
    fi

    echo "[BLOCK $BLOCK_ID] nuclei scan complete ($(wc -l < "$NUCLEI_OUT" 2>/dev/null || echo 0) findings)"
    save_state "nuclei_complete" "nuclei done" true true true
}

# ---------- Step 5: Camera-specific analysis ----------
step_camera_analysis() {
    echo "[BLOCK $BLOCK_ID] Running camera-specific analysis..."

    # Use a temp file for accumulation, then deduplicate
    CAMERA_TMP="$(mktemp)"
    echo '[]' > "$CAMERAS_OUT"

    # Detection 1: RTSP hosts (highest confidence - open RTSP = direct video stream)
    if [ -s "${RESULTS_DIR}/rtsp_${BLOCK_ID}.txt" ]; then
        while IFS= read -r ip; do
            echo "{\"ip\":\"$ip\",\"type\":\"rtsp\",\"port\":554,\"confidence\":5,\"source\":\"rtsp_port\"}" >> "$CAMERA_TMP"
        done < "${RESULTS_DIR}/rtsp_${BLOCK_ID}.txt"
    fi

    # Detection 2: Camera HTTP interfaces from httpx banners
    if [ -f "$HTTP_BANNERS" ] && [ -s "$HTTP_BANNERS" ]; then
        python3 -c "
import json, sys

camera_keywords = ['camera', 'webcam', 'dvr', 'nvr', 'axis', 'hikvision', 
                   'dahua', 'vivotek', 'onvif', 'liveview', 'mjpeg',
                   'snapshot', 'cctv', 'surveillance']

try:
    with open('$HTTP_BANNERS') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                entry = json.loads(line)
            except:
                continue
            
            ip = entry.get('host', entry.get('ip', ''))
            if not ip: continue
            
            title = (entry.get('title', '') or '').lower()
            server = (entry.get('server', '') or '').lower()
            status = entry.get('status_code', 0)
            
            # Check for camera fingerprints
            is_camera = any(k in title or k in server for k in camera_keywords)
            has_login = any(w in title for w in ['login','sign in','password','unauthorized','authenticate'])
            
            if is_camera:
                result = {
                    'ip': ip,
                    'port': entry.get('port', 80),
                    'type': 'no_auth_camera' if (status == 200 and not has_login) else 'camera_web',
                    'title': entry.get('title', ''),
                    'server': server,
                    'url': entry.get('url', ''),
                    'status_code': status,
                    'confidence': 5 if (status == 200 and not has_login) else 3,
                    'source': 'http_banner'
                }
                with open('$CAMERA_TMP', 'a') as out:
                    out.write(json.dumps(result) + '\n')
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" 2>&1 || true
    fi

    # Detection 3: Nuclei findings (already tagged by templates)
    if [ -f "$NUCLEI_OUT" ] && [ -s "$NUCLEI_OUT" ]; then
        cat "$NUCLEI_OUT" >> "$CAMERA_TMP" 2>/dev/null || true
    fi

    # Detection 4: Known camera web ports (8000=Hikvision, 8080=common, 81/82/88=alt)
    for port in 8000 8080 81 82 88; do
        grep -oP '"ip":"\K[^"]+(?=.*"port":'"$port"'[,}])' "$MASSCAN_OUT" 2>/dev/null | \
            while IFS= read -r ip; do
                echo "{\"ip\":\"$ip\",\"type\":\"camera_port\",\"port\":$port,\"confidence\":2,\"source\":\"port_hint\"}" >> "$CAMERA_TMP"
            done || true
    done

    # Deduplicate and write final results
    if [ -s "$CAMERA_TMP" ]; then
        sort -u "$CAMERA_TMP" | python3 -c "
import json, sys
seen = set()
results = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        entry = json.loads(line)
        ip = entry.get('ip', '')
        if ip and ip not in seen:
            seen.add(ip)
            results.append(entry)
    except:
        pass
print(json.dumps(results, indent=2))
" > "$CAMERAS_OUT" 2>/dev/null || true
    fi

    rm -f "$CAMERA_TMP"
    CAMERA_COUNT=$(wc -l < "$CAMERAS_OUT" 2>/dev/null || echo 0)
    echo "[BLOCK $BLOCK_ID] Camera analysis complete: $CAMERA_COUNT potential cameras"
}

# ---------- Step 6: Generate Summary ----------
step_summary() {
    echo "[BLOCK $BLOCK_ID] Generating summary..."

    HOSTS=$(wc -l < "$ALL_LIVE_HOSTS" 2>/dev/null || echo 0)
    HTTP_BANNER_COUNT=$(wc -l < "$HTTP_BANNERS" 2>/dev/null || echo 0)
    NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT" 2>/dev/null || echo 0)
    CAMERA_COUNT=$(wc -l < "$CAMERAS_OUT" 2>/dev/null || echo 0)
    MASSCAN_SIZE=$(wc -c < "$MASSCAN_OUT" 2>/dev/null || echo 0)

    # Count per-port stats
    PORT_STATS="{}"
    if [ -f "$MASSCAN_OUT" ] && [ -s "$MASSCAN_OUT" ]; then
        PORT_STATS=$(grep -oP '"port":\K[0-9]+' "$MASSCAN_OUT" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -20 | \
            awk '{printf "%s:%d,", $2, $1}' | sed 's/,$//') || PORT_STATS="{}"
    fi

    cat > "$SUMMARY_OUT" <<EOF
{
  "block_id": $BLOCK_ID,
  "cidr": "$CIDR",
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_hosts_found": $HOSTS,
  "http_banners_grabbed": $HTTP_BANNER_COUNT,
  "nuclei_findings": $NUCLEI_COUNT,
  "potential_cameras": $CAMERA_COUNT,
  "masscan_output_bytes": $MASSCAN_SIZE,
  "top_ports": "$PORT_STATS"
}
EOF

    echo "[BLOCK $BLOCK_ID] Summary written"
}

# ---------- Main Execution ----------
echo "============================================================"
echo "  Scanning Block $BLOCK_ID: $CIDR"
echo "============================================================"

# Run all steps sequentially (each saves its own state)
step_masscan
step_http_banners
step_proto_banners
step_nuclei_scan
step_camera_analysis
step_summary

# Final state
save_state "completed" "All scans complete" true true true

echo "============================================================"
echo "  Block $BLOCK_ID COMPLETE"
echo "  Results in: $RESULTS_DIR"
echo "============================================================"
