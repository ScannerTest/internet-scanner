#!/bin/bash
# ============================================================
# merge-results.sh - Merge all scanning block results
#
# Downloads artifacts from all scan jobs, deduplicates,
# and produces the final combined dataset.
# ============================================================
set -euo pipefail

ARTIFACTS_DIR="${1:-scan_results}"
OUTPUT_DIR="${2:-final_results}"

mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "  Merging scanning results"
echo "  Artifacts: $ARTIFACTS_DIR"
echo "  Output:    $OUTPUT_DIR"
echo "============================================================"

# ---------- Collect all block results ----------
echo "Collecting results from all blocks..."

COMBINED_CAMERAS="${OUTPUT_DIR}/all_cameras.json"
COMBINED_HTTP_BANNERS="${OUTPUT_DIR}/all_http_banners.json"
COMBINED_HOSTS="${OUTPUT_DIR}/all_hosts.txt"
COMBINED_SUMMARY="${OUTPUT_DIR}/scan_summary.json"
COMBINED_TOP_PORTS="${OUTPUT_DIR}/top_ports.csv"
TIMELINE="${OUTPUT_DIR}/scan_timeline.json"

# Initialize files
echo '[]' > "$COMBINED_CAMERAS"
echo '[]' > "$COMBINED_HTTP_BANNERS"
> "$COMBINED_HOSTS"

# Find all block result directories
BLOCK_DIRS=()
if [ -d "$ARTIFACTS_DIR" ]; then
    # Try direct files first (merge-multiple: true)
    HAS_FILES=0
    for f in "$ARTIFACTS_DIR"/state_*.json; do
        [ -f "$f" ] && HAS_FILES=1 && break
    done
    
    if [ "$HAS_FILES" -eq 1 ]; then
        # Files are merged directly into artifacts dir
        BLOCK_DIRS=("$ARTIFACTS_DIR")
        echo "Using merged artifact directory"
    else
        # Files are in subdirectories (pattern: scan_results/block_*/)
        for d in "$ARTIFACTS_DIR"/block_*; do
            [ -d "$d" ] && BLOCK_DIRS+=("$d")
        done
        echo "Found ${#BLOCK_DIRS[@]} block subdirectories"
    fi
fi

TOTAL_HOSTS=0
TOTAL_CAMERAS=0
BLOCK_COUNT=0
BLOCK_REPORTS=()

# ---------- Process each block ----------
for block_dir in "${BLOCK_DIRS[@]}"; do
    BLOCK_ID=$(basename "$block_dir" | sed 's/block_//')
    # If block_dir is the root artifacts dir, extract block_id from filenames
    if [ "$BLOCK_ID" = "$ARTIFACTS_DIR" ]; then
        # Process all state files to find individual blocks
        for state_file in "$block_dir"/state_*.json; do
            [ -f "$state_file" ] || continue
            BID=$(basename "$state_file" | sed 's/state_//;s/\.json//')
            
            # Summary
            summary_file="${block_dir}/summary_${BID}.json"
            if [ -f "$summary_file" ]; then
                BLOCK_REPORTS+=("$summary_file")
            fi
            
            # Live hosts
            hosts_file="${block_dir}/live_hosts_${BID}.txt"
            [ -f "$hosts_file" ] && cat "$hosts_file" >> "$COMBINED_HOSTS"
            
            # Cameras (NDJSON format)
            cams_file="${block_dir}/cameras_${BID}.json"
            if [ -f "$cams_file" ] && [ -s "$cams_file" ]; then
                if head -c 1 "$cams_file" | grep -q '\['
                then
                    python3 -c "
import json
try:
    items = json.load(open('$cams_file'))
    with open('${COMBINED_CAMERAS}.tmp', 'a') as f:
        for item in items:
            f.write(json.dumps(item) + '\n')
except:
    pass
" 2>/dev/null || true
                else
                    cat "$cams_file" >> "${COMBINED_CAMERAS}.tmp" 2>/dev/null || true
                fi
            fi
            BLOCK_COUNT=$((BLOCK_COUNT + 1))
        done
    else
        # Traditional block subdirectory
        summary_file="${block_dir}/summary_${BLOCK_ID}.json"
        if [ -f "$summary_file" ]; then
            BLOCK_REPORTS+=("$summary_file")
        fi
        
        hosts_file="${block_dir}/live_hosts_${BLOCK_ID}.txt"
        [ -f "$hosts_file" ] && cat "$hosts_file" >> "$COMBINED_HOSTS"

        cams_file="${block_dir}/cameras_${BLOCK_ID}.json"
        if [ -f "$cams_file" ] && [ -s "$cams_file" ]; then
            if head -c 1 "$cams_file" 2>/dev/null | grep -q '\['
            then
                python3 -c "
import json
try:
    items = json.load(open('$cams_file'))
    with open('${COMBINED_CAMERAS}.tmp', 'a') as f:
        for item in items:
            f.write(json.dumps(item) + '\n')
except:
    pass
" 2>/dev/null || true
            else
                cat "$cams_file" >> "${COMBINED_CAMERAS}.tmp" 2>/dev/null || true
            fi
        fi
        BLOCK_COUNT=$((BLOCK_COUNT + 1))
    fi
done

# ---------- Collect HTTP banners from chunked httpx results ----------
# http_banners_BLOCKID_CHUNKID.json are merged into the artifacts dir
# by the http-banners job (copied from http_banners/ into scan_results/)
echo "Collecting HTTP banner chunks..."
HTTP_CHUNK_COUNT=0
for f in "$ARTIFACTS_DIR"/http_banners_*.json; do
    [ -f "$f" ] || continue
    if [ -s "$f" ]; then
        cat "$f" >> "${COMBINED_HTTP_BANNERS}.tmp" 2>/dev/null || true
        HTTP_CHUNK_COUNT=$((HTTP_CHUNK_COUNT + 1))
    fi
done
echo "Collected $HTTP_CHUNK_COUNT HTTP banner chunk files"

# Deduplicate hosts
sort -u "$COMBINED_HOSTS" -o "$COMBINED_HOSTS" 2>/dev/null || true
UNIQUE_HOSTS=$(wc -l < "$COMBINED_HOSTS" 2>/dev/null || echo 0)

# Deduplicate cameras
if [ -f "${COMBINED_CAMERAS}.tmp" ]; then
    sort -u "${COMBINED_CAMERAS}.tmp" > "$COMBINED_CAMERAS" 2>/dev/null || true
    rm -f "${COMBINED_CAMERAS}.tmp"
fi
TOTAL_CAMERAS=$(wc -l < "$COMBINED_CAMERAS" 2>/dev/null || echo 0)

# Deduplicate HTTP banners
if [ -f "${COMBINED_HTTP_BANNERS}.tmp" ]; then
    sort -u "${COMBINED_HTTP_BANNERS}.tmp" > "$COMBINED_HTTP_BANNERS" 2>/dev/null || true
    rm -f "${COMBINED_HTTP_BANNERS}.tmp"
fi

# ---------- Generate Top Ports Stats ----------
echo "port,count" > "$COMBINED_TOP_PORTS"
if [ -d "$ARTIFACTS_DIR" ]; then
    # Use the Python approach for robust port extraction
    python3 -c "
import json, os, glob, sys
from collections import Counter

port_counter = Counter()

# Search for masscan results in various locations
search_paths = ['$ARTIFACTS_DIR']
# Also check subdirectories
for d in glob.glob('$ARTIFACTS_DIR/block_*'):
    search_paths.append(d)

for sp in search_paths:
    if not os.path.isdir(sp):
        continue
    for f in os.listdir(sp):
        if f.startswith('masscan_') and f.endswith('.json'):
            fpath = os.path.join(sp, f)
            try:
                with open(fpath) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line: continue
                        if line in ('[', ']', '{', '}'): continue
                        try:
                            entry = json.loads(line.rstrip(','))
                            port = entry.get('port')
                            if port:
                                port_counter[port] += 1
                        except:
                            pass
            except:
                pass

# Output top 50 ports
for port, count in port_counter.most_common(50):
    print(f'{port},{count}')
" >> "$COMBINED_TOP_PORTS" 2>/dev/null || true
fi

# Compute scan duration from first and last state timestamps
python3 -c "
import json, glob, os
from datetime import datetime

timestamps = []
search_roots = ['$ARTIFACTS_DIR']
for d in glob.glob('$ARTIFACTS_DIR/block_*'):
    search_roots.append(d)

for root in search_roots:
    if not os.path.isdir(root): continue
    for f in os.listdir(root):
        if f.startswith('state_') and f.endswith('.json'):
            try:
                with open(os.path.join(root, f)) as fh:
                    state = json.load(fh)
                ts = state.get('timestamp')
                if ts:
                    timestamps.append(ts)
            except: pass

if timestamps:
    timestamps.sort()
    start = datetime.fromisoformat(timestamps[0])
    end = datetime.fromisoformat(timestamps[-1])
    duration_seconds = (end - start).total_seconds()
else:
    duration_seconds = 0

with open('${OUTPUT_DIR}/duration.json', 'w') as f:
    json.dump({'scan_start': timestamps[0] if timestamps else '', 
               'scan_end': timestamps[-1] if timestamps else '',
               'duration_seconds': duration_seconds}, f, indent=2)
" 2>/dev/null || true

SCAN_DURATION=$(python3 -c "import json; print(json.load(open('${OUTPUT_DIR}/duration.json')).get('duration_seconds', 0))" 2>/dev/null || echo 0)
HOSTS_PER_SEC="N/A"
if [ "$SCAN_DURATION" -gt 0 ] 2>/dev/null; then
    HOSTS_PER_SEC=$(echo "scale=2; $UNIQUE_HOSTS / $SCAN_DURATION" | bc 2>/dev/null || echo "N/A")
fi

# Generate Summary
python3 -c "
import json
summary = {
    'scan_date': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'blocks_processed': $BLOCK_COUNT,
    'unique_hosts_found': $UNIQUE_HOSTS,
    'potential_cameras': $TOTAL_CAMERAS,
    'scan_duration_seconds': $SCAN_DURATION,
    'hosts_per_second': '$HOSTS_PER_SEC',
}
print(json.dumps(summary, indent=2))
" > "$COMBINED_SUMMARY"

# Generate Timeline from block summaries
if [ ${#BLOCK_REPORTS[@]} -gt 0 ]; then
    python3 -c "
import json, sys
reports = []
for path in sys.argv[1:]:
    try:
        reports.append(json.load(open(path)))
    except: pass
print(json.dumps(reports, indent=2))
" "${BLOCK_REPORTS[@]}" 2>/dev/null > "$TIMELINE" || echo '[]' > "$TIMELINE"
fi

# Cleanup temp files
rm -f "${OUTPUT_DIR}"/tmp_*.tmp 2>/dev/null || true

echo ""
echo "============================================================"
echo "  MERGE COMPLETE"
echo "  Blocks processed: $BLOCK_COUNT"
echo "  Unique hosts:     $UNIQUE_HOSTS"
echo "  Cameras found:    $TOTAL_CAMERAS"
echo "  Scan duration:    ${SCAN_DURATION}s ($HOSTS_PER_SEC hosts/s)"
echo "============================================================"
