#!/bin/bash
# ============================================================
# ROV Audit Pipeline — Crontab Driver
#
# Usage (add to crontab with: crontab -e):
#
#   # Atlas forensics: nightly at 02:00
#   0 2 * * * /home/terry/rov_audit/rov_cron.sh atlas >> /home/terry/rov_audit/logs/cron.log 2>&1
#
#   # Full topology rebuild + reports: weekly Sunday 03:00
#   0 3 * * 0 /home/terry/rov_audit/rov_cron.sh full >> /home/terry/rov_audit/logs/cron.log 2>&1
#
#   # Reports-only refresh: daily at 06:00 (uses cached topology)
#   0 6 * * * /home/terry/rov_audit/rov_cron.sh reports >> /home/terry/rov_audit/logs/cron.log 2>&1
#
#   # Commit report outputs: monthly on the 1st at 07:00
#   0 7 1 * * /home/terry/rov_audit/rov_cron.sh commit >> /home/terry/rov_audit/logs/cron.log 2>&1
#
# Modes:
#   atlas    — run batch_verify_smart_v4.py (5 Atlas targets, fast ~5 min)
#   reports  — run do_reports (audit + analysis + HTML generation)
#   full     — do_data_gathering + atlas + reports (weekly heavyweight run)
#   commit   — git commit changed report outputs (monthly, local commit only — no push)
#
# Lock files prevent overlapping runs of the same mode.
# ============================================================

set -euo pipefail

MODE="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOCK_DIR="$SCRIPT_DIR/.locks"
PYTHON=python3

mkdir -p "$LOG_DIR" "$LOCK_DIR"

# -----------------------------------------------------------
# Timestamped logging
# -----------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

die() {
    log "ERROR: $*"
    exit 1
}

# -----------------------------------------------------------
# Lock helper: acquire an exclusive lock for the given mode.
# Exits 0 (success) on acquisition, skips silently if already
# running (another cron slot fired before previous finished).
# -----------------------------------------------------------
LOCK_FILE=""
acquire_lock() {
    local name="$1"
    LOCK_FILE="$LOCK_DIR/${name}.lock"
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        log "[$name] Another instance is already running (lock: $LOCK_FILE). Skipping."
        exit 0
    fi
    log "[$name] Lock acquired."
}

release_lock() {
    flock -u 9 2>/dev/null || true
}

# -----------------------------------------------------------
# Stage: Atlas forensics
# -----------------------------------------------------------
run_atlas() {
    log "[atlas] Starting Atlas forensic batch (limit=5)..."
    cd "$SCRIPT_DIR"
    $PYTHON batch_verify_smart_v4.py --limit 5
    log "[atlas] Done."
}

# -----------------------------------------------------------
# Stage: Reports
# Reports calls sync_apnic_timeseries internally via rov_no_scrape_v22.py.
# That function fetches ~600 stale APNIC cache files on first run after
# cache expiry (7-day TTL), each with a 15s network timeout.  We wrap the
# entire reports stage in a generous timeout (3 hours) to allow completion
# while preventing a hung network call from blocking the cron slot forever.
# -----------------------------------------------------------
run_reports() {
    log "[reports] Starting report suite..."
    cd "$SCRIPT_DIR"
    # timeout(1) exits 124 on timeout — treat as non-fatal so the cron
    # slot finishes cleanly and the partial output is still useful.
    if timeout 10800 bash do_reports; then
        log "[reports] Done."
    else
        local rc=$?
        if [ $rc -eq 124 ]; then
            log "[reports] WARNING: do_reports timed out after 3 hours. Partial output may be available."
        else
            log "[reports] WARNING: do_reports exited with code $rc."
        fi
    fi
}

# -----------------------------------------------------------
# Stage: Full data gathering (topology rebuild)
# Heavy: downloads 5 RIB dumps (~500 MB each), runs Go extractors,
# rebuilds topology, syncs ROA + timeseries, packs ASN data.
# Timeout: 6 hours.
# -----------------------------------------------------------
run_data_gathering() {
    log "[data] Starting full data gathering pipeline..."
    cd "$SCRIPT_DIR"
    if timeout 21600 bash do_data_gathering; then
        log "[data] Done."
    else
        local rc=$?
        if [ $rc -eq 124 ]; then
            die "do_data_gathering timed out after 6 hours."
        else
            die "do_data_gathering failed with exit code $rc."
        fi
    fi
}

# -----------------------------------------------------------
# Stage: Commit report outputs
# Only stages *already-tracked* files under reports/, root-level CSVs,
# and logs/cron.log (git add -u), so it can never sweep in unrelated
# untracked files (secrets, new scratch scripts, etc.). Commits nothing
# and exits cleanly if there are no changes. Local commit only — never
# pushes.
# -----------------------------------------------------------
run_commit() {
    log "[commit] Checking for changed report outputs..."
    cd "$SCRIPT_DIR"
    git add -u -- reports/ '*.csv' logs/cron.log
    if git diff --cached --quiet; then
        log "[commit] No changes to commit."
        return
    fi
    local msg
    msg="chore: monthly report output snapshot ($(date '+%Y-%m'))"
    git commit -m "$msg" >/dev/null
    log "[commit] Committed: $msg"
}

# -----------------------------------------------------------
# Main dispatch
# -----------------------------------------------------------
case "$MODE" in
    atlas)
        acquire_lock atlas
        trap release_lock EXIT
        run_atlas
        ;;
    reports)
        acquire_lock reports
        trap release_lock EXIT
        run_reports
        ;;
    full)
        acquire_lock full
        trap release_lock EXIT
        log "[full] === Weekly full pipeline start ==="
        run_data_gathering
        run_atlas
        run_reports
        log "[full] === Weekly full pipeline complete ==="
        ;;
    commit)
        acquire_lock commit
        trap release_lock EXIT
        run_commit
        ;;
    *)
        echo "Usage: $0 {atlas|reports|full|commit}"
        echo ""
        echo "  atlas    — RIPE Atlas forensic batch (nightly, ~5 min)"
        echo "  reports  — Audit + analysis + HTML reports (daily, ~30 min)"
        echo "  full     — Topology rebuild + atlas + reports (weekly, ~2-3 hr)"
        echo "  commit   — Commit changed report outputs (monthly, local only)"
        exit 1
        ;;
esac
