#!/usr/bin/env bash
#
# high-admission-trace.sh
#
# Traces what's actually causing an appliance's high admission (adm)
# event volume back to a switch/port/MAC (and, where known, an IP).
# Built and verified live 2026-09-15 against a real Cisco 3560
# (192.168.22.221) via controlled port-bounce tests -- see
# "High Admission Root-Cause Tracing" in the vault for the full method
# and the real log-line examples this was built from.
#
# Run this ON the appliance itself, as root, by default -- it reads
# /usr/local/forescout/stats/today.log and
# /usr/local/forescout/log/sw_mac_track.log directly, and queries this
# appliance's own Postgres for MAC->IP. `analyze -b` is the exception:
# it runs anywhere (no fstool/psql needed) against an already-collected
# bundle instead, for offline/remote-site analysis of a case someone
# else collected.
#
# Three modes:
#
#   analyze (default) -- read-only. Sums admission-source counters from
#   today.log over a time window (learn.adm.swport vs
#   learn.adm.wifi/wifi_lap/dhcp/online_again/agent_adm -- confirmed
#   live these are genuinely separate counters, so this alone answers
#   "switch or wireless" before touching anything else), then ranks
#   switch/port/MAC activity from sw_mac_track.log in the same window
#   (this log runs at baseline debug, no elevation needed). Safe to run
#   standalone, no coordination needed -- start here. Add -b <bundle> to
#   run against a collected bundle instead of this live appliance (see
#   below).
#
#   live -- opt-in, active. Elevates Switch-plugin debug scoped to one
#   or more specific switches at the empirically-confirmed sweet spot
#   (--keylevel 1 -- confirmed live this captures the full switch/port/
#   MAC/VLAN/admission picture with none of --keylevel 4's SNMP/PoE/
#   property-diff noise), waits out the window, then reports the real
#   admission/trap lines captured from plugin/sw/sw.log. Debug is
#   always cleared on exit. Use this once `analyze` has narrowed down a
#   suspect switch, for full port/VLAN confirmation and precise timing.
#
#   collect -- builds a real Forescout tech-support bundle (`fstool
#   tech-support -p sw --pack`) carrying everything `analyze` needs:
#   a time-windowed excerpt of today.log, of sw_mac_track.log, and a
#   plain-text mac_ip (MAC->IP) export, all --attach-file'd (a standard
#   `-p sw` bundle does NOT include today.log/sw_mac_track.log/mac_ip by
#   default -- confirmed against a real bundle; it DOES already include
#   the full sw.log history natively, no extra step needed for that
#   part). Windowed excerpts, not whole files -- today.log alone runs
#   100+MB on a live box. Hand the resulting .tgz to `analyze -b`
#   anywhere, no live appliance access needed.
#
# Two checks added 2026-09-15 after applying this to a real LSEG
# production incident where no switch-plugin trace data existed at all
# (debug wasn't active when it happened) -- both work from today.log
# alone, so they still say something useful even in that situation:
#
#   - Peak-window connected-device write activity: for the busiest
#     admission-volume reporting windows, ranks every connected device's
#     <ip>.write.count/.write.bytes -- a device with dramatically more
#     writes than its peers during a spike is a possible contributing/
#     symptomatic device. Confirmed live against the real LSEG bundle:
#     surfaced one device at 30-50x every peer's write volume, consistent
#     across 5 separate spike windows.
#   - Stale MAC->IP flag: flags any MAC->IP mapping whose "known as of"
#     age exceeds a threshold (default 7 days) as suspiciously stale.
#     Doesn't prove any specific bug, but operationalizes a real
#     hypothesis from that same incident: SNMP TimeTicks (centiseconds)
#     misread as plain seconds inflates a real ARP age 100x, so a
#     genuinely-fresh mapping can appear many weeks old -- exactly the
#     shape this flag is built to catch, regardless of the exact cause.
#
# Two more checks added 2026-09-15 (second pass) after a second real
# LSEG bundle turned up actual sw.log trace lines (33 sw_send_adm_by_mac
# lines, despite conf.debug.level=0 -- confirmed some debug had been left
# on). Both read sw.log directly, so unlike the two checks above they
# need trace data to exist -- not guaranteed, same caveat as the
# switch/port/MAC section:
#
#   - Repeated re-admission pattern: flags any MAC re-admitted 3+ times
#     on the same switch with roughly consistent spacing between
#     admissions. Confirmed live against the real bundle: 4 independent
#     hosts across 2 switches, all re-admitting every ~18-21 minutes --
#     strong mechanistic support for a periodic recheck cycle
#     re-admitting instead of silently reconfirming (the same
#     ARP-staleness hypothesis above, but caught in the act).
#   - Switch poll-cycle intervals + ARP entry age: MAC-table read
#     interval per switch (from switch_query_macs_cb burst timing) and
#     an ARP-entry refresh interval (from switch_delete_ip_entries --
#     global only, this event isn't switch-keyed at baseline debug).
#     Also reports the ARP entry age distribution straight from sw.log's
#     own arp_list time= field -- confirmed live this really does show
#     ages up to ~233 days in the same bundle, directly corroborating
#     the reported ">63 day" ARP-age symptom from switch-log evidence
#     itself, independent of the mac_ip-table-based stale flag above.
#
# Usage:
#   ./high-admission-trace.sh analyze [-w <window>] [-k <switch-ip>[,<switch-ip>...]] [-n <top-N>] [-s <spike-N>] [-a <stale-days>] [-b <bundle.tgz|bundle-dir>]
#   ./high-admission-trace.sh live -k <switch-ip>[,<switch-ip>...] [-d <duration>]
#   ./high-admission-trace.sh collect [-w <window>] [-c <case-ref>]
#
#   -w  How far back to look, e.g. 30m, 2h, 1d (analyze/collect; default 1h)
#   -k  Switch IP(s), comma-separated (optional filter in analyze mode;
#       required in live mode)
#   -n  Top-N switch/port/MAC entries to report (analyze mode; default 10)
#   -s  Top-N peak admission-volume windows to inspect for connected-device
#       write outliers (analyze mode; default 5; 0 disables this check)
#   -a  Flag a MAC->IP mapping as stale if older than this many days
#       (analyze mode; default 7; 0 disables this check)
#   -d  Debug capture duration for live mode, e.g. 15m (default 15m)
#   -b  Analyze a bundle instead of this live appliance -- a .tgz (auto-
#       extracted to a temp dir) or an already-unpacked bundle directory
#   -c  Case reference / comment for the bundle (collect mode)
#   -h  Show this help
#
set -euo pipefail

VERSION="1.3.1"

# Overridden below when -b points analyze at a bundle instead of this
# live appliance -- everything else in the script reads through these
# three variables, never the literal /usr/local/forescout/... paths, so
# live vs. bundle analysis is the same code path either way.
TODAY_LOG="/usr/local/forescout/stats/today.log"
MAC_TRACK_LOG="/usr/local/forescout/log/sw_mac_track.log"
SW_PLUGIN_LOG="/usr/local/forescout/log/plugin/sw/sw.log"
MAC_IP_CSV=""   # only set in bundle mode -- live mode queries psql directly instead

# analyze mode's sw.log source list. Live: the single file above, if
# present. Bundle: sw.log rotates (a real bundle can carry 100+ rotated
# sw.<epoch>.<pid>.log files, confirmed against a real LSEG bundle), so
# this is every rotation found, fed to awk as multiple files at once.
SW_PLUGIN_LOG_FILES=()

usage() {
    cat <<USAGE
high-admission-trace.sh v${VERSION}

Usage:
  $0 analyze [-w <window>] [-k <switch-ip>[,<switch-ip>...]] [-n <top-N>] [-s <spike-N>] [-a <stale-days>] [-b <bundle.tgz|bundle-dir>]
  $0 live -k <switch-ip>[,<switch-ip>...] [-d <duration>]
  $0 collect [-w <window>] [-c <case-ref>]

  analyze  Read-only: admission-source breakdown, top switch/port/MAC activity,
           peak-window connected-device write outliers, a stale-MAC->IP flag,
           repeated-re-admission periodicity, and switch poll-cycle/ARP-age
           stats. Safe to run standalone, no coordination needed. Start here.
           Add -b to analyze an already-collected bundle instead of this live
           appliance.
  live     Active: elevates Switch-plugin debug (--keylevel 1, the confirmed
           sweet spot) on the given switch(es), waits out the window, then
           reports the real admission/trap lines captured. Debug is always
           cleared on exit.
  collect  Builds a real tech-support bundle (-p sw --pack) with everything
           analyze needs attached: windowed today.log/sw_mac_track.log excerpts
           and a plain-text mac_ip export (none of these ship in a standard
           bundle by default; sw.log's full history already does). Hand the
           resulting .tgz to `analyze -b` for offline/remote-site analysis.

  -w  How far back to look, e.g. 30m, 2h, 1d (analyze/collect; default 1h)
  -k  Switch IP(s), comma-separated (optional filter in analyze mode;
      required in live mode)
  -n  Top-N switch/port/MAC entries to report (analyze mode; default 10)
  -s  Top-N peak admission-volume windows to inspect for connected-device
      write outliers (analyze mode; default 5; 0 disables this check)
  -a  Flag a MAC->IP mapping as stale if older than this many days
      (analyze mode; default 7; 0 disables this check)
  -d  Debug capture duration for live mode, e.g. 15m (default 15m)
  -b  Analyze a bundle instead of this live appliance -- a .tgz (auto-extracted
      to a temp dir) or an already-unpacked bundle directory
  -c  Case reference / comment for the bundle (collect mode)
  -h  Show this help

analyze/live/collect (without -b) run ON the appliance itself, as root.
analyze -b runs anywhere -- no fstool/psql needed, just the bundle.
USAGE
    exit 1
}

[ $# -eq 0 ] && usage

MODE="$1"; shift
case "$MODE" in
    analyze|live|collect) ;;
    -h|--help) usage ;;
    *) echo "Error: unknown mode '$MODE' (expected 'analyze', 'live', or 'collect')" >&2; usage ;;
esac

WINDOW="1h"
SWITCH_FILTER=""
TOP_N=10
SPIKE_N=5
STALE_DAYS=7
DURATION="15m"
BUNDLE=""
CASE_REF="high-admission-trace"

while getopts "w:k:n:s:a:d:b:c:h" opt; do
    case "$opt" in
        w) WINDOW="$OPTARG" ;;
        k) SWITCH_FILTER="$OPTARG" ;;
        n) TOP_N="$OPTARG" ;;
        s) SPIKE_N="$OPTARG" ;;
        a) STALE_DAYS="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        b) BUNDLE="$OPTARG" ;;
        c) CASE_REF="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

echo "high-admission-trace.sh v${VERSION} -- mode: $MODE"

# Converts a "30m"/"2h"/"1d" style value into seconds.
window_to_seconds() {
    local w="$1"
    local num unit
    unit="${w: -1}"
    num="${w%[smhd]}"
    case "$unit" in
        s) echo $((num)) ;;
        m) echo $((num * 60)) ;;
        h) echo $((num * 3600)) ;;
        d) echo $((num * 86400)) ;;
        *) echo "Error: value '$w' must end in s/m/h/d (e.g. 30m, 2h, 1d)" >&2; exit 1 ;;
    esac
}

# ---- MAC->IP lookup: live psql, or the bundle's plain-text export ----
# Returns mac|ip|ts_human|ts_epoch_seconds -- the raw epoch (4th field) is
# what the stale-mapping check below does its age math against, since
# re-parsing the human-formatted string back into an epoch is more
# fragile than just carrying the number through in the first place.
lookup_mac_ip() {
    local mac="$1"
    if [ -n "$MAC_IP_CSV" ]; then
        # "No match" is a completely normal outcome (most MACs won't have
        # one) -- grep exiting 1 for that must NOT trip set -e/pipefail
        # here, or the whole script aborts the instant it hits the first
        # unmapped MAC (confirmed live: exactly this killed analyze -b
        # silently, no error text at all, since grep's "no match" produces
        # none).
        grep "^${mac}|" "$MAC_IP_CSV" 2>/dev/null | tail -1 || true
    else
        psql -t -F'|' -c "SELECT '${mac}', ((ip>>24)&255)||'.'||((ip>>16)&255)||'.'||((ip>>8)&255)||'.'||(ip&255), to_char(to_timestamp(time/1000),'YYYY-MM-DD HH24:MI:SS'), (time/1000)::bigint FROM mac_ip WHERE mac='${mac}' ORDER BY time DESC LIMIT 1;" 2>/dev/null | head -1 || true
    fi
}

# ==================================================================
# live mode
# ==================================================================
if [ "$MODE" = "live" ]; then
    if [ -z "$SWITCH_FILTER" ]; then
        echo "Error: live mode requires -k <switch-ip>[,<switch-ip>...]" >&2
        exit 1
    fi
    if ! command -v fstool >/dev/null 2>&1; then
        echo "Error: fstool not found -- this script must run on a Forescout appliance/EM." >&2
        exit 1
    fi

    DUR_SECONDS=$(window_to_seconds "$DURATION")
    START_EPOCH=$(date +%s)

    IFS=',' read -ra SWITCHES <<< "$SWITCH_FILTER"

    cleanup() {
        echo
        echo "=== Clearing debug (always runs, including on Ctrl-C) ==="
        fstool tech-support debug --clear-all sw >/dev/null 2>&1 || true
    }
    trap cleanup EXIT INT TERM

    echo "=== Elevating Switch-plugin debug (--keylevel 1) for: ${SWITCHES[*]} ==="
    for sw_ip in "${SWITCHES[@]}"; do
        fstool tech-support debug -t "$DURATION" -k "$sw_ip" --keylevel 1 --level 0 sw
    done
    fstool tech-support debug -l

    echo
    echo "=== Waiting out the ${DURATION} capture window ==="
    echo "(bounce/reproduce the issue now if this is a manual test -- Ctrl-C to stop early and report what's captured so far)"
    sleep "$DUR_SECONDS"

    END_EPOCH=$(date +%s)

    echo
    echo "=== Admission/trap events captured for ${SWITCHES[*]} in this window ==="
    if [ ! -f "$SW_PLUGIN_LOG" ]; then
        echo "No $SW_PLUGIN_LOG found -- nothing captured."
        exit 0
    fi

    SWITCH_GREP=$(IFS='|'; echo "${SWITCHES[*]}")
    awk -v s="$START_EPOCH" -v e="$END_EPOCH" -v switches="$SWITCH_GREP" '
        BEGIN { n = split(switches, sw_arr, "|"); for (i = 1; i <= n; i++) want[sw_arr[i]] = 1 }
        {
            # Real lines are "sw-<worker#>:<pid>:<epoch>.<usec>:..." (multi-
            # threaded plugin, confirmed against a real bundle) -- a bare
            # "sw:" prefix with no worker suffix never actually appears
            # outside a single-threaded test, so this must allow both or it
            # silently matches nothing on a busy appliance.
            if (!match($0, /^sw-?[0-9]*:[0-9]+:([0-9]+)\./, m)) next
            epoch = m[1] + 0
            if (epoch < s || epoch > e) next
            matched = 0
            for (ip in want) { if (index($0, ip) > 0) { matched = 1; break } }
            if (!matched) next
            if ($0 !~ /sw_send_adm_by_mac|sw_send_trap_event_by_mac|sw_resolve_all:2205/) next
            print
        }
    ' "$SW_PLUGIN_LOG"

    exit 0
fi

# ==================================================================
# collect mode
# ==================================================================
if [ "$MODE" = "collect" ]; then
    if ! command -v fstool >/dev/null 2>&1; then
        echo "Error: fstool not found -- this script must run on a Forescout appliance/EM." >&2
        exit 1
    fi

    WINDOW_SECONDS=$(window_to_seconds "$WINDOW")
    END_EPOCH=$(date +%s)
    START_EPOCH=$((END_EPOCH - WINDOW_SECONDS))

    WORKDIR=$(mktemp -d /tmp/hat-collect.XXXXXX)
    echo "=== Building windowed excerpts in $WORKDIR ==="

    TODAY_EXCERPT="$WORKDIR/today.log.excerpt"
    if [ -f "$TODAY_LOG" ]; then
        awk -v s="$START_EPOCH" -v e="$END_EPOCH" '$1 == "p" && $2 >= s && $2 <= e' "$TODAY_LOG" > "$TODAY_EXCERPT"
        echo "  today.log excerpt: $(wc -l < "$TODAY_EXCERPT") lines"
    else
        echo "  (no $TODAY_LOG found -- skipping)"
        : > "$TODAY_EXCERPT"
    fi

    MAC_TRACK_EXCERPT="$WORKDIR/sw_mac_track.log.excerpt"
    if [ -f "$MAC_TRACK_LOG" ]; then
        awk -v s="$START_EPOCH" -v e="$END_EPOCH" '{ split($1,t,"."); if (t[1]+0>=s && t[1]+0<=e) print }' "$MAC_TRACK_LOG" > "$MAC_TRACK_EXCERPT"
        echo "  sw_mac_track.log excerpt: $(wc -l < "$MAC_TRACK_EXCERPT") lines"
    else
        echo "  (no $MAC_TRACK_LOG found -- skipping)"
        : > "$MAC_TRACK_EXCERPT"
    fi

    MAC_IP_EXPORT="$WORKDIR/mac_ip.csv"
    psql -t -F'|' -c "SELECT mac, ((ip>>24)&255)||'.'||((ip>>16)&255)||'.'||((ip>>8)&255)||'.'||(ip&255), to_char(to_timestamp(time/1000),'YYYY-MM-DD HH24:MI:SS'), (time/1000)::bigint FROM mac_ip ORDER BY mac, time;" 2>/dev/null \
        | sed 's/ *| */|/g; s/^ *//; s/ *$//' > "$MAC_IP_EXPORT" || : > "$MAC_IP_EXPORT"
    echo "  mac_ip export: $(wc -l < "$MAC_IP_EXPORT") rows"

    echo
    echo "=== Building the bundle (fstool tech-support -p sw --pack) ==="
    echo "(sw.log's full history is already included natively -- confirmed, no extra attach needed for that)"
    fstool tech-support \
        --attach-file "$TODAY_EXCERPT" \
        --attach-file "$MAC_TRACK_EXCERPT" \
        --attach-file "$MAC_IP_EXPORT" \
        -p sw -comment "$CASE_REF" --pack -t "$WINDOW"

    echo
    echo "=== Done -- look for the .tgz fstool just reported above (typically /tmp) ==="
    echo "Hand it to: $0 analyze -b <bundle.tgz>"
    rm -rf "$WORKDIR"
    exit 0
fi

# ==================================================================
# analyze mode
# ==================================================================

if [ -n "$BUNDLE" ]; then
    if [ -d "$BUNDLE" ]; then
        BUNDLE_ROOT="$BUNDLE"
    elif [ -f "$BUNDLE" ]; then
        BUNDLE_ROOT=$(mktemp -d /tmp/hat-unpack.XXXXXX)
        echo "=== Unpacking $BUNDLE to $BUNDLE_ROOT ==="
        # Always clean this up on exit, success or failure -- confirmed
        # live this leaked multiple GB per run otherwise (an 867MB real
        # bundle expands to ~8GB unpacked), compounding across repeated
        # runs into real disk pressure.
        trap 'rm -rf "$BUNDLE_ROOT"' EXIT
        tar -xzf "$BUNDLE" -C "$BUNDLE_ROOT"
    else
        echo "Error: -b '$BUNDLE' is not a file or directory." >&2
        exit 1
    fi

    # A real -p sw bundle roots Forescout's own filesystem under files/usr/local/forescout/...
    # (confirmed against a real bundle) -- attached files preserve their
    # original collection-time path the same way. today.log/sw_mac_track.log/
    # mac_ip.csv are whatever collect mode named them under its own
    # /tmp/hat-collect.XXXXXX/ workdir, so locate them by filename instead of
    # assuming an exact path.
    TODAY_LOG=$(find "$BUNDLE_ROOT" -name "today.log.excerpt" -print -quit 2>/dev/null || true)
    MAC_TRACK_LOG=$(find "$BUNDLE_ROOT" -name "sw_mac_track.log.excerpt" -print -quit 2>/dev/null || true)
    MAC_IP_CSV=$(find "$BUNDLE_ROOT" -name "mac_ip.csv" -print -quit 2>/dev/null || true)

    if [ -z "$TODAY_LOG" ]; then
        # Fall back to the natively-shipped copy under files/usr/local/forescout/stats/,
        # if this bundle happens to have one (not guaranteed -- see header comment).
        TODAY_LOG=$(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/stats/today.log" -print -quit 2>/dev/null || true)
    fi
    if [ -z "$MAC_TRACK_LOG" ]; then
        MAC_TRACK_LOG=$(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/log/sw_mac_track.log" -print -quit 2>/dev/null || true)
    fi

    # sw.log rotates -- collect every rotation under plugin/sw/, not just
    # one file (confirmed against a real bundle: 115 rotated files, trace
    # lines scattered across 18 of them).
    while IFS= read -r f; do
        SW_PLUGIN_LOG_FILES+=("$f")
    done < <(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/log/plugin/sw/sw*.log" 2>/dev/null | sort)

    echo "Bundle sources found: today.log=${TODAY_LOG:-none} sw_mac_track.log=${MAC_TRACK_LOG:-none} mac_ip.csv=${MAC_IP_CSV:-none} sw.log=${#SW_PLUGIN_LOG_FILES[@]} file(s)"
    echo
fi

if [ -z "$BUNDLE" ] && [ -f "$SW_PLUGIN_LOG" ]; then
    SW_PLUGIN_LOG_FILES=("$SW_PLUGIN_LOG")
fi

if [ -z "$TODAY_LOG" ] || [ ! -f "$TODAY_LOG" ]; then
    echo "Error: no today.log source found$( [ -n "$BUNDLE" ] && echo " in this bundle" )." >&2
    exit 1
fi

WINDOW_SECONDS=$(window_to_seconds "$WINDOW")
END_EPOCH=$(date +%s)
START_EPOCH=$((END_EPOCH - WINDOW_SECONDS))

# A bundle's excerpt is already windowed at collect time -- re-filtering
# by "now minus WINDOW" would just discard it, since the bundle could be
# hours or days old by the time someone runs analyze -b on it. Only
# apply the live now-relative window when reading the live appliance's
# actual today.log.
if [ -n "$BUNDLE" ]; then
    START_EPOCH=0
    END_EPOCH=9999999999
    echo "Bundle mode: using every event in the excerpt (already windowed at collect time), not a fresh now-relative window."
else
    echo "Window: last ${WINDOW} ($(date -d "@$START_EPOCH" '+%Y-%m-%d %H:%M:%S') -> $(date -d "@$END_EPOCH" '+%Y-%m-%d %H:%M:%S'))"
fi
echo

echo "=== Admission source breakdown (today.log) ==="
awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
    $1 == "p" && $2 >= s && $2 <= e && $5 ~ /^learn\.adm\./ {
        sum[$5] += $6
    }
    END {
        if (length(sum) == 0) { print "  (no learn.adm.* events in this window)"; exit }
        for (m in sum) printf "  %-24s %d\n", m, sum[m]
    }
' "$TODAY_LOG"

echo
echo "=== Peak-window connected-device write activity (today.log) ==="
if [ "$SPIKE_N" -le 0 ]; then
    echo "  (disabled: -s 0)"
else
    echo "  (a device with dramatically more writes than its peers during a spike is a possible"
    echo "  contributing/symptomatic device -- not proof of causation on its own. Confirmed live"
    echo "  against a real incident: surfaced one device at 30-50x every peer, across 5 spikes.)"
    # Single pass over today.log emitting just the two metric families this
    # check needs, tagged -- avoids re-reading a 100-500+MB file twice for
    # "find the spikes" and "rank devices within them" separately.
    awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
        $1 == "p" && $2 >= s && $2 <= e {
            epoch = $2
            if ($5 ~ /^learn\.adm\./) { print "ADM", epoch, $6; next }
            if (match($5, /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.write\.count$/, m)) {
                print "WRITE", epoch, m[1], $6
            }
        }
    ' "$TODAY_LOG" > /tmp/.hat_tagged.$$

    awk '$1=="ADM"{sum[$2]+=$3} END{for(e in sum) print sum[e], e}' /tmp/.hat_tagged.$$ | sort -rn > /tmp/.hat_spikes_full.$$
    head -n "$SPIKE_N" /tmp/.hat_spikes_full.$$ > /tmp/.hat_spikes.$$
    rm -f /tmp/.hat_spikes_full.$$

    if [ ! -s /tmp/.hat_spikes.$$ ]; then
        echo "  (no admission spikes found in this window)"
    else
        while IFS=' ' read -r adm_total spike_epoch; do
            spike_h=$(date -d "@$spike_epoch" '+%Y-%m-%d %H:%M:%S')
            echo "  Spike at $spike_h ($adm_total admissions this window):"
            # sed, not head, on the live pipe below -- sed reads all its
            # input before exiting, so it never SIGPIPEs sort upstream the
            # way head closing early would (the exact bug already fixed
            # once in the ranked switch/port/MAC section above).
            awk -v ep="$spike_epoch" '$1=="WRITE" && $2==ep {print $4, $3}' /tmp/.hat_tagged.$$ | sort -rn | sed -n '1,5p' | while read -r wcount ip; do
                printf "    %-15s %s writes\n" "$ip" "$wcount"
            done
        done < /tmp/.hat_spikes.$$
    fi
    rm -f /tmp/.hat_tagged.$$ /tmp/.hat_spikes.$$
fi

echo
echo "=== Top switch/port/MAC activity (sw_mac_track.log) ==="
if [ -z "$MAC_TRACK_LOG" ] || [ ! -f "$MAC_TRACK_LOG" ]; then
    echo "  (no sw_mac_track.log source found$( [ -n "$BUNDLE" ] && echo " in this bundle" ))"
else
    awk -v s="$START_EPOCH" -v e="$END_EPOCH" -v filter="$SWITCH_FILTER" '
        BEGIN {
            if (filter != "") { n = split(filter, f, ","); for (i = 1; i <= n; i++) want[f[i]] = 1 }
        }
        {
            split($1, t, ".")
            epoch = t[1] + 0
            if (epoch < s || epoch > e) next
            if (!match($0, /:([0-9a-f]{12}):/, macm)) next
            mac = macm[1]
            if (!match($0, /ipport\[([0-9.]+):([0-9]+)\]/, ipm)) next
            sw_ip = ipm[1]; port_idx = ipm[2]
            if (filter != "" && !(sw_ip in want)) next
            portname = ""
            if (match($0, /portname\[([^]]*)\]/, pm)) portname = pm[1]
            key = sw_ip SUBSEP port_idx SUBSEP mac
            count[key]++
            if (!(key in first) || epoch < first[key]) first[key] = epoch
            if (!(key in last) || epoch > last[key]) last[key] = epoch
            if (portname != "") pname[key] = portname
        }
        END {
            for (k in count) {
                split(k, parts, SUBSEP)
                printf "%d\t%s\t%s\t%s\t%s\t%d\t%d\n", count[k], parts[1], parts[2], (pname[k] != "" ? pname[k] : "idx:" parts[2]), parts[3], first[k], last[k]
            }
        }
    ' "$MAC_TRACK_LOG" | sort -rn > /tmp/.hat_full.$$
    head -n "$TOP_N" /tmp/.hat_full.$$ > /tmp/.hat_ranked.$$
    rm -f /tmp/.hat_full.$$

    if [ ! -s /tmp/.hat_ranked.$$ ]; then
        echo "  (no switch/port/MAC activity in this window)"
    else
        while IFS=$'\t' read -r cnt sw_ip port_idx portname mac first_ts last_ts; do
            first_h=$(date -d "@$first_ts" '+%Y-%m-%d %H:%M:%S')
            last_h=$(date -d "@$last_ts" '+%Y-%m-%d %H:%M:%S')
            ip_row=$(lookup_mac_ip "$mac")
            ip_val=$(echo "$ip_row" | cut -d'|' -f2 | xargs 2>/dev/null || true)
            ip_ts=$(echo "$ip_row" | cut -d'|' -f3 | xargs 2>/dev/null || true)
            ip_epoch=$(echo "$ip_row" | cut -d'|' -f4 | xargs 2>/dev/null || true)
            stale_flag=""
            if [ "$STALE_DAYS" -gt 0 ] && [ -n "$ip_epoch" ] && [ "$ip_epoch" -eq "$ip_epoch" ] 2>/dev/null; then
                age_days=$(( (END_EPOCH - ip_epoch) / 86400 ))
                if [ "$age_days" -ge "$STALE_DAYS" ]; then
                    stale_flag="  [STALE: ${age_days}d old -- see the TimeTicks/seconds-unit hypothesis in the vault note if this looks wrong]"
                fi
            fi
            printf "  %-4s events  switch=%-15s port=%-10s mac=%-13s ip=%-15s (known as of %s)  first=%s  last=%s%s\n" \
                "$cnt" "$sw_ip" "$portname" "$mac" "${ip_val:-unknown}" "${ip_ts:-n/a}" "$first_h" "$last_h" "$stale_flag"
        done < /tmp/.hat_ranked.$$
    fi
    rm -f /tmp/.hat_ranked.$$
fi

echo
echo "=== Repeated re-admission pattern (sw.log) ==="
echo "  (same MAC re-admitted 3+ times on the same switch -- roughly consistent spacing between"
echo "  admissions is consistent with a periodic recheck cycle re-admitting instead of silently"
echo "  reconfirming, e.g. the ARP-staleness hypothesis. Confirmed live: a real bundle showed exactly"
echo "  this shape -- 4 independent hosts across 2 switches, all re-admitting every ~18-21 minutes.)"
if [ "${#SW_PLUGIN_LOG_FILES[@]}" -eq 0 ]; then
    echo "  (no sw.log source found$( [ -n "$BUNDLE" ] && echo " in this bundle" ) -- needs Switch-plugin trace"
    echo "  lines (sw_send_adm_by_mac), which aren't guaranteed present unless debug was active, or"
    echo "  elevated after the fact via 'live' mode.)"
else
    LC_ALL=C awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
        {
            if (!match($0, /^sw-?[0-9]*:[0-9]+:([0-9]+)\./, tm)) next
            epoch = tm[1] + 0
            if (epoch < s || epoch > e) next
            if ($0 !~ /sw_send_adm_by_mac/) next
            if (!match($0, /sw \[([0-9.]+)\] sending admission for mac\[([0-9a-f]+)\]/, am)) next
            key = am[1] SUBSEP am[2]
            n[key]++
            times[key, n[key]] = epoch
        }
        END {
            for (key in n) {
                cnt = n[key]
                for (i = 1; i <= cnt; i++) arr[i] = times[key, i]
                for (i = 2; i <= cnt; i++) { v = arr[i]; j = i - 1; while (j >= 1 && arr[j] > v) { arr[j+1] = arr[j]; j-- } arr[j+1] = v }
                # Collapse near-duplicate lines for the same admission (seen
                # live: two log lines a fraction of a second apart for one
                # real event) so they cannot masquerade as a fast, "regular"
                # re-admission interval.
                dn = 1; ded[1] = arr[1]
                for (i = 2; i <= cnt; i++) { if (arr[i] - ded[dn] >= 5) { dn++; ded[dn] = arr[i] } }
                if (dn < 3) { delete arr; delete ded; continue }
                gn = 0; gsum = 0
                for (i = 2; i <= dn; i++) { g = ded[i] - ded[i-1]; gn++; gaps[gn] = g; gsum += g }
                mean = gsum / gn
                vsum = 0
                for (i = 1; i <= gn; i++) { d = gaps[i] - mean; vsum += d * d }
                sd = sqrt(vsum / gn)
                cv = (mean > 0) ? sd / mean : 999
                split(key, parts, SUBSEP)
                gaplist = ""
                for (i = 1; i <= gn; i++) gaplist = gaplist (i > 1 ? "," : "") sprintf("%.1fm", gaps[i] / 60)
                printf "%d\t%s\t%s\t%s\t%.1f\t%.0f\n", dn, parts[1], parts[2], gaplist, mean / 60, cv * 100
                delete arr; delete ded; delete gaps
            }
        }
    ' "${SW_PLUGIN_LOG_FILES[@]}" | sort -t$'\t' -k6,6n -k1,1rn > /tmp/.hat_periodic.$$

    if [ ! -s /tmp/.hat_periodic.$$ ]; then
        echo "  (no MAC re-admitted 3+ times on the same switch in this window)"
    else
        while IFS=$'\t' read -r cnt sw_ip mac gaplist mean_min cv_pct; do
            regular=""
            if awk -v c="$cv_pct" -v m="$mean_min" 'BEGIN { exit !(c <= 40 && m >= 1) }'; then
                regular="  <- REGULAR SPACING (candidate periodic-recheck storm)"
            fi
            printf "  switch=%-15s mac=%-13s count=%-3s intervals=%-30s mean=%5.1fm  spacing-variance=%s%%%s\n" \
                "$sw_ip" "$mac" "$cnt" "$gaplist" "$mean_min" "$cv_pct" "$regular"
        done < /tmp/.hat_periodic.$$
    fi
    rm -f /tmp/.hat_periodic.$$
fi

echo
echo "=== Switch poll-cycle intervals (sw.log) ==="
echo "  MAC-table read interval: per-switch, from switch_query_macs_cb burst timestamps (a burst = many"
echo "  mac[] lines for one switch within a few seconds -- interval is time between burst starts)."
echo "  ARP-entry refresh interval: switch_delete_ip_entries isn't switch-keyed in this log at baseline"
echo "  debug (confirmed -- its [keys:] field is empty), so this one is global only, not per-switch."
if [ "${#SW_PLUGIN_LOG_FILES[@]}" -eq 0 ]; then
    echo "  (no sw.log source found$( [ -n "$BUNDLE" ] && echo " in this bundle" ))"
else
    LC_ALL=C awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
        {
            if (!match($0, /^sw-?[0-9]*:[0-9]+:([0-9]+)\./, tm)) next
            epoch = tm[1] + 0
            if (epoch < s || epoch > e) next
            if ($0 !~ /switch_query_macs_cb/) next
            if (!match($0, /\[keys:([0-9.]+)\]/, km)) next
            sw_ip = km[1]
            n[sw_ip]++
            times[sw_ip, n[sw_ip]] = epoch
        }
        END {
            for (sw_ip in n) {
                cnt = n[sw_ip]
                for (i = 1; i <= cnt; i++) arr[i] = times[sw_ip, i]
                for (i = 2; i <= cnt; i++) { v = arr[i]; j = i - 1; while (j >= 1 && arr[j] > v) { arr[j+1] = arr[j]; j-- } arr[j+1] = v }
                bn = 1; burst[1] = arr[1]
                for (i = 2; i <= cnt; i++) { if (arr[i] - arr[i-1] > 5) { bn++; burst[bn] = arr[i] } }
                if (bn < 2) { delete arr; delete burst; continue }
                gsum = 0; gmin = -1; gmax = 0
                for (i = 2; i <= bn; i++) {
                    g = burst[i] - burst[i-1]
                    gsum += g
                    if (gmin < 0 || g < gmin) gmin = g
                    if (g > gmax) gmax = g
                }
                printf "%s\t%d\t%.0f\t%.0f\t%.0f\n", sw_ip, bn, gmin, gsum / (bn - 1), gmax
                delete arr; delete burst
            }
        }
    ' "${SW_PLUGIN_LOG_FILES[@]}" | sort -t$'\t' -k3,3n > /tmp/.hat_macpoll.$$

    echo "  --- MAC-table read interval, per switch ---"
    if [ ! -s /tmp/.hat_macpoll.$$ ]; then
        echo "    (no switch_query_macs_cb activity in this window)"
    else
        while IFS=$'\t' read -r sw_ip bursts gmin gmean gmax; do
            printf "    switch=%-15s reads=%-4s min=%-5ss mean=%-5ss max=%-5ss\n" "$sw_ip" "$bursts" "$gmin" "$gmean" "$gmax"
        done < /tmp/.hat_macpoll.$$
    fi
    rm -f /tmp/.hat_macpoll.$$

    LC_ALL=C awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
        {
            if (!match($0, /^sw-?[0-9]*:[0-9]+:([0-9]+)\./, tm)) next
            epoch = tm[1] + 0
            if (epoch < s || epoch > e) next
            if ($0 !~ /switch_delete_ip_entries/) next
            n++
            times[n] = epoch
            if (match($0, /time=([0-9]+)/, atm)) {
                age = epoch - atm[1]
                if (age > 0) {
                    agen++; agesum += age
                    if (agen == 1 || age < agemin) agemin = age
                    if (agen == 1 || age > agemax) agemax = age
                }
            }
        }
        END {
            if (n < 2) { exit }
            for (i = 1; i <= n; i++) arr[i] = times[i]
            for (i = 2; i <= n; i++) { v = arr[i]; j = i - 1; while (j >= 1 && arr[j] > v) { arr[j+1] = arr[j]; j-- } arr[j+1] = v }
            bn = 1; burst[1] = arr[1]
            for (i = 2; i <= n; i++) { if (arr[i] - arr[i-1] > 5) { bn++; burst[bn] = arr[i] } }
            if (bn >= 2) {
                gsum = 0; gmin = -1; gmax = 0
                for (i = 2; i <= bn; i++) {
                    g = burst[i] - burst[i-1]
                    gsum += g
                    if (gmin < 0 || g < gmin) gmin = g
                    if (g > gmax) gmax = g
                }
                printf "BURSTS\t%d\t%.0f\t%.0f\t%.0f\n", bn, gmin, gsum / (bn - 1), gmax
            }
            if (agen > 0) printf "AGES\t%d\t%.1f\t%.1f\t%.1f\n", agen, agemin / 86400, (agesum / agen) / 86400, agemax / 86400
        }
    ' "${SW_PLUGIN_LOG_FILES[@]}" > /tmp/.hat_arp.$$

    echo "  --- ARP-entry refresh interval (global, all switches combined -- see caveat above) ---"
    BURST_LINE=$(awk -F'\t' '$1 == "BURSTS"' /tmp/.hat_arp.$$)
    if [ -z "$BURST_LINE" ]; then
        echo "    (no switch_delete_ip_entries activity in this window)"
    else
        echo "$BURST_LINE" | awk -F'\t' '{printf "    refresh-cycles=%d  min=%ss  mean=%ss  max=%ss\n", $2, $3, $4, $5}'
    fi

    echo
    echo "  --- ARP entry age at expiry, from sw.log's own arp_list time= field (not the mac_ip table) ---"
    echo "  (operationalizes the reported 'ARP times received in excess of 63 days' finding directly"
    echo "  from the switch log -- age = this log line's own timestamp minus the embedded time= value.)"
    AGE_LINE=$(awk -F'\t' '$1 == "AGES"' /tmp/.hat_arp.$$)
    if [ -z "$AGE_LINE" ]; then
        echo "    (no arp_list time= data found in this window)"
    else
        echo "$AGE_LINE" | awk -F'\t' '{printf "    samples=%d  min=%.1fd  mean=%.1fd  max=%.1fd\n", $2, $3, $4, $5}'
    fi
    rm -f /tmp/.hat_arp.$$
fi

echo
echo "Note: MAC->IP is the last KNOWN mapping, not necessarily current -- confirmed live this can lag"
echo "by hours behind a real port event. Treat 'known as of' as its real age, not the time of this event."
