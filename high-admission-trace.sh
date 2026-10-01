#!/usr/bin/env bash
#
# high-admission-trace.sh
#
# Traces what's actually causing an appliance's high admission (adm)
# event volume back to a switch/port/MAC (and, where known, an IP).
# Built and verified live 2026-09-15 against a real Cisco 3560
# (a lab switch) via controlled port-bounce tests -- see
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
#   tap -- read-only. Which endpoints keep this appliance in Admission
#   TAP control state (eyeSight's admission throttle: >100 admissions/h
#   or >1,000/10 h appliance-wide turns it on; a host with 5+ admissions
#   of one type in 10 h then has further ones of that type ignored, so
#   its properties stop being rechecked -- see "Admission TAP Control" in
#   the vault). Reports: the TAP on/off history from adm.tap.active (every
#   daily stats file present, not just today), what pushed it into TAP
#   (admissions in the hour before each entry), admissions by type with
#   how many TAP accepted vs discarded, and -- the part switch logs can't
#   give without debug -- the ENDPOINTS behind them, from the DHCP
#   Classifier's plugin_learn_cb lines (every admission the engine hands
#   dhclass: type, host IP/MAC, and the plugin@appliance that raised it,
#   at no debug level). Flags hosts over the per-host threshold (i.e.
#   being throttled) and any IP<->MAC pairing changes seen. Built on a
#   real customer case (2026-09-29), where it named one thin client in a
#   reboot loop as ~85% of an appliance's switch-port admissions and 11
#   IP-less devices as a second appliance's whole idc flood. Needs the
#   dhclass plugin running for the endpoint part; without it the TAP and
#   counter sections still work. Works live or on a bundle (-b).
#
#   -A (analyze/tap, run on the EM) -- the same report for one or more
#   appliances without logging on to each: "-A all" (every appliance the
#   EM knows, via `fstool oneach -g`), a comma list of IPs/hostnames, or
#   a file with one per line. The EM copies this script to each appliance
#   over its own root ssh trust (the one `fstool oneach` uses), runs it
#   there with the same options, removes it again, and prints one block
#   per appliance plus a summary. tap gets the EM's node-id -> name list
#   passed along (-N), so "raised by" shows appliance names. An
#   unreachable appliance is reported and skipped, not fatal.
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
# Two checks added 2026-09-15 after applying this to a real customer
# production incident where no switch-plugin trace data existed at all
# (debug wasn't active when it happened) -- both work from today.log
# alone, so they still say something useful even in that situation:
#
#   - Peak-window connected-device write activity: for the busiest
#     admission-volume reporting windows, ranks every connected device's
#     <ip>.write.count/.write.bytes -- a device with dramatically more
#     writes than its peers during a spike is a possible contributing/
#     symptomatic device. Confirmed live against the real customer bundle:
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
# customer bundle turned up actual sw.log trace lines (33 sw_send_adm_by_mac
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
#   ./high-admission-trace.sh analyze [-w <window>] [-k <switch-ip>[,<switch-ip>...]] [-n <top-N>] [-s <spike-N>] [-a <stale-days>] [-b <bundle.tgz|bundle-dir> | -A <appliances>]
#   ./high-admission-trace.sh live -k <switch-ip>[,<switch-ip>...] [-d <duration>]
#   ./high-admission-trace.sh tap [-w <window>|all] [-n <top-N>] [-D <days>] [-N <nodes-file>] [-b <bundle.tgz|bundle-dir> | -A <appliances>]
#   ./high-admission-trace.sh collect [-w <window>] [-c <case-ref>]
#
#   -w  How far back to look, e.g. 30m, 2h, 1d (analyze/collect/tap; default 1h;
#       tap also takes "all"). In tap -b mode the window ends at the bundle's
#       last today.log sample, not "now"
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
#   -D  tap mode: days of daily stats history to read for the TAP on/off
#       history (default 7; 0 = today.log only)
#   -N  tap mode: node-id -> appliance-name list, e.g. the EM's
#       `psql -c "select node_id,name from reg"` output saved to a file.
#       Live, the script tries that query itself (works on the EM)
#   -A  analyze/tap, run on the EM: the appliance(s) to run it on -- "all",
#       ip-or-host[,ip-or-host...], or a file with one per line
#   -h  Show this help
#
set -euo pipefail

VERSION="1.5.1"

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
# sw.<epoch>.<pid>.log files, confirmed against a real customer bundle), so
# this is every rotation found, fed to awk as multiple files at once.
SW_PLUGIN_LOG_FILES=()

# tap mode: dhclass plugin logs (per-endpoint admissions) and daily stats
# files (stats/YYYY_MM_DD.gz = the PREVIOUS day's today.log, written at
# midnight) -- found live below, or under the bundle in -b mode.
DHCLASS_LOG_FILES=()
STATS_DAILY_FILES=()
BUNDLE_TMP=""   # set when -b extracted a .tgz to a temp dir (cleaned up on exit)

usage() {
    cat <<USAGE
high-admission-trace.sh v${VERSION}

Usage:
  $0 analyze [-w <window>] [-k <switch-ip>[,<switch-ip>...]] [-n <top-N>] [-s <spike-N>] [-a <stale-days>] [-b <bundle.tgz|bundle-dir> | -A <appliances>]
  $0 live -k <switch-ip>[,<switch-ip>...] [-d <duration>]
  $0 tap [-w <window>|all] [-n <top-N>] [-D <days>] [-N <nodes-file>] [-b <bundle.tgz|bundle-dir> | -A <appliances>]
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
  tap      Read-only: which ENDPOINTS keep this appliance in Admission TAP
           control -- TAP on/off history (adm.tap.active, all daily stats
           files), what pushed it in, admissions by type accepted/discarded,
           and the hosts behind them from the DHCP Classifier's learn
           callbacks (type, IP/MAC, raising plugin@appliance), with hosts
           over the per-host threshold and IP<->MAC changes flagged.
  collect  Builds a real tech-support bundle (-p sw --pack) with everything
           analyze needs attached: windowed today.log/sw_mac_track.log excerpts
           and a plain-text mac_ip export (none of these ship in a standard
           bundle by default; sw.log's full history already does). Hand the
           resulting .tgz to 'analyze -b' for offline/remote-site analysis.

  -w  How far back to look, e.g. 30m, 2h, 1d (analyze/collect/tap; default 1h;
      tap also takes "all"; with -b the window ends at the bundle's last sample)
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
  -D  tap: days of daily stats history for the TAP on/off history (default 7)
  -N  tap: node-id -> appliance-name file (the EM's "select node_id,name from reg"
      output); live, the script tries that query itself
  -A  analyze/tap, run on the EM: run it on these appliances instead of this box --
      "all" (every appliance the EM knows), ip-or-host[,ip-or-host...], or a file
      with one per line. Uses the EM's root ssh trust to the appliances (as
      'fstool oneach' does); one report block per appliance, then a summary.
  -h  Show this help

analyze/live/collect (without -b) run ON the appliance itself, as root.
analyze -A / tap -A run on the EM against its appliances.
analyze -b / tap -b run anywhere -- no fstool/psql needed, just the bundle.
USAGE
    exit 1
}

[ $# -eq 0 ] && usage

MODE="$1"; shift
case "$MODE" in
    analyze|live|collect|tap) ;;
    -h|--help) usage ;;
    *) echo "Error: unknown mode '$MODE' (expected 'analyze', 'live', 'tap', or 'collect')" >&2; usage ;;
esac

WINDOW="1h"
SWITCH_FILTER=""
TOP_N=10
SPIKE_N=5
STALE_DAYS=7
DURATION="15m"
BUNDLE=""
CASE_REF="high-admission-trace"
NODES_FILE=""
HISTORY_DAYS=7
REMOTE_TARGETS=""
REMOTE_ARGS=()   # every option except -A/-N, replayed on each appliance in -A mode

while getopts "w:k:n:s:a:d:b:c:N:D:A:h" opt; do
    case "$opt" in A|N|h|\?) ;; *) REMOTE_ARGS+=("-$opt" "$OPTARG") ;; esac
    case "$opt" in
        w) WINDOW="$OPTARG" ;;
        k) SWITCH_FILTER="$OPTARG" ;;
        n) TOP_N="$OPTARG" ;;
        s) SPIKE_N="$OPTARG" ;;
        a) STALE_DAYS="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        b) BUNDLE="$OPTARG" ;;
        c) CASE_REF="$OPTARG" ;;
        N) NODES_FILE="$OPTARG" ;;
        D) HISTORY_DAYS="$OPTARG" ;;
        A) REMOTE_TARGETS="$OPTARG" ;;
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
# -A: run from the EM against one or more appliances
# ==================================================================
if [ -n "$REMOTE_TARGETS" ]; then
    case "$MODE" in
        analyze|tap) ;;
        *) echo "Error: -A works with analyze and tap only -- live and collect change state on the appliance, run those there." >&2; exit 1 ;;
    esac
    if [ -n "$BUNDLE" ]; then
        echo "Error: -A and -b don't mix -- -b analyses a bundle right here." >&2
        exit 1
    fi

    # Same ssh behaviour as `fstool oneach`: the EM's root key, no prompts, no known_hosts churn.
    SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
    RWORK=$(mktemp -d /tmp/hat-remote.XXXXXX)
    trap 'rm -rf "$RWORK"' EXIT

    # The EM's appliance registry: node id | name | address | resolved IP -- for the block
    # headers (a target given as an IP still finds its name) and for tap's -N list.
    REG="$RWORK/reg.txt"
    : > "$REG"
    if command -v psql >/dev/null 2>&1; then
        psql -t -A -F'|' -c "select node_id, name, coalesce(address, '') from reg" 2>/dev/null \
            | while IFS='|' read -r id nm addr; do
                [ -n "$id" ] || continue
                rip=$(getent hosts "$addr" 2>/dev/null | awk '{ print $1; exit }' || true)
                echo "$id|$nm|$addr|${rip:-$addr}"
            done > "$REG" || true
    fi

    if [ "$REMOTE_TARGETS" = "all" ]; then
        if ! command -v fstool >/dev/null 2>&1; then
            echo "Error: -A all needs fstool -- run it on the EM (or name the appliances)." >&2
            exit 1
        fi
        TARGET_LIST=$(fstool oneach -g </dev/null 2>/dev/null | tr ',' '\n' || true)
    elif [ -f "$REMOTE_TARGETS" ]; then
        TARGET_LIST=$(sed 's/#.*//' "$REMOTE_TARGETS" | tr ', \t\r' '\n\n\n\n')
    else
        TARGET_LIST=$(echo "$REMOTE_TARGETS" | tr ',' '\n')
    fi
    TARGET_LIST=$(echo "$TARGET_LIST" | awk 'NF && !seen[$1]++ { print $1 }')
    if [ -z "$TARGET_LIST" ]; then
        echo "Error: -A '$REMOTE_TARGETS' gave no appliances." >&2
        exit 1
    fi

    NODES_OUT=""
    if [ "$MODE" = "tap" ]; then
        if [ -n "$NODES_FILE" ]; then
            NODES_OUT="$NODES_FILE"
        elif [ -s "$REG" ]; then
            NODES_OUT="$RWORK/nodes.txt"
            awk -F'|' '{ print $1 "|" $2 }' "$REG" > "$NODES_OUT"
        fi
    fi

    SELF=$(readlink -f "$0")
    RTAG="/tmp/hat-remote-$$"
    OK_LIST=(); FAIL_LIST=()
    echo "Running '$MODE' on: $(echo "$TARGET_LIST" | tr '\n' ' ')"
    for t in $TARGET_LIST; do
        nm=$(awk -F'|' -v t="$t" '$3 == t || $4 == t || $2 == t { print $2; exit }' "$REG")
        echo
        echo "################ appliance ${nm:-$t} ($t) -- $MODE ################"
        if ! scp -q "${SSH_OPTS[@]}" "$SELF" "root@$t:$RTAG.sh" 2>"$RWORK/err"; then
            echo "  FAILED: couldn't copy the script to $t -- $(head -1 "$RWORK/err")"
            FAIL_LIST+=("$t (unreachable)")
            continue
        fi
        RARGS=("${REMOTE_ARGS[@]}")
        if [ -n "$NODES_OUT" ] && scp -q "${SSH_OPTS[@]}" "$NODES_OUT" "root@$t:$RTAG.nodes" 2>/dev/null; then
            RARGS+=(-N "$RTAG.nodes")
        fi
        # The script and node list are removed on the appliance whatever the outcome.
        RCMD="bash $RTAG.sh $(printf '%q ' "$MODE" "${RARGS[@]}"); rc=\$?; rm -f $RTAG.sh $RTAG.nodes; exit \$rc"
        if ssh -n "${SSH_OPTS[@]}" "root@$t" "$RCMD"; then
            OK_LIST+=("$t")
        else
            FAIL_LIST+=("$t (exit $?)")
        fi
    done

    echo
    echo "=== Summary: $MODE on ${#OK_LIST[@]} appliance(s) OK, ${#FAIL_LIST[@]} failed ==="
    for t in "${OK_LIST[@]}"; do echo "  OK      $t"; done
    for t in "${FAIL_LIST[@]}"; do echo "  FAILED  $t"; done
    if [ "${#FAIL_LIST[@]}" -eq 0 ]; then exit 0; else exit 1; fi
fi

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
        BUNDLE_TMP="$BUNDLE_ROOT"
        echo "=== Unpacking $BUNDLE to $BUNDLE_ROOT ==="
        # Always clean this up on exit, success or failure -- confirmed
        # live this leaked multiple GB per run otherwise (an 867MB real
        # bundle expands to ~8GB unpacked), compounding across repeated
        # runs into real disk pressure.
        trap 'rm -rf "$BUNDLE_ROOT"' EXIT
        tar -xzf "$BUNDLE" -C "$BUNDLE_ROOT"

        # Confirmed live, repeatedly, on one specific real bundle: a full
        # `tar -xzf` of the whole archive can exit 0 while silently
        # dropping an entire subtree (the plugin/sw/ log directory, 116
        # files) even from a byte-verified, checksum-correct archive --
        # reproduced 3 times in a row against the same bundle, so this
        # isn't just occasional memory-pressure flakiness on one random
        # file. What DID prove reliable, twice: a SECOND, TARGETED
        # extraction of just the missing subtree via `tar --wildcards`,
        # scoped narrowly rather than a second full-archive pass (which
        # shares whatever the first pass's problem was, and re-proved
        # unreliable when tried).
        #
        # A disk-only check can't tell "genuinely not in this bundle"
        # (common and legitimate -- a standard bundle often has no sw.log
        # trace data at all) from "silently dropped by extraction", so
        # this checks the archive's own listing (tar -tzf, decompress-
        # and-list only, no second ~8GB disk write) before deciding
        # anything is actually missing.
        ARCHIVE_LIST=$(tar -tzf "$BUNDLE" 2>/dev/null || true)
        if echo "$ARCHIVE_LIST" | grep -q '/usr/local/forescout/stats/today\.log$' \
            && [ -z "$(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/stats/today.log" -print -quit 2>/dev/null)" ]; then
            echo "=== today.log listed in the archive but missing after extraction -- retrying that path ===" >&2
            tar -xzf "$BUNDLE" -C "$BUNDLE_ROOT" --wildcards '*/usr/local/forescout/stats/today.log' 2>/dev/null || true
        fi
        if echo "$ARCHIVE_LIST" | grep -q '/usr/local/forescout/log/plugin/sw/sw.*\.log$' \
            && [ -z "$(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/log/plugin/sw/sw*.log" -print -quit 2>/dev/null)" ]; then
            echo "=== sw plugin logs listed in the archive but missing after extraction -- retrying that subtree ===" >&2
            tar -xzf "$BUNDLE" -C "$BUNDLE_ROOT" --wildcards '*/usr/local/forescout/log/plugin/sw/*' 2>/dev/null || true
        fi
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

    # tap mode's sources: dhclass learn-callback logs and daily stats history.
    while IFS= read -r f; do
        DHCLASS_LOG_FILES+=("$f")
    done < <(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/log/plugin/dhclass/dhclass*.log" 2>/dev/null | sort)
    while IFS= read -r f; do
        STATS_DAILY_FILES+=("$f")
    done < <(find "$BUNDLE_ROOT" -path "*/usr/local/forescout/stats/*" -name "[0-9][0-9][0-9][0-9]_[0-9][0-9]_[0-9][0-9].gz" 2>/dev/null | sort)

    echo "Bundle sources found: today.log=${TODAY_LOG:-none} sw_mac_track.log=${MAC_TRACK_LOG:-none} mac_ip.csv=${MAC_IP_CSV:-none} sw.log=${#SW_PLUGIN_LOG_FILES[@]} file(s) dhclass.log=${#DHCLASS_LOG_FILES[@]} file(s) daily-stats=${#STATS_DAILY_FILES[@]} file(s)"
    echo
fi

if [ -z "$BUNDLE" ] && [ -f "$SW_PLUGIN_LOG" ]; then
    SW_PLUGIN_LOG_FILES=("$SW_PLUGIN_LOG")
fi

if [ -z "$TODAY_LOG" ] || [ ! -f "$TODAY_LOG" ]; then
    echo "Error: no today.log source found$( [ -n "$BUNDLE" ] && echo " in this bundle" )." >&2
    exit 1
fi

# ==================================================================
# tap mode
# ==================================================================
if [ "$MODE" = "tap" ]; then
    # eyeSight defaults (FSAdmTap): per host, this many admissions of one type ...
    TAP_COUNT=5
    # ... within this many seconds -> further ones of that type are ignored.
    TAP_PERIOD=36000
    if [ -z "$BUNDLE" ]; then
        for f in /usr/local/forescout/log/plugin/dhclass/dhclass*.log; do
            [ -f "$f" ] && DHCLASS_LOG_FILES+=("$f")
        done
        for f in /usr/local/forescout/stats/[0-9][0-9][0-9][0-9]_[0-9][0-9]_[0-9][0-9].gz; do
            [ -f "$f" ] && STATS_DAILY_FILES+=("$f")
        done
        # Live: use this appliance's own thresholds if someone overrode them
        # (blank = default, per `fstool get_property`).
        if command -v fstool >/dev/null 2>&1; then
            v=$(fstool get_property fs.adm.tap.count 2>/dev/null | awk '{for (i = NF; i > 0; i--) if ($i ~ /^[0-9]+$/) { print $i; exit }}' || true)
            [ -n "$v" ] && TAP_COUNT="$v"
            v=$(fstool get_property fs.adm.tap.period.sec 2>/dev/null | awk '{for (i = NF; i > 0; i--) if ($i ~ /^[0-9]+$/) { print $i; exit }}' || true)
            [ -n "$v" ] && TAP_PERIOD="$v"
        fi
    fi

    TAPWORK=$(mktemp -d /tmp/hat-tap.XXXXXX)
    trap 'rm -rf "$TAPWORK"; if [ -n "$BUNDLE_TMP" ]; then rm -rf "$BUNDLE_TMP"; fi' EXIT
    trap 'exit 143' TERM INT   # stopped from outside (e.g. the caller's timeout): still clean up

    # node id -> appliance name (learn events carry only the node id)
    NAMES_TSV="$TAPWORK/names.tsv"
    : > "$NAMES_TSV"
    if [ -n "$NODES_FILE" ]; then
        if [ -f "$NODES_FILE" ]; then
            awk -F'|' 'NF >= 2 { id = $1; nm = $2; gsub(/[ \t\r]/, "", id); gsub(/^[ \t]+|[ \t\r]+$/, "", nm); if (id ~ /^-?[0-9]+$/ && nm != "") print id "\t" nm }' "$NODES_FILE" > "$NAMES_TSV"
        else
            echo "Warning: -N '$NODES_FILE' not found -- showing node ids instead of names." >&2
        fi
    elif [ -z "$BUNDLE" ] && command -v psql >/dev/null 2>&1; then
        psql -t -A -F'|' -c "select node_id, name from reg" 2>/dev/null \
            | awk -F'|' 'NF >= 2 && $1 ~ /^-?[0-9]+$/ { print $1 "\t" $2 }' > "$NAMES_TSV" || true
    fi

    # Window: live ends now; a bundle ends at its own last today.log sample.
    LAST_TS=$(tail -n 200 "$TODAY_LOG" | awk '$1 == "p" { t = $2 } END { print t + 0 }')
    if [ -z "$BUNDLE" ]; then END_EPOCH=$(date +%s); else END_EPOCH="$LAST_TS"; fi
    if [ "$WINDOW" = "all" ]; then
        START_EPOCH=0
    else
        START_EPOCH=$((END_EPOCH - $(window_to_seconds "$WINDOW")))
    fi
    echo "Window: $( [ "$WINDOW" = "all" ] && echo "all of today.log" || echo "last ${WINDOW}" ) ending $(awk -v t="$END_EPOCH" 'BEGIN { print strftime("%Y-%m-%d %H:%M:%S", t) }')$( [ -n "$BUNDLE" ] && echo " (the bundle's last sample)" )"
    echo "Per-host TAP threshold in use: ${TAP_COUNT} admissions of one type within $((TAP_PERIOD / 3600))h"

    # A dhclass log last written before the window starts can't hold a line inside it --
    # on a busy appliance with dhclass debug raised there can be many large rotated files
    # (a 900 s timeout was hit on one, 2026-10-01), so skip them rather than read them all.
    if [ "$START_EPOCH" -gt 0 ] && [ "${#DHCLASS_LOG_FILES[@]}" -gt 0 ]; then
        DHCLASS_ALL=${#DHCLASS_LOG_FILES[@]}
        KEEP=()
        for f in "${DHCLASS_LOG_FILES[@]}"; do
            m=$(stat -c %Y "$f" 2>/dev/null || echo 0)
            if [ "$m" -ge "$START_EPOCH" ]; then KEEP+=("$f"); fi
        done
        DHCLASS_LOG_FILES=("${KEEP[@]}")
        echo "dhclass logs read: ${#DHCLASS_LOG_FILES[@]} of ${DHCLASS_ALL} (the rest were last written before the window)"
    fi
    echo

    # One pass per stats file, keeping only the three metric families used below.
    TAPDATA="$TAPWORK/tap.dat"
    EXTRACT='$1 == "p" && ($5 == "adm.tap.active" || $5 ~ /^learn\.adm\./ || $5 ~ /^adm\.tap\.(accept|discard)\./) { print $2, $5, $6 }'
    PREFILTER='adm\.tap\.(active|accept|discard)|learn\.adm\.'
    {
        if [ "${#STATS_DAILY_FILES[@]}" -gt 0 ] && [ "$HISTORY_DAYS" -gt 0 ]; then
            printf '%s\n' "${STATS_DAILY_FILES[@]}" | sort | tail -n "$HISTORY_DAYS" > "$TAPWORK/daily.lst"
            while IFS= read -r f; do
                gzip -dc "$f" 2>/dev/null | LC_ALL=C grep -E "$PREFILTER" | LC_ALL=C awk "$EXTRACT" || true
            done < "$TAPWORK/daily.lst"
        fi
        LC_ALL=C grep -E "$PREFILTER" "$TODAY_LOG" | LC_ALL=C awk "$EXTRACT" || true
    } > "$TAPDATA"

    # ---------------------------------------------------------------
    echo "=== 1. Admission TAP control state (adm.tap.active, one sample a minute) ==="
    echo "  (ON when admissions across ALL endpoints exceed 100/h or 1,000/10h. ON by itself throttles"
    echo "  nothing -- it arms the per-host rule in section 4.)"
    awk '$2 == "adm.tap.active" { print $1, ($3 == "true" ? 1 : 0) }' "$TAPDATA" | sort -n -u -k1,1 > "$TAPWORK/active.dat"
    awk -v entries="$TAPWORK/entries.dat" '
        {
            t = $1; a = $2; d = strftime("%Y-%m-%d", t)
            if (!(d in seen)) { seen[d] = 1; days[++nd] = d; run = 0 }
            n[d]++
            if (a) act[d]++
            if (a && !prev) {
                if (NR == 1) { onatstart = 1; lastentry = t }   # already ON when the data starts -- not an entry
                else {
                    ent[d]++
                    if (ent[d] <= 6) elist[d] = elist[d] (elist[d] == "" ? "" : " ") strftime("%H:%M", t)
                    lastentry = t; print t > entries
                }
            }
            if (!a && prev) lastexit = t
            run = a ? run + 1 : 0
            if (run > best[d]) best[d] = run
            orun = a ? orun + 1 : 0
            if (orun > obest) { obest = orun; obest_end = t }
            prev = a; lasta = a; lastt = t
        }
        END {
            if (nd == 0) { print "  (no adm.tap.active samples found)"; exit }
            if (onatstart) printf "  (already ON at the first sample, %s -- not counted as an entry)\n", strftime("%Y-%m-%d %H:%M", first_t)
            printf "  %-10s %8s %8s %6s %8s %13s  %s\n", "day", "samples", "in TAP", "", "entries", "longest run", "entered at"
            for (i = 1; i <= nd; i++) {
                d = days[i]
                printf "  %-10s %8d %8d %5.0f%% %8d %9d min  %s\n", d, n[d], act[d] + 0, 100 * (act[d] + 0) / n[d], ent[d] + 0, best[d] + 0, elist[d]
            }
            if (obest > 0) printf "\n  Longest continuous TAP run in this data: %d min, ending %s\n", obest, strftime("%Y-%m-%d %H:%M", obest_end)
            if (lasta) printf "  Current state: IN TAP control since %s%s\n", strftime("%Y-%m-%d %H:%M", lastentry), ((onatstart && lastentry == first_t) ? " -- already ON when this data starts; add daily stats history (-D, or the full bundle) to see when it went in" : "")
            else if (lastexit) printf "  Current state: not in TAP control (last left it %s)\n", strftime("%Y-%m-%d %H:%M", lastexit)
            else print "  Current state: not in TAP control"
        }
        NR == 1 { first_t = $1 }
    ' "$TAPWORK/active.dat"

    # ---------------------------------------------------------------
    echo
    echo "=== 2. What pushed it into TAP -- admissions in the hour before each entry (last 5 entries) ==="
    if [ ! -s "$TAPWORK/entries.dat" ]; then
        echo "  (no TAP entry in this data)"
    else
        tail -n 5 "$TAPWORK/entries.dat" > "$TAPWORK/entries5.dat"
        awk -v ef="$TAPWORK/entries5.dat" '
            BEGIN { while ((getline x < ef) > 0) E[++ne] = x + 0 }
            $2 ~ /^learn\.adm\./ {
                for (i = 1; i <= ne; i++)
                    if ($1 > E[i] - 3600 && $1 <= E[i]) { S[i, substr($2, 11)] += $3; tot[i] += $3; T[substr($2, 11)] = 1 }
            }
            END {
                for (i = 1; i <= ne; i++) {
                    line = ""
                    for (t in T) if (S[i, t] > 0) line = line sprintf("%s=%d ", t, S[i, t])
                    printf "  entered %s -- %d admissions in the hour before: %s\n", strftime("%Y-%m-%d %H:%M", E[i]), tot[i] + 0, (line == "" ? "(no learn.adm data for that hour)" : line)
                }
            }
        ' "$TAPDATA"
    fi

    # ---------------------------------------------------------------
    echo
    echo "=== 3. Admissions in the window by type (today.log) -- accepted vs ignored by TAP ==="
    awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
        $1 >= s && $1 <= e {
            if ($2 ~ /^learn\.adm\./)             { t = substr($2, 11); L[t] += $3; T[t] = 1 }
            else if ($2 ~ /^adm\.tap\.accept\./)  { t = substr($2, 16); A[t] += $3; T[t] = 1 }
            else if ($2 ~ /^adm\.tap\.discard\./) { t = substr($2, 17); D[t] += $3; T[t] = 1 }
        }
        END { for (t in T) printf "%d\t%s\t%d\t%d\n", L[t], t, A[t], D[t] }
    ' "$TAPDATA" | sort -t$'\t' -k1,1rn > "$TAPWORK/bytype.tsv"
    ADM_TOTAL=$(awk -F'\t' '{ s += $1 } END { print s + 0 }' "$TAPWORK/bytype.tsv")
    if [ ! -s "$TAPWORK/bytype.tsv" ]; then
        echo "  (no admission counters in this window)"
    else
        printf "  %-14s %10s %10s %10s %9s\n" "type" "admissions" "accepted" "ignored" "% ignored"
        while IFS=$'\t' read -r cnt t acc dis; do
            pct=$(awk -v a="$acc" -v d="$dis" 'BEGIN { printf "%.0f", (a + d > 0) ? 100 * d / (a + d) : 0 }')
            printf "  %-14s %10s %10s %10s %8s%%\n" "$t" "$cnt" "$acc" "$dis" "$pct"
        done < "$TAPWORK/bytype.tsv"
        echo "  total          $ADM_TOTAL"
    fi

    # ---------------------------------------------------------------
    echo
    echo "=== 4. The endpoints behind them (dhclass plugin_learn_cb) ==="
    if [ "${#DHCLASS_LOG_FILES[@]}" -eq 0 ] && [ -n "${DHCLASS_ALL:-}" ]; then
        echo "  (no dhclass log was written during this window -- widen -w)"
    elif [ "${#DHCLASS_LOG_FILES[@]}" -eq 0 ]; then
        echo "  (no dhclass.log found$( [ -n "$BUNDLE" ] && echo " in this bundle" ) -- per-endpoint attribution needs the DHCP Classifier"
        echo "  plugin running on this appliance. Without it, run 'analyze' (switch logs) or elevate Switch-plugin"
        echo "  debug with 'live' on the switch-managing appliance.)"
    else
        LC_ALL=C grep -h -F plugin_learn_cb "${DHCLASS_LOG_FILES[@]}" | LC_ALL=C awk -v s="$START_EPOCH" -v e="$END_EPOCH" '
            /plugin_learn_cb/ {
                split($0, f, ":"); t = int(f[3])   # whole seconds: a fractional epoch prints as 1.79069e+09
                if (t < s || t > e) next
                if (!match($0, /\{name=adm,value=([a-z_0-9]+)\}/, am)) next
                host = ""
                if (match($0, /host=\{(.*)\},learnevent=/, hm)) host = hm[1]
                gsub(/_timeinfo=\{[^}]*\},?/, "", host)
                ip = "-"; mac = "-"
                if (match(host, /(^|,)ip=([0-9.]+)/, im)) ip = im[2]
                if (match(host, /(^|,)mac=([0-9a-f]{12})/, mm)) mac = mm[2]
                # MAC-only hosts are keyed by a 224.x placeholder IP that
                # appears here as a plain integer.
                if (ip != "-" && ip !~ /\./) { v = ip + 0; ip = int(v / 16777216) % 256 "." int(v / 65536) % 256 "." int(v / 256) % 256 "." v % 256 }
                agent = "-"; node = "-"
                if (match($0, /learnevent=\{agent=\{id=([a-z_0-9]+),nodeid=(-?[0-9]+)\}/, gm)) { agent = gm[1]; node = gm[2] }
                else if ($0 ~ /learnevent=\{agent=,/) { agent = "engine"; node = "local" }   # raised by the engine itself
                print t "\t" ip "\t" mac "\t" am[1] "\t" agent "\t" node
            }
        ' > "$TAPWORK/cb.tsv" || true

        CB_TOTAL=$(wc -l < "$TAPWORK/cb.tsv" | tr -d ' ')
        if [ "$CB_TOTAL" -eq 0 ]; then
            echo "  (dhclass.log present but it has no learn callbacks in this window -- it may have rotated;"
            echo "  widen -w or collect closer to the event)"
        else
            CB_FIRST=$(awk -F'\t' 'NR == 1 || $1 < m { m = $1 } END { print strftime("%H:%M", m) }' "$TAPWORK/cb.tsv")
            CB_LAST=$(awk -F'\t' '$1 > m { m = $1 } END { print strftime("%H:%M", m) }' "$TAPWORK/cb.tsv")
            echo "  Coverage: dhclass named ${CB_TOTAL} admissions between ${CB_FIRST} and ${CB_LAST}; today.log counted ${ADM_TOTAL} in the"
            echo "  whole window. The endpoint figures below are for the dhclass span -- if it is much shorter than"
            echo "  the window (dhclass.log rotated), re-run with a -w that matches it for a like-for-like share."

            # Aggregate per host + type + source, with the per-host TAP rule applied.
            LC_ALL=C awk -F'\t' -v names="$NAMES_TSV" -v tc="$TAP_COUNT" -v tp="$TAP_PERIOD" '
                BEGIN { while ((getline l < names) > 0) { split(l, x, "\t"); nm[x[1]] = x[2] } }
                {
                    src = ($5 == "engine") ? "engine (this appliance)" : $5 "@" (($6 in nm) ? nm[$6] : $6)
                    k = $2 SUBSEP $3 SUBSEP $4 SUBSEP src
                    c[k]++; ts[k, c[k]] = $1
                }
                END {
                    for (k in c) {
                        n = c[k]
                        for (i = 1; i <= n; i++) a[i] = ts[k, i]
                        for (i = 2; i <= n; i++) { v = a[i]; j = i - 1; while (j >= 1 && a[j] > v) { a[j + 1] = a[j]; j-- } a[j + 1] = v }
                        # largest number inside any TAP_PERIOD-long window
                        mx = 0; lo = 1
                        for (hi = 1; hi <= n; hi++) { while (a[hi] - a[lo] > tp) lo++; if (hi - lo + 1 > mx) mx = hi - lo + 1 }
                        # typical interval, ignoring same-second duplicates
                        dn = 1; dd[1] = a[1]
                        for (i = 2; i <= n; i++) if (a[i] - dd[dn] >= 2) dd[++dn] = a[i]
                        gap = (dn > 1) ? (dd[dn] - dd[1]) / (dn - 1) : 0
                        split(k, p, SUBSEP)
                        printf "%d\t%s\t%s\t%s\t%s\t%.0f\t%d\t%s\n", n, p[1], p[2], p[3], p[4], gap, mx, (mx >= tc ? "THROTTLED" : "")
                        delete a; delete dd
                    }
                }
            ' "$TAPWORK/cb.tsv" | sort -t$'\t' -k1,1rn > "$TAPWORK/hosts.tsv"

            echo
            echo "  --- By raising plugin@appliance ---"
            awk -F'\t' '{ s[$5] += $1 } END { for (k in s) printf "%d\t%s\n", s[k], k }' "$TAPWORK/hosts.tsv" | sort -t$'\t' -k1,1rn > "$TAPWORK/bysrc.tsv"
            while IFS=$'\t' read -r cnt src; do
                printf "    %5s  %5.1f%%  %s\n" "$cnt" "$(awk -v c="$cnt" -v t="$CB_TOTAL" 'BEGIN { print 100 * c / t }')" "$src"
            done < "$TAPWORK/bysrc.tsv"

            echo
            echo "  --- Top ${TOP_N} endpoints (share = of the ${CB_TOTAL} dhclass-named admissions) ---"
            printf "    %5s %6s  %-12s %-15s %-13s %-30s %9s  %s\n" "count" "share" "type" "ip" "mac" "raised by" "every" "per-host TAP"
            awk -v n="$TOP_N" 'NR <= n' "$TAPWORK/hosts.tsv" > "$TAPWORK/top.tsv"
            while IFS=$'\t' read -r cnt ip mac t src gap mx flag; do
                every="-"
                [ "$gap" -gt 0 ] && every=$(awk -v g="$gap" 'BEGIN { if (g < 120) printf "%ds", g; else printf "%.1fm", g / 60 }')
                printf "    %5s %5.1f%%  %-12s %-15s %-13s %-30s %9s  %s\n" "$cnt" "$(awk -v c="$cnt" -v t="$CB_TOTAL" 'BEGIN { print 100 * c / t }')" \
                    "$t" "$ip" "$mac" "$src" "$every" "$( [ -n "$flag" ] && echo "THROTTLED ($mx of one type within $((TAP_PERIOD / 3600))h)" || echo "under threshold (max $mx)" )"
            done < "$TAPWORK/top.tsv"

            echo
            THR_HOSTS=$(awk -F'\t' '$8 == "THROTTLED" { print $2 "|" $3 }' "$TAPWORK/hosts.tsv" | sort -u | wc -l | tr -d ' ')
            THR_ADM=$(awk -F'\t' '$8 == "THROTTLED" { s += $1 } END { print s + 0 }' "$TAPWORK/hosts.tsv")
            echo "  Hosts over the per-host threshold (their further admissions of that type are ignored, so their"
            echo "  actively-resolved properties stop being rechecked): ${THR_HOSTS} host(s), ${THR_ADM} of the ${CB_TOTAL} named admissions."

            echo
            echo "  --- IP<->MAC pairing changes seen in these callbacks (a pairing change is itself an admission) ---"
            awk -F'\t' '
                $2 != "-" && $3 != "-" && $2 !~ /^224\./ { pair[$3, $2] = 1; macs[$2, $3] = 1 }
                END {
                    for (k in pair) { split(k, p, SUBSEP); ipn[p[1]]++; ips[p[1]] = ips[p[1]] (ips[p[1]] == "" ? "" : ",") p[2] }
                    for (k in macs) { split(k, p, SUBSEP); macn[p[1]]++; ml[p[1]] = ml[p[1]] (ml[p[1]] == "" ? "" : ",") p[2] }
                    for (m in ipn) if (ipn[m] > 1) { printf "    MAC %s seen with %d IPs: %s\n", m, ipn[m], ips[m]; f = 1 }
                    for (i in macn) if (macn[i] > 1) { printf "    IP %s seen with %d MACs: %s\n", i, macn[i], ml[i]; f = 1 }
                    if (!f) print "    (none in this window)"
                }
            ' "$TAPWORK/cb.tsv"
        fi
    fi

    echo
    echo "Notes: an IP shown as 224.x is Forescout's placeholder for a host with no known IP (MAC-only)."
    echo "The same event can be logged as two callbacks a few seconds apart; the engine counts both."
    exit 0
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
