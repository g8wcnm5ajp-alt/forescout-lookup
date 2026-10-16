#!/bin/bash
#
# Reset.sh -- captures evidence, then restarts the Forescout Tech
# Support Collector container on this Enterprise Manager. Run this ON
# the EM, as root, from inside the same directory Deploy.sh was run from.
#
# Why (David, 2026-10-16): on a customer site the app looked crashed --
# the Support Log and Debug Log buttons no longer answered, so there was
# nothing to send back for diagnosis. This script grabs what the
# container can still tell us BEFORE bouncing it (container log, state,
# memory/disk, the Docker daemon's own journal), then restarts the
# container and waits for the login page to answer. The app's Support
# Log zip picks up the newest capture automatically, so the evidence
# comes home with the next support log.
#
# Note: a Forescout engine start/restart on an EM also stops and starts
# the Docker daemon (its own plugin command modules do this), which
# kills every container for 10-20 s -- the app comes back by itself
# afterwards, but anything in flight is lost. If the "crash" lines up
# with an engine restart, that is why; the dockerd journal captured here
# shows it.
#
# How the restart works: a running app is asked to exit by itself (SIGINT to
# its process through `docker exec`), and Docker's restart policy starts a
# fresh one in ~2 s. `docker restart` is only the fallback for a hung app --
# a manual stop marks the container "manually stopped", and a Docker-daemon
# restart landing right then left the app down for good (2026-10-16). A
# stopped container is simply started.
#
# Usage: sudo ./Reset.sh              capture evidence, then restart the container
#        sudo ./Reset.sh --logs-only  capture evidence only, leave the app running
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="forescout-tech-support-collector"
HTTPS_PORT=8443
DATA_DIR="${DIR}/data"
KEEP_CAPTURES=10

LOGS_ONLY=0
[ "${1:-}" = "--logs-only" ] && LOGS_ONLY=1

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed/available on this EM." >&2
    exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${DATA_DIR}/reset-logs/${TS}"
mkdir -p "$OUT"

echo "=== 1. Capturing evidence -> ${OUT} ==="
{
    echo "Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC), host $(hostname)"
    echo "Mode: $([ "$LOGS_ONLY" = 1 ] && echo logs-only || echo restart)"
    echo "Uptime: $(uptime)"
    echo
    echo "--- fstool service status ---"
    fstool service status 2>&1 | head -3
    echo
    echo "--- login page before reset ---"
    curl -sk -o /dev/null -m 10 -w "HTTP %{http_code} in %{time_total}s\n" "https://127.0.0.1:${HTTPS_PORT}/login" 2>&1 || echo "no answer"
    echo
    echo "--- memory ---"
    free -m
    echo
    echo "--- disk ---"
    df -h "$DIR" / 2>/dev/null
} > "${OUT}/summary.txt" 2>&1

CONTAINER_EXISTS=1
docker inspect "$CONTAINER_NAME" >/dev/null 2>&1 || CONTAINER_EXISTS=0

if [ "$CONTAINER_EXISTS" = 1 ]; then
    docker inspect "$CONTAINER_NAME" --format \
        'Status={{.State.Status}} Running={{.State.Running}} ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}} StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}} RestartCount={{.RestartCount}} RestartPolicy={{.HostConfig.RestartPolicy.Name}} Image={{.Config.Image}}' \
        > "${OUT}/container-state.txt" 2>&1
    docker inspect "$CONTAINER_NAME" > "${OUT}/container-inspect.json" 2>&1
    docker logs --tail 2000 --timestamps "$CONTAINER_NAME" > "${OUT}/container.log" 2>&1
    docker stats --no-stream "$CONTAINER_NAME" > "${OUT}/container-stats.txt" 2>&1
    docker top "$CONTAINER_NAME" > "${OUT}/container-top.txt" 2>&1
else
    echo "Container ${CONTAINER_NAME} does not exist on this EM." > "${OUT}/container-state.txt"
fi
docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}' > "${OUT}/docker-ps.txt" 2>&1
docker info > "${OUT}/docker-info.txt" 2>&1
journalctl -u docker -n 200 --no-pager > "${OUT}/dockerd-journal.txt" 2>&1 || true
# The EM's engine restarts bounce dockerd -- this shows whether one happened just now.
journalctl -u docker --since "-24 hours" --no-pager 2>/dev/null | grep -E "Started Docker|Stopping Docker" > "${OUT}/dockerd-starts-24h.txt" 2>&1 || true
dmesg -T 2>/dev/null | grep -i -E "oom|out of memory|killed process" | tail -50 > "${OUT}/dmesg-oom.txt" 2>&1 || true

# Keep only the newest captures so /data does not fill up over time.
ls -1d "${DATA_DIR}/reset-logs"/*/ 2>/dev/null | sort | head -n -"$KEEP_CAPTURES" | xargs -r rm -rf

cat "${OUT}/summary.txt"
echo
echo "Container: $(cat "${OUT}/container-state.txt")"
echo "Docker daemon starts in the last 24 h: $(grep -c "Started Docker" "${OUT}/dockerd-starts-24h.txt" 2>/dev/null || echo 0)"
echo "Evidence saved under ${OUT} (the app's Support Log zip includes the newest capture)."

# Shows up in the app's Recent activity (same JSON-lines file the app writes).
printf '{"logged_at": %d, "action": "reset_sh", "remote_addr": "(EM console)", "user_agent": "", "mode": "%s", "capture": "%s"}\n' \
    "$(date +%s)" "$([ "$LOGS_ONLY" = 1 ] && echo logs-only || echo restart)" "reset-logs/${TS}" \
    >> "${DATA_DIR}/activity_log.jsonl" 2>/dev/null || true

if [ "$LOGS_ONLY" = 1 ]; then
    echo
    echo "--logs-only: nothing restarted."
    exit 0
fi

if [ "$CONTAINER_EXISTS" = 0 ]; then
    echo
    echo "Nothing to restart: the container does not exist. Run: sudo ./Deploy.sh" >&2
    exit 2
fi

echo
echo "=== 2. Restarting the container ==="
STATE="$(docker inspect "$CONTAINER_NAME" --format '{{.State.Status}}' 2>/dev/null || echo unknown)"
STARTED_BEFORE="$(docker inspect "$CONTAINER_NAME" --format '{{.State.StartedAt}}' 2>/dev/null || true)"
RESTARTED_VIA=""
if [ "$STATE" = "running" ]; then
    # Ask the app to exit by itself (SIGINT ends the server cleanly) so Docker's own restart
    # policy starts a fresh process in ~2 s. NOT `docker restart`: that marks the container as
    # manually stopped, and a Docker-daemon restart (every EM engine start/restart does one)
    # landing in that window leaves the app down for good -- seen live 2026-10-16.
    if timeout 15 docker exec "$CONTAINER_NAME" python -c 'import os, signal; os.kill(1, signal.SIGINT)' >/dev/null 2>&1; then
        RESTARTED_VIA="self-exit"
        echo "Asked the app to exit at $(date +%T); Docker's restart policy brings a fresh process up ..."
        for i in $(seq 1 10); do
            now="$(docker inspect "$CONTAINER_NAME" --format '{{.State.StartedAt}}' 2>/dev/null || true)"
            [ -n "$now" ] && [ "$now" != "$STARTED_BEFORE" ] && break
            sleep 1
        done
        now="$(docker inspect "$CONTAINER_NAME" --format '{{.State.StartedAt}}' 2>/dev/null || true)"
        if [ "$now" = "$STARTED_BEFORE" ]; then
            echo "The app did not exit on request (hung?) -- falling back to docker restart."
            RESTARTED_VIA=""
        fi
    else
        echo "Could not signal the app (docker exec failed or hung) -- falling back to docker restart."
    fi
    if [ -z "$RESTARTED_VIA" ]; then
        if ! docker restart -t 5 "$CONTAINER_NAME" >/dev/null; then
            echo "docker restart failed -- try: sudo ./Deploy.sh (redeploys the same image, keeps data/keys/certs)." >&2
            exit 1
        fi
        RESTARTED_VIA="docker restart"
    fi
else
    echo "Container is '${STATE}' -- starting it."
    if ! docker start "$CONTAINER_NAME" >/dev/null; then
        echo "docker start failed -- try: sudo ./Deploy.sh (redeploys the same image, keeps data/keys/certs)." >&2
        exit 1
    fi
    RESTARTED_VIA="docker start"
fi
echo "Restarted via ${RESTARTED_VIA} at $(date +%T); waiting for the login page on port ${HTTPS_PORT} ..."

for i in $(seq 1 30); do
    code="$(curl -sk -o /dev/null -m 5 -w '%{http_code}' "https://127.0.0.1:${HTTPS_PORT}/login" 2>/dev/null || true)"
    now="$(docker inspect "$CONTAINER_NAME" --format '{{.State.StartedAt}}' 2>/dev/null || true)"
    if [ "$code" = "200" ] && [ "$now" != "$STARTED_BEFORE" ]; then
        echo "App is answering again (HTTP 200 after $((i * 2)) s)."
        echo
        echo "=== Done ===  https://$(hostname -I 2>/dev/null | awk '{print $1}'):${HTTPS_PORT}/"
        exit 0
    fi
    sleep 2
done

echo "The app is still not answering after 60 s. Container state now:" >&2
docker ps -a --filter "name=${CONTAINER_NAME}" --format '{{.Names}}\t{{.Status}}' >&2
echo "Last container log lines:" >&2
docker logs --tail 30 "$CONTAINER_NAME" >&2 2>&1
echo "Next step: sudo ./Deploy.sh (redeploys the same image, keeps data/keys/certs)." >&2
exit 1
