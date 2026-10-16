#!/bin/bash
#
# Deploy.sh -- installs the Forescout Tech Support Collector directly
# on THIS Enterprise Manager. Run this ON the EM, as root, from inside
# the unpacked ForescoutTechSupportCollector directory.
#
# What this does, in order (each step is idempotent -- safe to re-run
# this whole script, e.g. to pick up a renewed cert or redeploy a
# newer image, without duplicating anything):
#   1. Installs the bundled webapp-query.py forced-command wrapper onto
#      this EM (if not already present), generates a dedicated SSH
#      keypair for this app, and registers its public half in this
#      EM's own authorized_keys restricted to ONLY that wrapper -- the
#      private key never leaves this box.
#   2. Generates a self-signed HTTPS cert on first install (browsers
#      show a one-time trust warning) -- reuses it as-is on any rerun,
#      including one dropped into certs/ later via the app's own
#      Certificate page.
#   3. Creates the TechSupportBridge docker network.
#   4. Loads and runs the bundled image -- auto-restarts on reboot.
#   5. Opens the app's port through this EM's own built-in firewall via
#      fstool's own addhook mechanism (survives an EM firewall
#      reactivation/reboot, unlike a raw iptables rule added by hand).
#
# Python: webapp-query.py and its sibling scripts run on this EM's own
# OS, outside the container (they need fstool, the EM's root trust to
# the appliances and the EM's own log files -- none of which exist in
# the image). A 9.x EM ships python3 (3.9 on RHEL 9) and that is used
# as-is. An 8.x EM (CentOS 7) has no python3 at all -- confirmed live
# 2026-10-13 on an 8.5.2.2 EM ("Error: python3 not found") -- so the
# package carries its own portable CPython (python-build-standalone
# install_only build, glibc >= 2.17 = CentOS/RHEL 7 or newer) and this
# script unpacks it ONLY when the host has no usable python3. Nothing
# is downloaded on the EM; the package is self-contained (David's rule,
# 2026-10-13: "Can't download anything, everything needs to be self
# contained").
#
# Usage: sudo ./Deploy.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="forescout-tech-support-collector"
CONTAINER_NAME="forescout-tech-support-collector"
NETWORK_NAME="TechSupportBridge"
HTTPS_PORT=8443
FW_HOOK_NAME="ForeScoutTechSupportHelper"
# Source CIDR allowed to reach the app's HTTPS port. Defaults to
# 0.0.0.0/0 (open to any source) -- David's explicit call 2026-09-14,
# reverting the earlier same-day no-default hardening (which existed
# because a placeholder default had once silently firewalled out the
# real admin LAN). Override with ADMIN_CIDR=<cidr> ./Deploy.sh to scope
# this down to a specific network.
ADMIN_CIDR="${ADMIN_CIDR:-0.0.0.0/0}"

KEY_DIR="${DIR}/keys"
KEY_FILE="${KEY_DIR}/webapp_query_rsa"
KEY_COMMENT="forescout-tech-support-collector-em"
CERT_DIR="${DIR}/certs"
DATA_DIR="${DIR}/data"
APACHE_CERT="/usr/local/forescout/etc/net_portal_ssl/cert.pem"
APACHE_KEY="/usr/local/forescout/etc/net_portal_ssl/private.key"
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
WEBAPP_QUERY_WRAPPER="/root/scripts/webapp-query/webapp-query.py"
BUNDLED_WEBAPP_QUERY="${DIR}/webapp-query.py"
# high-admission-trace.sh (the High Admission Root-Cause Tracing tool) --
# webapp-query.py reads this sibling file fresh on every analyzeadm/
# pluginlogszip call and pipes it into `bash -s` on whichever target is
# being analyzed, so a redeploy of this one file is all it takes to pick
# up a newer version, no per-appliance deployment needed.
HAT_SCRIPT="/root/scripts/webapp-query/high-admission-trace.sh"
BUNDLED_HAT_SCRIPT="${DIR}/high-admission-trace.sh"
# bundle-correlate.py (Upload & Review Bundle tab's multi-bundle Correlate)
# -- webapp-query.py's bundlecorrelate verb runs this sibling file on this
# EM's own python3. Same arrangement: redeploying the file is the upgrade.
CORRELATE_SCRIPT="/root/scripts/webapp-query/bundle-correlate.py"
BUNDLED_CORRELATE_SCRIPT="${DIR}/bundle-correlate.py"
# radius-analyze.py (RADIUS Log Analysis on the Live Analyze and Upload & Review tabs)
RADIUS_SCRIPT="/root/scripts/webapp-query/radius-analyze.py"
BUNDLED_RADIUS_SCRIPT="${DIR}/radius-analyze.py"
# Portable Python runtime -- see the header. Unpacked next to the wrapper
# only when this EM has no python3 of its own.
BUNDLED_PYTHON_TARBALL="${DIR}/python-runtime.tar.gz"
BUNDLED_PYTHON_DIR="/root/scripts/webapp-query/python"
BUNDLED_PYTHON_BIN="${BUNDLED_PYTHON_DIR}/bin/python3"

# True when "$1" is an executable Python 3.8+ (the oldest the host-side
# scripts are written for).
python_ok() {
    [ -n "${1:-}" ] && [ -x "$1" ] || return 1
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed on this EM." >&2
    exit 1
fi

if [ ! -f "${DIR}/image.tar" ]; then
    echo "Error: ${DIR}/image.tar not found." >&2
    if [ -d "${DIR}/dist/ForeScoutTechSupport" ]; then
        echo "You're running this from the source repo root -- the deployable package is in dist/ForeScoutTechSupport/." >&2
        echo "  cd dist/ForeScoutTechSupport && ADMIN_CIDR=<your LAN> ./Deploy.sh" >&2
    else
        echo "Run this from inside the unpacked ForeScoutTechSupport package (the folder/zip that has Deploy.sh and image.tar together)." >&2
    fi
    exit 1
fi

if [ ! -x "$(command -v fstool)" ]; then
    echo "Error: fstool not found -- this script must run on a Forescout EM." >&2
    exit 1
fi

HOST_PYTHON="$(command -v python3 2>/dev/null || true)"
if python_ok "$HOST_PYTHON"; then
    PYTHON_BIN="$HOST_PYTHON"
    PYTHON_SOURCE="this EM's own $("$PYTHON_BIN" -c 'import platform; print("Python " + platform.python_version())')"
else
    if [ ! -f "$BUNDLED_PYTHON_TARBALL" ]; then
        echo "Error: this EM has no python3 (3.8+) and ${BUNDLED_PYTHON_TARBALL} is missing -- run this from inside the unpacked package." >&2
        exit 1
    fi
    PYTHON_BIN="$BUNDLED_PYTHON_BIN"
    PYTHON_SOURCE="the bundled portable runtime (this EM has no python3 of its own)"
fi

if [ ! -f "$BUNDLED_WEBAPP_QUERY" ]; then
    echo "Error: ${BUNDLED_WEBAPP_QUERY} not found -- run this from inside the unpacked package." >&2
    exit 1
fi
if [ ! -f "$BUNDLED_HAT_SCRIPT" ]; then
    echo "Error: ${BUNDLED_HAT_SCRIPT} not found -- run this from inside the unpacked package." >&2
    exit 1
fi
if [ ! -f "$BUNDLED_CORRELATE_SCRIPT" ]; then
    echo "Error: ${BUNDLED_CORRELATE_SCRIPT} not found -- run this from inside the unpacked package." >&2
    exit 1
fi

echo "=== 1. SSH key for this app's own EM->appliance/EM calls ==="
mkdir -p "$(dirname "$WEBAPP_QUERY_WRAPPER")"

if [ "$PYTHON_BIN" = "$BUNDLED_PYTHON_BIN" ]; then
    # Idempotent: the unpacked tree is stamped with the tarball's sha256, so
    # a redeploy with the same runtime skips the 34 MB extraction and a
    # package carrying a newer runtime replaces the old tree cleanly.
    WANT_STAMP="$(sha256sum "$BUNDLED_PYTHON_TARBALL" | cut -d' ' -f1)"
    HAVE_STAMP="$(cat "${BUNDLED_PYTHON_DIR}/.runtime-sha256" 2>/dev/null || true)"
    if [ "$WANT_STAMP" != "$HAVE_STAMP" ] || ! python_ok "$BUNDLED_PYTHON_BIN"; then
        rm -rf "$BUNDLED_PYTHON_DIR"
        mkdir -p "$BUNDLED_PYTHON_DIR"
        # the archive's single top-level dir (python/) is stripped so bin/ and lib/ land directly here
        tar -xzf "$BUNDLED_PYTHON_TARBALL" -C "$BUNDLED_PYTHON_DIR" --strip-components=1
        echo "$WANT_STAMP" > "${BUNDLED_PYTHON_DIR}/.runtime-sha256"
        echo "Unpacked the bundled Python runtime to $BUNDLED_PYTHON_DIR"
    else
        echo "Bundled Python runtime already in place at $BUNDLED_PYTHON_DIR -- not re-extracting"
    fi
    if ! python_ok "$BUNDLED_PYTHON_BIN"; then
        echo "Error: the bundled Python runtime does not run on this EM ($("$BUNDLED_PYTHON_BIN" --version 2>&1 | tail -1))." >&2
        echo "It needs x86_64 and glibc 2.17 or newer (CentOS/RHEL 7 or later): $(uname -m), $(ldd --version 2>&1 | head -1)" >&2
        exit 1
    fi
fi
echo "Host-side scripts will run on ${PYTHON_SOURCE}: ${PYTHON_BIN}"

# Pin each installed script to the chosen interpreter: sshd runs the forced
# command by its shebang, and webapp-query.py launches its siblings with
# sys.executable, so this one line per file is the whole wiring.
install_py() {
    cp "$1" "$2"
    sed -i "1s|^#!.*|#!${PYTHON_BIN}|" "$2"
    chmod 755 "$2"
}
install_py "$BUNDLED_WEBAPP_QUERY" "$WEBAPP_QUERY_WRAPPER"
cp "$BUNDLED_HAT_SCRIPT" "$HAT_SCRIPT"
chmod 755 "$HAT_SCRIPT"
install_py "$BUNDLED_CORRELATE_SCRIPT" "$CORRELATE_SCRIPT"
install_py "$BUNDLED_RADIUS_SCRIPT" "$RADIUS_SCRIPT"
echo "Installed webapp-query.py at $WEBAPP_QUERY_WRAPPER"
echo "Installed high-admission-trace.sh at $HAT_SCRIPT"
echo "Installed bundle-correlate.py at $CORRELATE_SCRIPT"
echo "Installed radius-analyze.py at $RADIUS_SCRIPT"

mkdir -p "$KEY_DIR"
if [ ! -f "$KEY_FILE" ]; then
    ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -N "" -C "$KEY_COMMENT" -q
    echo "Generated new keypair at $KEY_FILE"
else
    echo "Keypair already exists at $KEY_FILE -- not regenerating"
fi
chmod 600 "$KEY_FILE"
chmod 644 "${KEY_FILE}.pub"

mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
touch "$AUTHORIZED_KEYS"
PUBKEY_CONTENT="$(cat "${KEY_FILE}.pub")"
DESIRED_LINE="command=\"${WEBAPP_QUERY_WRAPPER}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${PUBKEY_CONTENT}"
if grep -qF "$DESIRED_LINE" "$AUTHORIZED_KEYS" 2>/dev/null; then
    echo "Key already registered in $AUTHORIZED_KEYS -- skipped"
else
    # Compare actual key CONTENT, not just the comment -- a comment-only match
    # left a stale entry registered across a keypair regeneration before
    # (confirmed live 2026-09-14: the local keys/ dir got a fresh keypair on
    # a later redeploy, but this comment-only check thought it was already
    # registered and never updated authorized_keys, breaking every SSH call
    # this app made until the mismatch was found and fixed by hand). Drop any
    # existing entry for this app before adding the current one, so a stale
    # key from an earlier keypair can never linger.
    grep -v "$KEY_COMMENT" "$AUTHORIZED_KEYS" > "${AUTHORIZED_KEYS}.tmp" 2>/dev/null || true
    mv "${AUTHORIZED_KEYS}.tmp" "$AUTHORIZED_KEYS"
    echo "$DESIRED_LINE" >> "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    echo "Registered restricted key in $AUTHORIZED_KEYS (replaced any stale entry)"
fi

echo
echo "=== 2. HTTPS certificate ==="
mkdir -p "$CERT_DIR"
KEY_PASSWORD_FILE="${CERT_DIR}/key_password.txt"

if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/private.key" ]; then
    echo "Using cert/key already in $CERT_DIR from a previous run -- not touching them"
    echo "(delete $CERT_DIR/cert.pem and $CERT_DIR/private.key first if you want a new one generated,"
    echo " or replace them via the app's own Certificate page once it's running)"
else
    echo "No cert/key found in $CERT_DIR yet -- generating a self-signed one."
    echo "(browsers will show a one-time trust warning; replace it later via the app's own Certificate page)"
    EM_IP_FOR_CERT="$(hostname -I 2>/dev/null | awk '{print $1}')"
    EM_FQDN="$(hostname -f 2>/dev/null || hostname)"
    # The SAN goes in via a temporary openssl config, NOT `-addext`: that
    # flag only exists in OpenSSL 1.1.1+, and an 8.x EM (CentOS 7) ships
    # OpenSSL 1.0.2, which rejects it and -- under `set -e` -- aborts the
    # whole deploy (confirmed live 2026-10-13 on an 8.5.3-582 EM:
    # "unknown option -addext"). A config file with an x509v3 extensions
    # section is understood by 1.0.2 and 1.1.1+ alike, so this one path
    # covers every EM.
    CERT_CONF="$(mktemp)"
    cat > "$CERT_CONF" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ext
prompt = no
[dn]
CN = ${EM_FQDN}
[v3_ext]
subjectAltName = DNS:${EM_FQDN},IP:${EM_IP_FOR_CERT:-127.0.0.1}
EOF
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$CERT_DIR/private.key" -out "$CERT_DIR/cert.pem" \
        -days 825 -config "$CERT_CONF" \
        >/dev/null 2>&1
    rm -f "$CERT_CONF"
    chmod 600 "$CERT_DIR/private.key"
    echo "Generated a self-signed cert for ${EM_FQDN} in $CERT_DIR"
fi

if grep -q "ENCRYPTED" "$CERT_DIR/private.key" 2>/dev/null && [ ! -f "$KEY_PASSWORD_FILE" ]; then
    echo "WARNING: $CERT_DIR/private.key looks passphrase-protected but $KEY_PASSWORD_FILE is missing." >&2
    echo "The app will fail to start until you create it:" >&2
    echo "    echo -n 'the-passphrase' > $KEY_PASSWORD_FILE && chmod 600 $KEY_PASSWORD_FILE" >&2
fi

echo
echo "=== 3. Docker network ==="
if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    docker network create "$NETWORK_NAME" >/dev/null
    echo "Created docker network $NETWORK_NAME"
else
    echo "Docker network $NETWORK_NAME already exists -- skipped"
fi

# Docker's "host-gateway" magic value for --add-host is unreliable on
# some bridge-network setups (seen in practice: it resolves to <nil>
# in /etc/hosts instead of a real IP). Resolving the network's own
# gateway IP ourselves and passing that concrete address instead is
# what actually works every time.
BRIDGE_GATEWAY="$(docker network inspect "$NETWORK_NAME" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
if [ -z "$BRIDGE_GATEWAY" ]; then
    echo "Error: could not determine ${NETWORK_NAME}'s gateway IP." >&2
    exit 1
fi
echo "Container will reach this EM via host.docker.internal -> ${BRIDGE_GATEWAY}"

echo
echo "=== 4. Loading and starting the container ==="
docker load -i "${DIR}/image.tar"

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "Removing existing $CONTAINER_NAME container ..."
    docker rm -f "$CONTAINER_NAME" >/dev/null
fi

mkdir -p "$DATA_DIR"

# Deploy counter -- David's standing rule (2026-09-14): every real deploy
# increments this, independent of the hand-curated semantic APP_VERSION in
# app.py, so it's always possible to tell at a glance whether a given
# instance is actually running the latest deploy, not a stale one. Persists
# across redeploys into the same DATA_DIR; resets only on a --purge'd
# Remove.sh (which wipes DATA_DIR entirely, same as everything else in it).
DEPLOY_COUNT_FILE="${DATA_DIR}/deploy_count.txt"
DEPLOY_COUNT=$(( $(cat "$DEPLOY_COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$DEPLOY_COUNT" > "$DEPLOY_COUNT_FILE"
echo "Deploy #${DEPLOY_COUNT}"

# Recorded before the container starts -- tells the wait-for-password step
# below whether this is a genuinely fresh account (redeployed into an empty
# data dir) or a redeploy into existing data (account already set up, no
# new password to show).
ACCOUNT_ALREADY_EXISTED=0
[ -f "${DATA_DIR}/auth.json" ] && ACCOUNT_ALREADY_EXISTED=1

docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --restart always \
    --add-host="host.docker.internal:${BRIDGE_GATEWAY}" \
    -p "${HTTPS_PORT}:5000" \
    -v "${KEY_DIR}:/keys:ro" \
    -v "${CERT_DIR}:/certs" \
    -v "${DATA_DIR}:/data" \
    -v "$(dirname "$APACHE_CERT"):/host-apache-certs:ro" \
    -e FORESCOUT_EM_HOST=host.docker.internal \
    -e FORESCOUT_SSL_CERT=/certs/cert.pem \
    -e FORESCOUT_SSL_KEY=/certs/private.key \
    -e FORESCOUT_SSL_KEY_PASSWORD_FILE=/certs/key_password.txt \
    "$IMAGE_NAME" >/dev/null

echo "Container $CONTAINER_NAME started"

echo
echo "=== 5. Opening the firewall port (fstool fw addhook) ==="
echo "Restricting access to ${ADMIN_CIDR} (override with ADMIN_CIDR=... ./Deploy.sh)"
fstool fw delhook "$FW_HOOK_NAME" >/dev/null 2>&1 || true
fstool fw addhook "$FW_HOOK_NAME" "iptables -I INPUT -s ${ADMIN_CIDR} -m tcp -p tcp --dport ${HTTPS_PORT} -j ACCEPT"
if iptables -L INPUT -n | grep -q "dpt:${HTTPS_PORT}"; then
    echo "Firewall rule for port $HTTPS_PORT confirmed active"
else
    echo "WARNING: could not confirm the firewall rule via iptables -- check by hand." >&2
fi
# Keeps the app's own Setup page (getadmincidr) accurate even when
# ADMIN_CIDR was only ever set here, never through the GUI.
echo "${ADMIN_CIDR}" > "$(dirname "$WEBAPP_QUERY_WRAPPER")/admin_cidr.state" 2>/dev/null || true

echo
echo "=== 6. Initial admin login ==="
# David's ask, 2026-09-14: print the actual login on this console right
# after a deploy, not just point at docker logs/the data file -- app.py
# now generates the account eagerly at startup (not lazily on first
# /login attempt), so it should already exist by the time the container
# is up; this just waits briefly for it and reads it back.
LOGIN_LINE="Default login: admin / <not shown -- see below>"
if [ "$ACCOUNT_ALREADY_EXISTED" -eq 1 ]; then
    LOGIN_LINE="An admin account already existed in this data dir before this deploy -- login is unchanged from before, not shown here."
else
    INITIAL_PW=""
    for _ in $(seq 1 10); do
        if [ -f "${DATA_DIR}/initial-admin-password.txt" ]; then
            INITIAL_PW="$(cat "${DATA_DIR}/initial-admin-password.txt")"
            break
        fi
        sleep 1
    done
    if [ -n "$INITIAL_PW" ]; then
        LOGIN_LINE="Default login: admin / ${INITIAL_PW}  (you will be forced to change this on first sign-in)"
    else
        LOGIN_LINE="Could not confirm the initial password within 10s -- check 'docker logs ${CONTAINER_NAME}' or ${DATA_DIR}/initial-admin-password.txt by hand."
    fi
fi
echo "$LOGIN_LINE"

EM_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

=== Done ===

  https://${EM_IP:-<this-EM-ip>}:${HTTPS_PORT}/

${LOGIN_LINE}

To uninstall later: sudo ./Remove.sh
EOF
