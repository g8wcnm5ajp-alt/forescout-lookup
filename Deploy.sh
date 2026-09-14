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
# Usage: sudo ./Deploy.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="forescout-tech-support-collector"
CONTAINER_NAME="forescout-tech-support-collector"
NETWORK_NAME="TechSupportBridge"
HTTPS_PORT=8443
FW_HOOK_NAME="ForeScoutTechSupportHelper"
# Source CIDR allowed to reach the app's HTTPS port. Must be set explicitly
# (no default) -- a placeholder default here would either expose the app
# too broadly or silently firewall out the real admin LAN, confirmed live
# 2026-09-14 when an earlier documentation-only placeholder default did
# exactly that on a real deploy.
if [ -z "${ADMIN_CIDR:-}" ]; then
    echo "Error: ADMIN_CIDR is not set." >&2
    echo "Export it before running, e.g.:" >&2
    echo "    ADMIN_CIDR=192.168.1.0/24 ./Deploy.sh" >&2
    exit 1
fi

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

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed on this EM." >&2
    exit 1
fi

if [ ! -f "${DIR}/image.tar" ]; then
    echo "Error: ${DIR}/image.tar not found -- run this from inside the unpacked package." >&2
    exit 1
fi

if [ ! -x "$(command -v fstool)" ]; then
    echo "Error: fstool not found -- this script must run on a Forescout EM." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found on this EM's host OS -- required to run webapp-query.py." >&2
    exit 1
fi

if [ ! -f "$BUNDLED_WEBAPP_QUERY" ]; then
    echo "Error: ${BUNDLED_WEBAPP_QUERY} not found -- run this from inside the unpacked package." >&2
    exit 1
fi

echo "=== 1. SSH key for this app's own EM->appliance/EM calls ==="
mkdir -p "$(dirname "$WEBAPP_QUERY_WRAPPER")"
cp "$BUNDLED_WEBAPP_QUERY" "$WEBAPP_QUERY_WRAPPER"
chmod 755 "$WEBAPP_QUERY_WRAPPER"
echo "Installed webapp-query.py at $WEBAPP_QUERY_WRAPPER"

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
if ! grep -q "$KEY_COMMENT" "$AUTHORIZED_KEYS" 2>/dev/null; then
    PUBKEY_CONTENT="$(cat "${KEY_FILE}.pub")"
    echo "command=\"${WEBAPP_QUERY_WRAPPER}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${PUBKEY_CONTENT}" \
        >> "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    echo "Registered restricted key in $AUTHORIZED_KEYS"
else
    echo "Key already registered in $AUTHORIZED_KEYS -- skipped"
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
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$CERT_DIR/private.key" -out "$CERT_DIR/cert.pem" \
        -days 825 -subj "/CN=${EM_FQDN}" \
        -addext "subjectAltName=DNS:${EM_FQDN},IP:${EM_IP_FOR_CERT:-127.0.0.1}" \
        >/dev/null 2>&1
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

docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
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

EM_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

=== Done ===

  https://${EM_IP:-<this-EM-ip>}:${HTTPS_PORT}/

Default login: admin / a random password generated on first boot --
run 'docker logs' or check /data/initial-admin-password.txt on the
container's data volume to retrieve it.
(you will be forced to change this on first sign-in)

To uninstall later: sudo ./Remove.sh
EOF
