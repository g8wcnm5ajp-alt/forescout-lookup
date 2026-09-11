#!/bin/bash
#
# Remove-230.sh -- uninstalls the Forescout Host Lookup web app (the
# start.sh-based deployment) from THIS host (192.168.22.230). Run this
# ON .230, with sudo, from anywhere.
#
# This is a companion to Remove.sh (which targets the EM-hosted /
# Deploy.sh-based install on the Forescout EM itself, .210) -- .230's
# install is structurally different: a generic Docker host with its
# source at /root/forescout-lookup/, no fstool, and its own dedicated
# SSH key trusted on .210 via a forced-command authorized_keys entry
# (that trust was already revoked on .210's side on 2026-09-11 -- see
# the vault's Remote Access note -- so this script only needs to clean
# up .230's own local half).
#
# Context: this box's SSH access was locked out on 2026-09-11 by a
# `firewall-cmd --reload` that discarded a batch of runtime-only (never
# `--permanent`) port allowances, port 22 included. If you're running
# this script, that access has presumably just been restored via
# console -- see the vault's Remote Access note for the exact recovery
# commands and full incident writeup before doing anything else here.
#
# Usage: sudo ./Remove-230.sh [--purge]
#   --purge also removes /root/forescout-lookup/data and .../keys
#   (scheduled-debug job history and the dedicated SSH keypair). Left in
#   place by default in case this deployment is ever reinstated.
set -euo pipefail

CONTAINER_NAME="forescout-lookup"
SOURCE_DIR="/root/forescout-lookup"

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

echo "=== 1. Removing the container ==="
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    echo "Removed container $CONTAINER_NAME"
else
    echo "Container $CONTAINER_NAME not found -- skipped"
fi

echo
echo "=== 2. Removing the built image ==="
if docker image inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    docker rmi "$CONTAINER_NAME" >/dev/null 2>&1 \
        && echo "Removed image $CONTAINER_NAME" \
        || echo "WARNING: could not remove image $CONTAINER_NAME (still tagged/used elsewhere?)" >&2
else
    echo "Image $CONTAINER_NAME not found -- skipped"
fi

echo
echo "=== 3. Removing the source directory ==="
if [ -d "$SOURCE_DIR" ]; then
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$SOURCE_DIR"
        echo "Removed $SOURCE_DIR entirely (--purge)"
    else
        rm -rf "${SOURCE_DIR:?}"/app.py "${SOURCE_DIR:?}"/forescout_client.py "${SOURCE_DIR:?}"/templates "${SOURCE_DIR:?}"/static \
               "${SOURCE_DIR:?}"/Dockerfile "${SOURCE_DIR:?}"/requirements.txt "${SOURCE_DIR:?}"/start.sh "${SOURCE_DIR:?}"/stop.sh
        echo "Removed app source from $SOURCE_DIR, leaving ${SOURCE_DIR}/data and ${SOURCE_DIR}/keys in place"
        echo "(pass --purge to remove those too)"
    fi
else
    echo "$SOURCE_DIR not found -- skipped"
fi

echo
echo "Done. Note: the corresponding forced-command SSH key trust on the"
echo "EM (192.168.22.210, authorized_keys comment 'forescout-lookup-webapp')"
echo "was already revoked from the .210 side on 2026-09-11 -- nothing further"
echo "needed there."
