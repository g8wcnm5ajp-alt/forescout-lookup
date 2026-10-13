#!/bin/bash
#
# build-dist.sh -- builds the Docker image and packages
# dist/ForeScoutTechSupport/, the thing you actually run Deploy.sh from.
# Run this from the repo root, wherever `docker` and `python3` are
# available (a dev machine, not the EM).
#
# Packages Deploy.sh, Remove.sh, README-Deploy.md (as README.md),
# webapp-query.py + its sibling scripts, the portable Python runtime
# (vendor/, see below) and a fresh image.tar into dist/ForeScoutTechSupport/.
#
# The runtime: vendor/ holds one python-build-standalone CPython tarball
# (install_only_stripped, x86_64 glibc, runs on CentOS/RHEL 7+) plus its
# published sha256, committed to this repo so a build never needs the
# internet -- the package has to be self-contained because customer EMs
# can't download anything (David, 2026-10-13). Deploy.sh unpacks it only
# on an EM without a python3 of its own (8.x). To move to a newer runtime:
# drop the new tarball + .sha256 from the project's GitHub release into
# vendor/, update VENDOR_PYTHON below, delete the old pair.
# That folder is tracked directly in git (not zipped) -- GitHub's own
# "Download ZIP" of this repo already lands you with image.tar sitting
# right next to Deploy.sh, no second unzip step. Confirmed live
# 2026-09-14 that nesting a zip-of-the-package inside the repo zip was
# a real, repeated source of "image.tar not found" confusion -- fixed
# by not nesting a zip at all.
#
# Also builds dist/ForeScoutTechSupport.zip (gitignored, NOT committed)
# for uploading as a GitHub Release asset -- a single clean-named
# download for anyone who doesn't want the whole source repo. Built
# with Python's zipfile module directly rather than `zip`/PowerShell's
# Compress-Archive: Compress-Archive tags the archive with a
# Windows/FAT host byte even though it stores forward-slash paths --
# confirmed live 2026-09-14 that this makes some `unzip` builds print
# "appears to use backslashes as path separators" and, on a stricter
# implementation than this EM's own InfoZip 6.00 (which merely
# warned), can extract flat files with literal backslashes in the name
# instead of a real subdirectory. Forcing forward-slash arcnames and a
# Unix create_system byte avoids the ambiguity outright.
#
# Usage: ./build-dist.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="forescout-tech-support-collector"
PKG_DIR="${DIR}/dist/ForeScoutTechSupport"
ZIP_PATH="${DIR}/dist/ForeScoutTechSupport.zip"
VENDOR_PYTHON="${DIR}/vendor/cpython-3.12.15+20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed/available." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is not installed/available (needed to build the release zip correctly)." >&2
    exit 1
fi
if [ ! -f "$VENDOR_PYTHON" ] || [ ! -f "${VENDOR_PYTHON}.sha256" ]; then
    echo "Error: ${VENDOR_PYTHON} (+ .sha256) not found -- the portable Python runtime must be committed in vendor/." >&2
    exit 1
fi

echo "=== 1. Building the Docker image ==="
docker build -t "${IMAGE_NAME}:latest" "$DIR"

echo
echo "=== 2. Staging the package (dist/ForeScoutTechSupport/, tracked in git) ==="
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"
cp "${DIR}/Deploy.sh" "${DIR}/Remove.sh" "$PKG_DIR/"
cp "${DIR}/README-Deploy.md" "${PKG_DIR}/README.md"
cp "${DIR}/webapp-query.py" "${DIR}/high-admission-trace.sh" "${DIR}/bundle-correlate.py" "${DIR}/radius-analyze.py" "$PKG_DIR/"
echo "Staged Deploy.sh, Remove.sh, README.md, webapp-query.py, high-admission-trace.sh, bundle-correlate.py, radius-analyze.py"
# the runtime, verified against its published checksum before it is staged
( cd "$(dirname "$VENDOR_PYTHON")" && sha256sum -c --quiet "$(basename "$VENDOR_PYTHON").sha256" ) \
    || { echo "Error: ${VENDOR_PYTHON} does not match its .sha256 -- refusing to ship it." >&2; exit 1; }
cp "$VENDOR_PYTHON" "${PKG_DIR}/python-runtime.tar.gz"
echo "Staged python-runtime.tar.gz ($(basename "$VENDOR_PYTHON"), $(du -h "$VENDOR_PYTHON" | cut -f1), sha256 verified)"

echo
echo "=== 3. Exporting the image ==="
docker save -o "${PKG_DIR}/image.tar" "${IMAGE_NAME}:latest"
echo "Exported image.tar ($(du -h "${PKG_DIR}/image.tar" | cut -f1))"

echo
echo "=== 4. Building the Release zip (forward-slash paths, Unix host byte, gitignored) ==="
python3 - "$DIR/dist" "$ZIP_PATH" <<'PYEOF'
import os
import sys
import zipfile

dist_dir, zip_path = sys.argv[1], sys.argv[2]
src = os.path.join(dist_dir, "ForeScoutTechSupport")

if os.path.exists(zip_path):
    os.remove(zip_path)

# Scripts that need +x once unzipped on the EM (a real Linux box).
EXECUTABLE_NAMES = {"Deploy.sh", "Remove.sh", "webapp-query.py", "high-admission-trace.sh", "bundle-correlate.py", "radius-analyze.py"}

with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
    for name in sorted(os.listdir(src)):
        full = os.path.join(src, name)
        arcname = "ForeScoutTechSupport/" + name
        info = zipfile.ZipInfo.from_file(full, arcname)
        info.create_system = 3  # Unix -- see the header comment for why this matters
        # Set the Unix permission bits explicitly rather than trust what
        # ZipInfo.from_file() read from os.stat() -- confirmed live
        # 2026-09-14 that on Windows (where this script actually runs),
        # os.stat().st_mode never reflects a real executable bit no
        # matter what git or a local `ls` claims, so every script in the
        # release zip extracted on the real (Linux) EM as -rw-rw-rw-,
        # unrunnable without a manual chmod. This is the one place that
        # bit actually has to be forced correct, since (unlike the plain
        # git-tracked package folder) git's own mode tracking doesn't
        # apply to a zip built by hand.
        mode = 0o755 if name in EXECUTABLE_NAMES else 0o644
        info.external_attr = (mode << 16) | (info.external_attr & 0xFFFF)
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(full, "rb") as f:
            zf.writestr(info, f.read())
        print("  added", arcname)
PYEOF

echo
echo "=== Done ==="
echo "  Repo package (commit this):  ${PKG_DIR}"
echo "  Release asset (upload this, don't commit): ${ZIP_PATH}"
