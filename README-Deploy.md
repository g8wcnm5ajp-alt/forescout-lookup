# ForeScout Tech Support Collector

Self-contained Forescout tech-support log collection tool, deployable directly onto an Enterprise Manager.

## Install

```
sudo ./Deploy.sh
```

`ADMIN_CIDR` scopes the source subnet allowed to reach the app's HTTPS port. It defaults to `0.0.0.0/0` (any source) -- to restrict it, set it explicitly: `sudo ADMIN_CIDR=<your management LAN, e.g. 192.168.1.0/24> ./Deploy.sh`.

Run this **on the EM itself**, as root, from inside this unpacked directory. It:

1. Installs the bundled `webapp-query.py` forced-command wrapper onto this EM (if not already present), generates a dedicated SSH keypair for this app, and registers it in this EM's own `authorized_keys`, restricted to that wrapper. The private key never leaves this box.
2. Generates a self-signed HTTPS cert on first install (browsers show a one-time trust warning). Reused as-is on any rerun — replace it later via the app's own Certificate page, or drop a real cert/key into `certs/` by hand before rerunning `Deploy.sh`.
3. Creates the `TechSupportBridge` docker network.
4. Loads and starts the container (restart policy `always`: it comes back after a reboot, after the app exits, and on every Docker-daemon start regardless of how it was last stopped).
5. Opens port 8443 through this EM's own firewall via `fstool fw addhook` (survives a firewall reactivation/reboot).
6. On a genuinely fresh install, waits briefly for the container to generate the initial admin account and **prints the login straight to this console** — no need to dig through `docker logs` or the data volume by hand.

Requires `docker` and `fstool` on the EM (both standard). The host-side scripts use the EM's own `python3` when it has one (9.x); on an EM without it (8.x, CentOS 7) `Deploy.sh` unpacks the bundled portable Python runtime instead -- nothing is downloaded, the package is self-contained.

Safe to re-run — every step is idempotent.

## Access

```
https://<this-EM's-IP>:8443/
```

Default login: `admin` / a random password generated on first boot -- `Deploy.sh` prints it directly to the console on a fresh install (see step 6 above). Also in the container logs (`docker logs`) and written once to `/data/initial-admin-password.txt` if you need it again before first sign-in — you'll be forced to change it on first sign-in, after which that file is deleted. On a redeploy into existing data (an account already set up), `Deploy.sh` says so instead of showing a password, since the login hasn't changed.

## Reset / restart

If the app stops answering (the page does not load, or the Debug Log / Support Log buttons fail):

```
sudo ./Reset.sh
```

It first saves evidence under `./data/reset-logs/<timestamp>/` (container log and state, memory/disk, the Docker daemon's journal), then asks the app to exit by itself so Docker's restart policy starts a fresh one (a stopped container is simply started; `docker restart` is only the fallback for a hung app), and waits for the login page to answer. The app's **Support Log** zip includes the newest capture automatically, so generate one afterwards and send it. `sudo ./Reset.sh --logs-only` captures without restarting.

While the app is still answering, the **Restart app** link at the top of the page does the same restart from the browser (the container restarts itself; running jobs are marked failed).

Note: a Forescout engine start/restart on the EM also restarts the Docker daemon, which stops every container for 10-20 s. The app comes back by itself afterwards, but anything in flight at that moment is lost -- the page says "the app isn't answering, retrying" while that happens.

## Uninstall

```
sudo ./Remove.sh
```

Leaves `./data`, `./keys`, and `./certs` in place by default (so a later re-`Deploy.sh` doesn't lose history or need a fresh key). Pass `--purge` to remove those too.

## What's in this package

- `Deploy.sh` / `Remove.sh` / `Reset.sh` — install / uninstall / capture-and-restart scripts.
- `image.tar` — the pre-built Docker image (`docker load`'d by `Deploy.sh`, nothing built at install time).
- `webapp-query.py` — the SSH forced-command wrapper Deploy.sh installs onto the EM's host OS.
- `high-admission-trace.sh` — admission analysis (Live Analyze tab, bundle Analyze buttons); installed next to the wrapper.
- `bundle-correlate.py` — multi-bundle offline correlation (Upload & Review Bundle tab's Correlate: an EM bundle plus its appliance bundle(s), clocks aligned, EM-to-appliance disconnect timeline, error/performance sweep); installed next to the wrapper.
- `radius-analyze.py` — RADIUS log analysis (Live Analyze and Upload & Review tabs); installed next to the wrapper. On an appliance without `python3` the logs are streamed to the EM and analysed there.
- `python-runtime.tar.gz` — portable CPython 3.12 (python-build-standalone, x86_64, glibc 2.17+). Unpacked to `/root/scripts/webapp-query/python/` only when the EM has no `python3` of its own; `Remove.sh --purge` removes it.
- `keys/`, `certs/`, `data/` — created by `Deploy.sh` on first install; not shipped in the package.
