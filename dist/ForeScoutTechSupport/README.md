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
4. Loads and starts the container (auto-restarts on reboot).
5. Opens port 8443 through this EM's own firewall via `fstool fw addhook` (survives a firewall reactivation/reboot).
6. On a genuinely fresh install, waits briefly for the container to generate the initial admin account and **prints the login straight to this console** — no need to dig through `docker logs` or the data volume by hand.

Requires `docker`, `fstool`, and `python3` already present on the EM (all standard on a Forescout EM).

Safe to re-run — every step is idempotent.

## Access

```
https://<this-EM's-IP>:8443/
```

Default login: `admin` / a random password generated on first boot -- `Deploy.sh` prints it directly to the console on a fresh install (see step 6 above). Also in the container logs (`docker logs`) and written once to `/data/initial-admin-password.txt` if you need it again before first sign-in — you'll be forced to change it on first sign-in, after which that file is deleted. On a redeploy into existing data (an account already set up), `Deploy.sh` says so instead of showing a password, since the login hasn't changed.

## Uninstall

```
sudo ./Remove.sh
```

Leaves `./data`, `./keys`, and `./certs` in place by default (so a later re-`Deploy.sh` doesn't lose history or need a fresh key). Pass `--purge` to remove those too.

## What's in this package

- `Deploy.sh` / `Remove.sh` — install/uninstall scripts.
- `image.tar` — the pre-built Docker image (`docker load`'d by `Deploy.sh`, nothing built at install time).
- `webapp-query.py` — the SSH forced-command wrapper Deploy.sh installs onto the EM's host OS.
- `keys/`, `certs/`, `data/` — created by `Deploy.sh` on first install; not shipped in the package.
