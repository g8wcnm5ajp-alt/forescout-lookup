"""
forescout_client.py

Talks to the EM (FORESCOUT_EM_HOST) via the restricted SSH key set up for
this app -- never touches an appliance directly. The EM-side forced-
command wrapper (webapp-query/webapp-query.py in this repo, deployed at
/root/scripts/webapp-query/webapp-query.py on the EM) is the only thing
that key is allowed to run; every call here maps to one of its verbs
(lookup, debugsetappliance, tracelist, tracedefaults, traceset,
techsupportpreview, techsupportcollect, techsupportwindowappliance,
techsupportempreview, techsupportem, techsupportlogtail, techsupportlogclear,
policytree, lastchecked, matched, history, rawfields, arplist, appliances,
runshowerrors) and gets back one line of JSON.
"""
import json
import os
import re
import subprocess

EM_HOST = os.environ.get("FORESCOUT_EM_HOST")
if not EM_HOST:
    raise RuntimeError(
        "FORESCOUT_EM_HOST is not set. Deploy.sh sets this automatically; "
        "a standalone (start.sh-style) deployment must set it explicitly."
    )
SSH_KEY_PATH = os.environ.get("FORESCOUT_SSH_KEY", "/keys/webapp_query_rsa")

IP_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IP_RE = re.compile(rf"^{IP_OCTET}(?:\.{IP_OCTET}){{3}}$")


class ForescoutClientError(Exception):
    """Raised for anything the UI should show as a clean error message."""


def valid_ip(ip):
    return bool(IP_RE.match(ip or ""))


# A managed target (the EM or a specific appliance) may be addressed by
# IP or, on some deployments, by DNS hostname -- the EM's own reg table
# can store either (see _get_fstool_dns_servers/_resolve_target_host in
# webapp-query.py, added 2026-08-28 for exactly this). Confirmed live
# 2026-09-14: every target-taking verb here was rejecting a real,
# working hostname target outright at this shape-check layer, before
# the EM's own resolve_target ever got a chance to match it against the
# reg table's own (hostname-shaped) address values -- not a DNS
# problem, this app's own validation was just IP-only. valid_ip stays
# separate and unchanged for HOST ips (the thing actually being looked
# up), which are always IP-addressed in this app's domain.
# 2026-09-18, a customer estate: appliances registered by SHORT name
# ("appliance01", no dot) -- the "at least one label after a dot" shape
# rejected every one of them ("is not a valid target"). A hostname is one
# or more labels; the EM-side resolve_target still requires the value to
# be in the reg table, so the shape check is not the authorization.
HOSTNAME_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
TARGET_RE = re.compile(rf"^(?:{IP_RE.pattern[1:-1]}|{HOSTNAME_LABEL}(?:\.{HOSTNAME_LABEL})*)$")


def valid_target(target):
    return bool(TARGET_RE.match(target or ""))


def _run_verb(verb_command, timeout):
    if not os.path.isfile(SSH_KEY_PATH):
        raise ForescoutClientError(
            f"SSH key not found at {SSH_KEY_PATH} -- the container's key volume isn't mounted correctly."
        )
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY_PATH, f"root@{EM_HOST}", verb_command,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ForescoutClientError(f"Request to the EM timed out after {timeout}s.")
    except FileNotFoundError:
        raise ForescoutClientError("ssh is not available in this container.")

    if not p.stdout.strip():
        detail = p.stderr.strip() or f"exit code {p.returncode}"
        raise ForescoutClientError(f"No response from the EM ({detail}).")

    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise ForescoutClientError(f"Unexpected (non-JSON) response from the EM: {p.stdout[:300]}")

    if "error" in data:
        raise ForescoutClientError(data["error"] if not data.get("still_active") else _format_still_active(data))
    return data


def _format_still_active(data):
    parts = [f"{e['plugin']} ({e['seconds_remaining']}s remaining)" for e in data.get("still_active", [])]
    return "Debug still active on: " + ", ".join(parts) + ". Wait for it to finish before building a bundle."


def lookup(ip, timeout=360):
    # Was 45s: do_lookup queries every known appliance for its installed/
    # enabled plugins and databases, and confirmed live 2026-09-11 that two
    # appliances (two in the lab -- previously assumed dead, no longer
    # filtered out) each take ~11.5s just for the enabled-plugins check,
    # pushing a single lookup's total time to ~34s even after parallelizing
    # those per-target queries server-side (webapp-query.py's
    # _parallel_target_map) -- 90s is a safety margin above that measured
    # worst case, not a tuned exact value.
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"lookup {ip}", timeout=timeout)


# Shape only (safe plugin-name charset) -- which plugin names are real is
# a live, per-deployment fact only the EM's own wrapper can check (see
# get_installed_plugins there); this layer just blocks garbage before it
# ever reaches SSH.
DEBUGSET_ITEM_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}:(?:[0-9]|1[0-2]):\d{1,4}$")

PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")


def debug_set_appliance(target, spec, case_ref=None, timeout=45):
    """
    Appliance-addressed -- target is the EM or a specific managed
    appliance's IP (whichever box a plugin/level/duration row's target
    resolved to in a lookup's debug_targets), not a host's own IP. Which
    target IPs are actually real EM/appliances is checked EM-side
    (resolve_target); this layer only shape-validates.

    spec: comma-separated "<plugin>:<level>:<minutes>" triples, already
    built by the caller from the debug panel's checkbox/level/duration
    controls -- shape-validated here (defense in depth) before ever
    reaching SSH.

    case_ref (optional): only passed by the tech-support proceed flow
    (start_techsupport_run) -- when given, the EM-side wrapper tags this
    debug-enable command into TS_LOG_PATH (David's ask, 2026-08-26: see
    what commands are actually run once Proceed is hit). The standalone
    Debug panel and scheduled-debug jobs call this with no case_ref, so
    their commands stay out of that log -- uses _case_ref_token's same
    "-" -for-none convention as every other optional wire token here, so
    the EM-side verb pattern stays unambiguous.
    """
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    items = [i for i in (spec or "").split(",") if i]
    if not items or not all(DEBUGSET_ITEM_RE.match(i) for i in items):
        raise ForescoutClientError("Invalid debug configuration.")
    for i in items:
        minutes = int(i.split(":")[2])
        if not (1 <= minutes <= 1440):
            raise ForescoutClientError("Duration must be between 1 and 1440 minutes (24h).")
    return _run_verb(f"debugsetappliance {target} {spec} {_case_ref_token(case_ref)}", timeout=timeout)


# Advanced Trace -- David's ask, 2026-08-26: an "Enhance Trace" feature exposing
# /usr/local/forescout/etc/fstrace.properties per box (EM or appliance), with a captured-once default and
# a timed auto-revert. Shape mirrors DEBUGSET_ITEM_RE's own convention (name:on|off:level triples).
TRACE_CATEGORY_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,80}$")
TRACE_LEVELS = ("error", "warning", "normal", "detailed")
TRACE_ITEM_RE = re.compile(r"^[A-Za-z0-9_]{1,80}:(on|off):(error|warning|normal|detailed)$")


def trace_list(target, timeout=20):
    """Every trace category on target, live state + captured-once default alongside each."""
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    return _run_verb(f"tracelist {target}", timeout=timeout)


def trace_defaults(target, timeout=20):
    """Just the captured-once default snapshot for target -- used by the auto-revert timer."""
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    return _run_verb(f"tracedefaults {target}", timeout=timeout)


def trace_set(target, changes, timeout=20):
    """changes: {category: (enabled_bool, level_str), ...} -- shape-validated here (defense in depth)
    before ever reaching SSH; every category name is re-validated against the box's own live file
    EM-side regardless."""
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    if not changes:
        raise ForescoutClientError("No trace changes given.")
    parts = []
    for name, (enabled, level) in changes.items():
        if not TRACE_CATEGORY_NAME_RE.match(name):
            raise ForescoutClientError(f"'{name}' is not a valid trace category name.")
        level = (level or "").lower()
        if level not in TRACE_LEVELS:
            raise ForescoutClientError(f"'{level}' is not a valid trace level ({'/'.join(TRACE_LEVELS)}).")
        item = f"{name}:{'on' if enabled else 'off'}:{level}"
        if not TRACE_ITEM_RE.match(item):
            raise ForescoutClientError(f"'{item}' has an invalid shape.")
        parts.append(item)
    return _run_verb(f"traceset {target} {','.join(parts)}", timeout=timeout)


# Shape only, mirrors CASE_REF_RE in webapp-query.py -- an optional
# reference number/ticket a build should be filed under. "-" means none
# (sent as a literal command token, not left genuinely optional, so the
# EM-side verb patterns stay unambiguous); threaded into the bundle's
# fstool -comment and used to group its output file(s) under
# /tmp/case-<case_ref>/ on whichever box builds it.
CASE_REF_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _case_ref_token(case_ref):
    if not case_ref:
        return "-"
    if not CASE_REF_RE.match(case_ref):
        raise ForescoutClientError(
            "Case reference may only contain letters, numbers, '-' and '_' (max 40 chars)."
        )
    return case_ref


# fstool's own -company value, David's ask 2026-08-26 -- an editable
# override for what used to be a hardcoded company name. No spaces, same
# reason as CASE_REF_RE: this travels through webapp-query.py's
# space-separated dispatch tokens.
COMPANY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,60}$")


def _company_token(company):
    if not company:
        return "-"
    if not COMPANY_NAME_RE.match(company):
        raise ForescoutClientError(
            "Company name may only contain letters, numbers, '.', '-' and '_' (max 60 chars, no spaces)."
        )
    return company


LEVEL_RE = re.compile(r"^(?:[0-9]|1[0-2])$")


def _validated_ips(ips):
    if not ips or not all(valid_ip(ip) for ip in ips):
        raise ForescoutClientError("One or more of the given IPs is not a valid IPv4 address.")
    return ips


def _validated_level(level):
    if not LEVEL_RE.match(str(level)):
        raise ForescoutClientError("Debug level must be 0-12.")
    return level


def _validated_minutes(minutes):
    if not (isinstance(minutes, int) and 1 <= minutes <= 1440):
        raise ForescoutClientError("Duration must be between 1 and 1440 minutes (24h).")
    return minutes


def _selected_plugins_token(selected_plugins):
    """
    selected_plugins: None (no selection at all -- use the full auto-
    detected set; not exercised by the real UI, kept for API
    completeness) vs {} (David's ask, 2026-08-26: a deliberately EMPTY
    selection -- every plugin unchecked on purpose, e.g. a build that
    only attaches DB tables or collects a plain hostinfo-only bundle) vs
    {target: [plugin, ...]} restricting the build to only what's
    explicitly checked in the UI. These three cases are NOT the same and
    must map to distinct wire tokens -- "-" (None) vs "0" ({}) vs the
    real pairs -- since webapp-query.py's own selected_plugins filter
    behaves differently for "no restriction" (None) than for "restrict
    to nothing" ({}). Shape-validated here (which targets/plugins are
    real is re-checked EM-side against the actual detected set -- this
    layer only blocks garbage before it ever reaches SSH).
    """
    if selected_plugins is None:
        return "-"
    pairs = []
    for target, plugins in selected_plugins.items():
        if not valid_target(target):
            raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
        for plugin in plugins:
            if not PLUGIN_NAME_RE.match(plugin):
                raise ForescoutClientError(f"'{plugin}' is not a valid plugin name.")
            pairs.append(f"{target}:{plugin}")
    return ",".join(pairs) if pairs else "0"


DBTABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _selected_dbtables_token(selected_dbtables):
    """
    selected_dbtables: None/empty (no tables requested) or
    {target: [table, ...]} -- David's ask (2026-08-26, "Attach DBs"),
    attach specific tables via fstool's own --dbtable. Went through a
    same-day detour assuming David meant whole separate Postgres
    databases (pg_dump'd + --attach-file) -- his own correction: "the
    only ones I need are listed by running the fstool db diskspace,"
    which is itself a curated, size-ranked list of TABLE names within
    the one default database, the exact granularity --dbtable always
    addressed. Shape-validated here the same way as
    _selected_plugins_token; which tables genuinely appear in a given
    target's own `db diskspace` output is re-checked EM-side
    (get_databases), since that list is per-box.
    """
    if not selected_dbtables:
        return "-"
    pairs = []
    for target, databases in selected_dbtables.items():
        if not valid_target(target):
            raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
        for database in databases:
            if not DBTABLE_NAME_RE.match(database):
                raise ForescoutClientError(f"'{database}' is not a valid database name.")
            pairs.append(f"{target}:{database}")
    return ",".join(pairs) if pairs else "-"


def _send_token(send):
    """fstool's own --send flag ("Send support bundle directly to Forescout", David's ask, 2026-08-26) --
    "1"/"0", not the "-"-for-none convention the other optional tokens use, since this is a genuine
    boolean with no meaningful "unset" state (unchecked just means False)."""
    return "1" if send else "0"


def preview_techsupport(
    ips, level, minutes, selected_plugins=None, selected_dbtables=None, company=None, send=False, case_ref=None,
    timeout=45,
):
    """
    Read-only -- returns the exact command sequence collect_techsupport
    (plus the debug-enable the caller fires just before it) would run
    for these hosts/level/minutes/case_ref, without executing anything.
    David's ask: review the commands before proceeding. selected_plugins:
    see _selected_plugins_token. selected_dbtables: see
    _selected_dbtables_token. company: see _company_token -- David's ask
    2026-08-26, an editable override for the previously-hardcoded
    company name. send: see _send_token.
    """
    ips = _validated_ips(ips)
    level = _validated_level(level)
    minutes = _validated_minutes(minutes)
    plugins_token = _selected_plugins_token(selected_plugins)
    dbtables_token = _selected_dbtables_token(selected_dbtables)
    return _run_verb(
        f"techsupportpreview {','.join(ips)} {level} {minutes} {plugins_token} {dbtables_token} "
        f"{_company_token(company)} {_send_token(send)} {_case_ref_token(case_ref)}",
        timeout=timeout,
    )


def collect_techsupport(
    ips, minutes, selected_plugins=None, selected_dbtables=None, company=None, send=False, case_ref=None,
    timeout=480,
):
    """
    One or more host IPs at once -- webapp-query.py's do_techsupport_collect
    groups every relevant plugin across all of them by target box (EM or
    a specific appliance) and builds ONE combined bundle per target
    (fstool's own repeated -p, confirmed live it collects multiple
    plugins in a single invocation), with each contributing host's own
    hostinfo dump attached via --attach-file, and any selected tables
    via fstool's own --dbtable, rather than one bundle per plugin or per
    host.
    Assumes the caller (app.py) has already enabled debug on each
    relevant plugin and waited out `minutes` itself -- this call only
    collects and centralizes, it doesn't enable debug or wait.
    selected_plugins must match whatever the preceding debug-enable step
    actually used, so the collected bundle covers exactly what was
    enabled, no more (see _selected_plugins_token). selected_dbtables
    has no debug-enable step of its own, so it can differ freely from
    whatever the preview showed (see _selected_dbtables_token). company:
    see _company_token. send: see _send_token.
    """
    ips = _validated_ips(ips)
    minutes = _validated_minutes(minutes)
    plugins_token = _selected_plugins_token(selected_plugins)
    dbtables_token = _selected_dbtables_token(selected_dbtables)
    return _run_verb(
        f"techsupportcollect {','.join(ips)} {minutes} {plugins_token} {dbtables_token} "
        f"{_company_token(company)} {_send_token(send)} {_case_ref_token(case_ref)}",
        timeout=timeout,
    )


def build_techsupport_window_appliance(target, start_epoch, end_epoch, plugins, case_ref=None, timeout=480):
    """
    Appliance-addressed version of the historical-window bundle -- used
    when a requested debug-capture window is entirely in the past (debug
    can't be backdated, so this pulls from already-rotated logs instead
    via fstool's own -t utc:X -t utc:Y range, confirmed live).
    """
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    if not (isinstance(start_epoch, int) and isinstance(end_epoch, int) and 0 < start_epoch < end_epoch):
        raise ForescoutClientError("Invalid time window.")
    if not plugins or not all(PLUGIN_NAME_RE.match(p) for p in plugins):
        raise ForescoutClientError("Invalid plugin selection.")
    return _run_verb(
        f"techsupportwindowappliance {target} {start_epoch}:{end_epoch} {','.join(plugins)} "
        f"{_case_ref_token(case_ref)}",
        timeout=timeout,
    )


def preview_techsupport_em(duration, company=None, send=False, case_ref=None, timeout=45):
    """
    Read-only -- the exact command sequence build_techsupport_em would
    run for this duration/case_ref, without executing anything. Added
    2026-08-25 after David caught the EM panel's preview (previously
    hand-written text built directly in app.py) had drifted out of sync
    with what actually runs -- wrong -comment value, missing mkdir -p,
    one combined mv line shown instead of the real two separate ones.
    Same fix already applied to the host path back in Round 18; this
    closes the same gap for the EM path by routing through a real verb
    instead of a second, independently-hand-maintained copy of the
    command text. company: see _company_token. send: see _send_token.
    """
    if not DURATION_RE.match(duration or ""):
        raise ForescoutClientError(f"'{duration}' is not a valid duration (expected e.g. 30m, 2h).")
    return _run_verb(
        f"techsupportempreview {duration} {_company_token(company)} {_send_token(send)} "
        f"{_case_ref_token(case_ref)}",
        timeout=timeout,
    )


def build_techsupport_em(duration, company=None, send=False, case_ref=None, timeout=480):
    """
    A general, EM-wide tech-support bundle -- there's no host to derive a
    relevant-plugin list from, so this collects fstool's own default
    category set rather than guessing. Distinct from run_show_errors,
    which deliberately deletes its snapshot after review; this one is a
    real, kept bundle, same as build_techsupport/_window_appliance.
    company: see _company_token. send: see _send_token.
    """
    if not DURATION_RE.match(duration or ""):
        raise ForescoutClientError(f"'{duration}' is not a valid duration (expected e.g. 30m, 2h).")
    return _run_verb(
        f"techsupportem {duration} {_company_token(company)} {_send_token(send)} {_case_ref_token(case_ref)}",
        timeout=timeout,
    )


def raw_fields(ip, timeout=45):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"rawfields {ip}", timeout=timeout)


def hostinfo(ip, timeout=60):
    """Raw `fstool hostinfo` text for the Live Analyze "Host info" download."""
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"hostinfo {ip}", timeout=timeout)


def arp_list(ip, timeout=20):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"arplist {ip}", timeout=timeout)


def policy_tree(timeout=30):
    return _run_verb("policytree", timeout=timeout)


def list_appliances(timeout=30):
    return _run_verb("appliances", timeout=timeout)


def tail_techsupport_log(timeout=15):
    """
    The tail of TS_LOG_PATH on the EM -- David's ask, 2026-08-26: a
    popup window polls this while a tech-support build is running, so
    the real commands (debug-enable, fstool hostinfo/tech-support/
    --dbtable, mkdir/scp/rm/split) show up as they actually execute,
    tagged "[case_ref]", not just after the whole proceed action
    finishes. One shared log for the whole EM, so this is a plain,
    argument-free poll.
    """
    return _run_verb("techsupportlogtail", timeout=timeout)


def clear_techsupport_log(timeout=15):
    """Truncates TS_LOG_PATH on the EM -- David's ask, 2026-08-26: a Clear button (with a y/n confirm
    client-side) for each log-history section; this is the one that lives on the EM, not in this app's own
    /data, so it needs its own verb round-trip rather than a plain local file truncate."""
    return _run_verb("techsupportlogclear", timeout=timeout)


def tail_lookup_debug_log(timeout=15):
    """
    The tail of LOOKUP_LOG_PATH on the EM -- David's ask, 2026-09-11: a
    remote-site deployment can't hand over a live SSH session when a
    lookup silently comes back empty, so this script's own diagnostic
    trace of what happened (per-target timing, resolved mode/appliance,
    which plugin candidates were found or skipped and why, any unhandled
    exception) needs to be retrievable through the app itself.
    """
    return _run_verb("lookuplogtail", timeout=timeout)


def clear_lookup_debug_log(timeout=15):
    """Truncates LOOKUP_LOG_PATH on the EM -- same reasoning as clear_techsupport_log."""
    return _run_verb("lookuplogclear", timeout=timeout)


# Shape only -- which CIDR is actually sensible is David's call, made in
# the GUI; this just blocks garbage before it reaches SSH, same pattern
# as every other validated-at-this-layer value above.
CIDR_RE = re.compile(rf"^{IP_OCTET}(?:\.{IP_OCTET}){{3}}/(?:[0-9]|[12][0-9]|3[0-2])$")


def valid_cidr(cidr):
    return bool(CIDR_RE.match(cidr or ""))


def get_admin_cidr(timeout=15):
    return _run_verb("getadmincidr", timeout=timeout)


def set_admin_cidr(cidr, timeout=20):
    if not valid_cidr(cidr):
        raise ForescoutClientError(f"'{cidr}' is not a valid CIDR (expected e.g. 192.168.1.0/24 or 0.0.0.0/0).")
    return _run_verb(f"setadmincidr {cidr}", timeout=timeout)


# Mirrors webapp-query.py's own BUNDLE_PATH_RE -- checked here too before
# ever spending an SSH round-trip on an obviously-bogus path, but the EM
# side re-validates independently regardless (never trust the browser).
BUNDLE_PATH_RE = re.compile(r"^/shared/shared/case/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$")


def download_techsupport_bundle(path, timeout=600):
    """
    Streams a previously-built bundle (or its -commands.txt / split
    .part-xx sibling) off the EM -- David's ask, 2026-08-27: download the
    built tech-support bundles via the web app's own HTTP session rather
    than an admin scp-ing them off the EM by hand.

    Returns the live subprocess.Popen so app.py's route can stream
    proc.stdout straight into the browser response in chunks, without
    ever holding a multi-hundred-MB (or multi-GB, pre-split) bundle
    fully in this process's memory. Caller is responsible for reading
    proc.stdout to EOF and calling proc.wait() (or just letting the
    `with` in the Flask route's generator close it) -- this function
    only handles the handshake: reading the first line to tell a real
    "BEGIN-BINARY" stream apart from a JSON error response (missing
    file, path rejected, etc.), matching what do_techsupport_download
    on the EM side actually writes.
    """
    if not BUNDLE_PATH_RE.match(path or ""):
        raise ForescoutClientError(f"'{path}' is not a recognized tech-support bundle path.")
    if not os.path.isfile(SSH_KEY_PATH):
        raise ForescoutClientError(
            f"SSH key not found at {SSH_KEY_PATH} -- the container's key volume isn't mounted correctly."
        )
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY_PATH, f"root@{EM_HOST}", f"techsupportdownload {path}",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise ForescoutClientError("ssh is not available in this container.")

    marker = proc.stdout.readline()
    if marker.strip() != b"BEGIN-BINARY":
        rest = proc.stdout.read()
        proc.wait()
        raw = marker + rest
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ForescoutClientError(f"Unexpected response from the EM: {raw[:300]!r}")
        raise ForescoutClientError(data.get("error", "Unknown error downloading the bundle."))
    return proc


def delete_techsupport_bundle(path, timeout=30):
    """Deletes a single bundle/chunk/-commands.txt file off the EM's shared case storage -- David's ask,
    2026-08-27: a Clean up button right next to each Download link. Same path whitelist as
    download_techsupport_bundle -- checked here before ever spending an SSH round-trip, and the EM side
    re-validates independently regardless."""
    if not BUNDLE_PATH_RE.match(path or ""):
        raise ForescoutClientError(f"'{path}' is not a recognized tech-support bundle path.")
    return _run_verb(f"techsupportcleanup {path}", timeout=timeout)


DURATION_RE = re.compile(r"^\d{1,4}[mh]$")


def run_show_errors(target, duration, timeout=1200):
    """
    Fires `fstool tech-support -t <duration> --review --show-errors` on
    target -- confirmed live this is a real, several-minutes-long,
    unscoped snapshot, hence the generous timeout (the caller runs this
    in a background thread and polls, never inline in a request).
    """
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    if not DURATION_RE.match(duration or ""):
        raise ForescoutClientError(f"'{duration}' is not a valid duration (expected e.g. 30m, 2h).")
    return _run_verb(f"runshowerrors {target} {duration}", timeout=timeout)


# Live Analyze tab (High Admission Root-Cause Tracing) -- see
# webapp-query.py's own pluginlist/analyzeadm/pluginlogszip docstrings
# for what each actually runs on the EM side.
ANALYZE_WINDOW_RE = re.compile(r"^\d{1,5}[smhd]$")


def list_plugins(target, timeout=20):
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    return _run_verb(f"pluginlist {target}", timeout=timeout)


def analyze_admission(
    target, bundle_path=None, window="1h", switch_filter=None, top_n=10, spike_n=5, stale_days=7, timeout=1250,
):
    """
    Runs high-admission-trace.sh's `analyze` mode. Give bundle_path to
    analyze a bundle already centralized on the EM (same path shape as
    download_techsupport_bundle/delete_techsupport_bundle) OR one
    uploaded through the Upload & Review Bundle tab (UPLOAD_PATH_RE --
    do_analyzeadm's own EM-side check already accepts either; this
    mirrors it client-side too, confirmed live this was the actual gap:
    a real uploaded bundle's path was rejected instantly, before the
    request ever reached the EM, because this check only knew about the
    centralized-bundle shape) instead of the live target -- target is
    still required either way (informational only when bundle_path is
    given, naming where the bundle came from). A generous default
    timeout: a real bundle analysis measured ~110s against an 867MB real
    bundle; this leaves headroom for a much bigger one. The caller runs
    this in a background thread and polls, same pattern as
    run_show_errors/tech-support builds.
    """
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    if bundle_path is not None and not (
        BUNDLE_PATH_RE.match(bundle_path)
        or UPLOAD_PATH_RE.match(bundle_path)
        or MANUAL_STAGING_PATH_RE.match(bundle_path)
    ):
        raise ForescoutClientError(f"'{bundle_path}' is not a recognized tech-support bundle path.")
    if not ANALYZE_WINDOW_RE.match(window or ""):
        raise ForescoutClientError(f"'{window}' is not a valid window (expected e.g. 30m, 2h, 1d).")
    switches = [s.strip() for s in (switch_filter or "").split(",") if s.strip()]
    if switches and not all(valid_ip(s) for s in switches):
        raise ForescoutClientError("Switch filter must be a comma-separated list of IPv4 addresses.")
    for name, value in (("top_n", top_n), ("spike_n", spike_n), ("stale_days", stale_days)):
        if not (isinstance(value, int) and 0 <= value <= 9999):
            raise ForescoutClientError(f"'{name}' must be a non-negative number.")
    return _run_verb(
        f"analyzeadm {target} {bundle_path or '-'} {window} {','.join(switches) or '-'} "
        f"{top_n} {spike_n} {stale_days}",
        timeout=timeout,
    )


def download_plugin_logs_zip(target, plugins, start_epoch, end_epoch, timeout=300):
    """
    Streams a tar.gz of the named plugin(s)' raw log files, modified in
    [start_epoch, end_epoch], off `target` -- the Live Analyze tab's
    "download the raw logs for the debug window just captured" button.
    Same raw-bytes/BEGIN-BINARY streaming handshake and Popen-return
    convention as download_techsupport_bundle -- see its own docstring.
    """
    if not valid_target(target):
        raise ForescoutClientError(f"'{target}' is not a valid target (expected an IP or a hostname).")
    if not plugins or not all(PLUGIN_NAME_RE.match(p) for p in plugins):
        raise ForescoutClientError("Invalid plugin selection.")
    if not (isinstance(start_epoch, int) and isinstance(end_epoch, int) and 0 < start_epoch < end_epoch):
        raise ForescoutClientError("Invalid time window.")
    if not os.path.isfile(SSH_KEY_PATH):
        raise ForescoutClientError(
            f"SSH key not found at {SSH_KEY_PATH} -- the container's key volume isn't mounted correctly."
        )
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY_PATH, f"root@{EM_HOST}",
        f"pluginlogszip {target} {','.join(plugins)} {start_epoch}:{end_epoch}",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise ForescoutClientError("ssh is not available in this container.")

    marker = proc.stdout.readline()
    if marker.strip() != b"BEGIN-BINARY":
        rest = proc.stdout.read()
        proc.wait()
        raw = marker + rest
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ForescoutClientError(f"Unexpected response from the EM: {raw[:300]!r}")
        raise ForescoutClientError(data.get("error", "Unknown error building the plugin logs zip."))
    return proc


# Upload & Review Bundle tab -- a tech-support bundle this app never
# built itself (e.g. one a customer sent in). Lands under its own fixed
# uploads directory on the EM, entirely separate from the real
# centralized-bundle tree BUNDLE_PATH_RE addresses.
UPLOAD_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,120}\.(?:tgz|tar\.gz)$")
UPLOAD_PATH_RE = re.compile(r"^/tmp/hat-uploads/[A-Za-z0-9_.\-]{1,120}\.(?:tgz|tar\.gz)$")

# A third accepted analyze_admission bundle source: real customer
# bundles staged by hand directly on the EM (this site's own established
# workflow), same reasoning/whitelisting approach as UPLOAD_PATH_RE --
# see webapp-query.py's own MANUAL_STAGING_DIR/_PATH_RE, which this
# mirrors on the client side.
MANUAL_STAGING_PATH_RE = re.compile(r"^/root/scripts/staged-bundles/[A-Za-z0-9_.\-]{1,120}\.(?:tgz|tar\.gz)$")

# Sanity cap, not confirmed with David as the right number -- same
# reasoning as MAX_LOOKUP_IPS in app.py. Real bundles seen so far (up to
# 867MB) are comfortably under this.
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024


def upload_bundle(filename, stream, timeout=900):
    """
    Streams an uploaded bundle (`stream`: a binary file-like object --
    Flask's own spooled upload) to the EM via `bundleupload <filename>`
    and returns {"path": ..., "size": ...} -- the EM-side path, ready to
    hand straight to analyze_admission(bundle_path=...) or
    correlate_bundles(). Copied through in 1MB pieces rather than read
    whole: the Correlate feature means several 800MB bundles uploaded
    back to back, and holding each one in this container's RAM is what
    the old f.read() version did. Unlike every other verb call here, this
    can't go through _run_verb (that helper runs in text mode; a bundle's
    bytes are binary), so it builds its own subprocess call the same way
    download_plugin_logs_zip/download_techsupport_bundle do for the
    opposite (EM-to-browser) direction.
    """
    if not UPLOAD_FILENAME_RE.match(filename or ""):
        raise ForescoutClientError("Bundle filename must end in .tgz or .tar.gz (letters/digits/./-/_ only).")
    if not os.path.isfile(SSH_KEY_PATH):
        raise ForescoutClientError(
            f"SSH key not found at {SSH_KEY_PATH} -- the container's key volume isn't mounted correctly."
        )
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY_PATH, f"root@{EM_HOST}", f"bundleupload {filename}",
    ]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise ForescoutClientError("ssh is not available in this container.")
    sent = 0
    try:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            sent += len(block)
            if sent > MAX_UPLOAD_BYTES:
                proc.kill()
                proc.communicate()
                raise ForescoutClientError(f"Bundle is over the {MAX_UPLOAD_BYTES // (1024 * 1024)}MB upload limit.")
            proc.stdin.write(block)
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass  # the EM side hung up early -- its own error (stdout/stderr below) says why
    try:
        stdout = proc.stdout.read()
        stderr = proc.stderr.read()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise ForescoutClientError(f"Upload to the EM timed out after {timeout}s.")
    if not stdout.strip():
        detail = stderr.decode(errors="replace").strip() or f"exit code {proc.returncode}"
        raise ForescoutClientError(f"No response from the EM ({detail}).")
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError:
        raise ForescoutClientError(f"Unexpected (non-JSON) response from the EM: {stdout[:300]}")
    if "error" in result:
        raise ForescoutClientError(result["error"])
    return result


def delete_uploaded_bundle(path, timeout=30):
    if not UPLOAD_PATH_RE.match(path or ""):
        raise ForescoutClientError(f"'{path}' is not a recognized uploaded bundle path.")
    return _run_verb(f"bundleuploadcleanup {path}", timeout=timeout)


def list_uploaded_bundles(timeout=20):
    return _run_verb("bundleuploadlist", timeout=timeout)


MAX_CORRELATE_BUNDLES = 8
ROAM_KEY_RE = re.compile(r"^(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}|\d{1,3}(?:\.\d{1,3}){3})$")


def bundle_roaming(path, key, timeout=1900):
    """Where one device (MAC or IP) was seen connected, from a bundle's own logs -- see webapp-query.py's
    do_bundleroam. Same three accepted path shapes as analyze_admission."""
    if not (BUNDLE_PATH_RE.match(path or "") or UPLOAD_PATH_RE.match(path or "") or MANUAL_STAGING_PATH_RE.match(path or "")):
        raise ForescoutClientError(f"'{path}' is not a recognized tech-support bundle path.")
    if not ROAM_KEY_RE.match(key or ""):
        raise ForescoutClientError("Enter a MAC address (aa:bb:cc:dd:ee:ff or aabbccddeeff) or an IPv4 address.")
    return _run_verb(f"bundleroam {path} {key}", timeout=timeout)


def correlate_bundles(paths, gap=150, context=120, top_n=10, timeout=3700):
    """
    Runs bundle-correlate.py on the EM over 1-8 bundles together (an EM
    bundle plus its appliance bundle(s)) -- see webapp-query.py's
    do_bundlecorrelate. Same three accepted path shapes as
    analyze_admission. Returns {"bundles": [identity...], "output": text}.
    The caller runs this in a background thread and polls.
    """
    paths = list(paths or [])
    if not 1 <= len(paths) <= MAX_CORRELATE_BUNDLES or len(set(paths)) != len(paths):
        raise ForescoutClientError(f"Select 1 to {MAX_CORRELATE_BUNDLES} different bundles.")
    for path in paths:
        if not (BUNDLE_PATH_RE.match(path) or UPLOAD_PATH_RE.match(path) or MANUAL_STAGING_PATH_RE.match(path)):
            raise ForescoutClientError(f"'{path}' is not a recognized tech-support bundle path.")
    for name, value, top in (("gap", gap, 99999), ("context", context, 99999), ("top_n", top_n, 999)):
        if not (isinstance(value, int) and 1 <= value <= top):
            raise ForescoutClientError(f"'{name}' must be a positive number.")
    return _run_verb(f"bundlecorrelate {','.join(paths)} {gap} {context} {top_n}", timeout=timeout)


def last_checked(ip, timeout=20):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"lastchecked {ip}", timeout=timeout)


WINDOW_RE = re.compile(r"^\d{1,4}[hdw]$")


def matched_rules(ip, window, timeout=30):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    if not WINDOW_RE.match(window or ""):
        raise ForescoutClientError(f"'{window}' is not a valid window (expected e.g. 24h, 3d, 2w).")
    return _run_verb(f"matched {ip} {window}", timeout=timeout)


ROAMING_WINDOW_RE = re.compile(r"^(?:[1-9]|1\d|2[0-8])d$")


def roaming(ip, window, timeout=500):
    """Switches/ports and wireless APs the host was connected to inside the window (1d-28d), with
    counts -- see webapp-query.py's do_roaming (replays the managing appliance's source_log)."""
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    if not ROAMING_WINDOW_RE.match(window or ""):
        raise ForescoutClientError(f"'{window}' is not a valid roaming window (expected 1d to 28d).")
    return _run_verb(f"roaming {ip} {window}", timeout=timeout)


def policy_history(ip, window, timeout=30):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    if not WINDOW_RE.match(window or ""):
        raise ForescoutClientError(f"'{window}' is not a valid window (expected e.g. 24h, 3d, 2w).")
    return _run_verb(f"history {ip} {window}", timeout=timeout)
