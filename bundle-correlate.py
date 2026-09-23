#!/usr/bin/env python3
"""
bundle-correlate.py -- offline, cross-bundle analysis of Forescout
tech-support bundles (Upload & Review Bundle tab, "Correlate").

Give it one or more bundles (.tgz/.tar.gz, or an already-unpacked bundle
directory). Typical use is an EM bundle plus one or more appliance
bundles from the same incident: it lines their clocks up, builds an
EM <-> appliance connectivity timeline from both sides' Trace_cu logs,
then sweeps every log / stats / database-info file for performance
problems and system errors.

Nothing is ever unpacked to disk: each archive is read ONCE as a stream
(tarfile "r|gz") and every member is parsed as it goes past. A real
bundle unpacks to 4-12GB; two of them would not fit in this EM's /tmp,
and a full `tar -xzf` has already been seen silently dropping files on a
box under memory pressure (see high-admission-trace.sh's retry logic).

Runs on the EM only (python3 stdlib, 3.9-compatible), installed next to
webapp-query.py by Deploy.sh -- same arrangement as
high-admission-trace.sh.

Formats relied on (all checked against real bundles, 2026-09-17):
  info/snapshot.properties     type= nodeid= version= start= end= timezone=
  log/Trace_cu_*.txt           Date|Now millis|Uptime seconds|Version|SP|
                               Application(em|app)|Mem total|Mem free|
                               Mem occupied|Category|Level|Message|Thread
                               -- column 2 (epoch ms) is the alignment key
  stats/today.log              p <epoch> <component> <pid> <metric> <value>
  fstool/perl logs             <name>:<pid>:<epoch>.<frac>:<human time>: msg
  command outputs              "Start: <local time>, (utc: <epoch>)"
"""

import argparse
import gzip
import io
import json
import os
import re
import sys
import tarfile
import time
from collections import Counter, defaultdict

VERSION = "1.2.0"

FS = "files/usr/local/forescout/"

# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def utc(ts):
    """Epoch seconds -> 'YYYY-MM-DD HH:MM:SS' UTC."""
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


def utc_hm(ts):
    return time.strftime("%m-%d %H:%M:%S", time.gmtime(ts)) if ts is not None else "-"


def dur(seconds):
    seconds = int(round(seconds))
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    if seconds < 60:
        return f"{sign}{seconds}s"
    if seconds < 3600:
        return f"{sign}{seconds // 60}m{seconds % 60:02d}s"
    if seconds < 86400:
        return f"{sign}{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{sign}{seconds // 86400}d{(seconds % 86400) // 3600:02d}h"


def median(values):
    s = sorted(values)
    if not s:
        return None
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2.0


_NORM = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"), "<mac>"),
    (re.compile(r"@[0-9a-f]{5,}\b"), "@<x>"),
    (re.compile(r"\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{12}\b"), "<mac>"),
    (re.compile(r"\d{4,}"), "<n>"),
]


def normalize(msg, width=150):
    """Collapse the variable parts of a message so repeats group together."""
    msg = msg.strip()[:400]
    for rx, rep in _NORM:
        msg = rx.sub(rep, msg)
    return msg[:width]


def rel_member(name):
    """Strip the bundle's own top-level directory off a tar member name."""
    name = name.lstrip("./")
    head, sep, tail = name.partition("/")
    return tail if sep else ""


_ROT = [
    (re.compile(r"\.\d{9,10}\.\d+\.log$"), ".log"),    # sw.1789478946.1716.log
    (re.compile(r"\.log\.\d{9,10}$"), ".log"),         # purger.log.1765801742
    (re.compile(r"-\d{8}$"), ""),                      # messages-20260730
    (re.compile(r"\.\d+$"), ""),                       # foo.log.1
]


def family(rel):
    """log/plugin/sw/sw.1789478946.1716.log -> log/plugin/sw/sw.log"""
    rel = rel[len(FS):] if rel.startswith(FS) else rel
    for rx, rep in _ROT:
        new = rx.sub(rep, rel)
        if new != rel:
            return new
    return rel


# ----------------------------------------------------------------------
# Trace_cu
# ----------------------------------------------------------------------

RX_MONITOR = re.compile(r"Adding monitor (\S+?), port:\d+, id: (\d+)")
RX_CC2 = re.compile(r"Loaded CC2: address =(\S+?), port=\d+, node id=(\d+)")
RX_SESSMGR = re.compile(r"Session manager for \S*?@([^:\s]+):(\d+).*?connType=(\w+)")
RX_NBSESSION = re.compile(r"FSNonBlockingMessageSession session with ([0-9a-fA-F.:]+?):(\d+)")
RX_LOGINFAIL_NODE = re.compile(r"onLoginFailure: nodeID = (\d+)")
RX_WATCHDOG = re.compile(r"LoginWatchdog: Checking (\d+), connected=(true|false)")
RX_FINLOGIN = re.compile(r"finished login to (\S+) after (\d+) seconds")
RX_CAPACITY = re.compile(r"Missing or non positive capacity: \S+ for node id (\d+)")
RX_EMIPS = re.compile(r"Received emIps message: FSEMIPMessage\{emIP=\[([^\]]*)\], em2IP=\[([^\]]*)\]")
RX_LE_ONLINE = re.compile(r"fieldName=online, value=(true|false),")
RX_LE_AGENT = re.compile(r"agentID=([A-Za-z0-9_]+)@")
RX_LE_KEY = re.compile(r" key=([^,]+), ")
RX_LE_CHANGED = re.compile(r"changedFields=\{(.*?)\}, listChangeInfo")
RX_LE_MAC = re.compile(r"fieldName=mac, value=([0-9a-f]{12})")
RX_APP_LOGIN = re.compile(r"Logging login success of (\S+?)@([0-9a-fA-F.:]+)")
RX_APP_CLOSE = re.compile(r"Closing connection: Appliance: (\d+), socket=Socket\[addr=/?([^,\]]+),port=(\d+).*?elapsed=(\d+)")
RX_APP_SENDERR = re.compile(r"Error in send/recieve message: con=Appliance: (\d+)")
RX_IAC_CLOSED = re.compile(r"Connection to node (\d+) is closed")
RX_EMINFO = re.compile(r"HTEMInfo\{emNodeID=(\d+), emName='([^']*)'")
RX_EXC = re.compile(r"^(?:Caused by: )?((?:[a-zA-Z_][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error))\b:?\s*(.*)")


class TraceAgg:
    def __init__(self):
        self.files = []            # (first_t, first_up, last_t, last_up, rel)
        self.lines = 0
        self.tmin = None
        self.tmax = None
        self.app_votes = Counter()
        self.versions = Counter()
        self.cat_level = Counter()
        self.issues = {}           # sig -> dict
        self.issue_minutes = defaultdict(Counter)   # sig -> {minute: n}
        self.err_minutes = Counter()
        self.active_minutes = set()
        self.heartbeats = []
        self.emips = []
        self.em_ips = set()
        self.min_free = None       # (pct_free, t, free, total)
        self.neg_uptime = 0
        self.clock_events = []     # (t, kind, detail)
        # EM side
        self.monitors = {}         # addr -> nodeid
        self.peer_conntype = {}    # addr -> connType
        self.peer_events = []      # (t, addr_or_None, nodeid_or_None, kind, detail)
        self.learn_events = 0
        self.learn_t0 = None
        self.learn_t1 = None
        self.online_by_agent = {}  # agent plugin -> {"true","false","changed","hosts": Counter}
        self.fwd_loop = Counter()
        self.fwd_loop_macs = Counter()
        self._sess_seen = set()
        self._sess_last = {}       # addr -> last time any healthy line was seen on its session thread
        # appliance side
        self.app_logins = []       # (t, user, ip)  -- "Logging login success of admin@<EM ip>"
        self.app_closes = []       # [t, peer nodeid, peer ip, elapsed_ms, reason]
        self.iac_reopen = defaultdict(list)   # peer nodeid -> [t]
        self.em_identity = Counter()          # (em nodeid, em name) the appliance says it belongs to
        # appliance side: errors on the session thread to a peer ip
        self.session_issues = defaultdict(Counter)   # peer ip -> {sig: n}

    def feed(self, rel, fobj):
        first = last = None
        prev_t = prev_up = None
        last_issue = None
        last_fail = None
        last_close = None
        for raw in fobj:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            parts = line.split("|", 12)
            if len(parts) < 12 or len(parts[1]) != 13 or not parts[1].isdigit():
                # continuation line (stack trace etc.) -- first exception
                # class after an Error/Warning is that event's reason
                m = RX_EXC.match(line.strip()) if (last_issue or last_fail or last_close) else None
                if m and "FSTrace dummy exception" in line:
                    m = None
                if m:
                    reason = (m.group(1).rsplit(".", 1)[-1] + (": " + normalize(m.group(2), 60) if m.group(2) else ""))
                    if last_issue is not None and not last_issue.get("_exc_done"):
                        last_issue["exc"][reason] += 1
                        last_issue["_exc_done"] = True
                    if last_fail is not None and last_fail[4] is None:
                        last_fail[4] = reason
                        last_fail = None
                    if last_close is not None and last_close[4] is None:
                        last_close[4] = reason
                        last_close = None
                continue

            t_ms = int(parts[1])
            t = t_ms / 1000.0
            try:
                up = int(parts[2])
            except ValueError:
                up = None
            self.lines += 1
            if self.tmin is None or t < self.tmin:
                self.tmin = t
            if self.tmax is None or t > self.tmax:
                self.tmax = t
            minute = int(t // 60)
            self.active_minutes.add(minute)
            if first is None:
                first = (t, up)
                self.app_votes[parts[5]] += 1
                self.versions[parts[3]] += 1
            last = (t, up)

            if up is not None:
                if up < 0:
                    self.neg_uptime += 1
                if prev_up is not None:
                    self._clock_check(prev_t, prev_up, t, up)
                prev_t, prev_up = t, up

            try:
                total, free = int(parts[6]), int(parts[7])
                if total > 0:
                    pct = 100.0 * free / total
                    if self.min_free is None or pct < self.min_free[0]:
                        self.min_free = (pct, t, free, total)
            except ValueError:
                pass

            cat, level, msg = parts[9], parts[10], parts[11]
            thread = parts[12] if len(parts) > 12 else ""
            self.cat_level[(cat, level)] += 1
            last_issue = None

            if level in ("Error", "Warning", "Fatal", "Critical"):
                sig = f"{cat}|{level}|{normalize(msg)}"
                rec = self.issues.get(sig)
                if rec is None:
                    rec = self.issues[sig] = {
                        "count": 0, "first": t, "last": t, "sample": msg.strip()[:300], "exc": Counter(),
                    }
                rec["count"] += 1
                rec["last"] = max(rec["last"], t)
                rec["first"] = min(rec["first"], t)
                rec["_exc_done"] = False
                last_issue = rec
                self.issue_minutes[sig][minute] += 1
                if level != "Warning":
                    self.err_minutes[minute] += 1
                ms = RX_NBSESSION.search(thread)
                if ms:
                    self.session_issues[ms.group(1)][sig] += 1

            # ---- who asserts a host's `online` state (needs np_processor at Detailed; on an EM
            # one real case showed pxGrid re-asserting online=true ~200x/min)
            if cat == "np_processor" and msg.startswith("In newInfo: got "):
                self.learn_events += 1
                if self.learn_t0 is None or t < self.learn_t0:
                    self.learn_t0 = t
                if self.learn_t1 is None or t > self.learn_t1:
                    self.learn_t1 = t
                mo = RX_LE_ONLINE.search(msg)
                if mo:
                    ma = RX_LE_AGENT.search(msg)
                    agent = ma.group(1) if ma else "(no agent)"
                    rec = self.online_by_agent.get(agent)
                    if rec is None:
                        rec = self.online_by_agent[agent] = {"true": 0, "false": 0, "changed": 0, "hosts": Counter()}
                    rec[mo.group(1)] += 1
                    mc = RX_LE_CHANGED.search(msg)
                    if mc and "online=" in mc.group(1):
                        rec["changed"] += 1
                    mk = RX_LE_KEY.search(msg)
                    if mk and mo.group(1) == "true" and (len(rec["hosts"]) < 50000 or mk.group(1) in rec["hosts"]):
                        rec["hosts"][mk.group(1)] += 1
                continue
            # ---- learn events ping-ponging between appliances until the hop limit
            if cat == "id_change" and msg.startswith("FSLearnEventCarrierMessage"):
                if "reached forwarding limit" in msg:
                    self.fwd_loop["reached forwarding limit"] += 1
                elif "forwared back to resolver" in msg:
                    self.fwd_loop["forwarded back to resolver"] += 1
                elif "has no existing endpoints" in msg:
                    self.fwd_loop["has no existing endpoints"] += 1
                    mm = RX_LE_MAC.search(msg)
                    if mm:
                        self.fwd_loop_macs[mm.group(1)] += 1
                continue

            # ---- appliance-side liveness markers
            if cat == "application" and msg.startswith("HeartBeat Sent Out"):
                self.heartbeats.append(t)
                continue
            if cat == "appliance_sync":
                m = RX_EMIPS.search(msg)
                if m:
                    self.emips.append(t)
                    for grp in (m.group(1), m.group(2)):
                        for ip in grp.split(","):
                            if ip.strip():
                                self.em_ips.add(ip.strip())
                    continue

            if cat == "login" and msg.startswith("Logging login success"):
                m = RX_APP_LOGIN.search(msg)
                if m:
                    self.app_logins.append((t, m.group(1), m.group(2)))
                continue
            if cat == "iac":
                m = RX_IAC_CLOSED.search(msg)
                if m:
                    self.iac_reopen[m.group(1)].append(t)
                    continue
            if cat == "em_info":
                m = RX_EMINFO.search(msg)
                if m:
                    self.em_identity[(m.group(1), m.group(2))] += 1
                continue
            if cat == "session_manager" and "Appliance: " in msg:
                m = RX_APP_SENDERR.search(msg)
                if m:
                    # logged just before "Closing connection" and carries the real exception
                    last_close = [t, m.group(1), None, None, None]
                    self._pending_close = last_close
                    continue
                m = RX_APP_CLOSE.search(msg)
                if m:
                    pend = getattr(self, "_pending_close", None)
                    reason = pend[4] if pend and pend[1] == m.group(1) and t - pend[0] < 2 else None
                    self.app_closes.append([t, m.group(1), m.group(2), int(m.group(4)), reason])
                    self._pending_close = None
                    continue

            # ---- EM-side peer session markers
            sm = RX_SESSMGR.search(thread)
            addr = sm.group(1) if sm else None
            if sm:
                self.peer_conntype[addr] = sm.group(3)
                if level not in ("Error", "Warning") and cat not in ("ssl", "session_manager", "rmi", "license"):
                    # healthy traffic on this peer's session thread: one marker per peer per
                    # minute (order-independent -- files arrive out of time order); session
                    # (re)starts are derived from the sorted event list in em_peer_outages
                    if (addr, minute) not in self._sess_seen:
                        self._sess_seen.add((addr, minute))
                        self.peer_events.append([t, addr, None, "sess_up", None])
                    if cat == "login" and msg.startswith("Logging out"):
                        self.peer_events.append([t, addr, None, "logout", None])
            if cat == "ccu":
                m = RX_MONITOR.search(msg)
                if m:
                    self.monitors[m.group(1)] = m.group(2)
                    continue
                m = RX_WATCHDOG.search(msg)
                if m:
                    kind = "wd_up" if m.group(2) == "true" else "wd_down"
                    self.peer_events.append([t, None, m.group(1), kind, None])
                    continue
            elif cat == "register":
                m = RX_CC2.search(msg)
                if m:
                    self.monitors[m.group(1)] = m.group(2)
                    self.peer_conntype.setdefault(m.group(1), "EM2_EM")
                    continue
                m = RX_FINLOGIN.search(msg)
                if m:
                    self.peer_events.append([t, m.group(1), None, "login_ok", m.group(2) + "s"])
                    continue
            elif cat == "session_manager":
                m = RX_LOGINFAIL_NODE.search(msg)
                if m and addr:
                    self.monitors.setdefault(addr, m.group(1))
                elif msg.startswith("Failed to login/connect"):
                    ev = [t, addr, None, "fail", None]
                    self.peer_events.append(ev)
                    last_fail = ev
            elif cat == "appliance_capacity":
                m = RX_CAPACITY.search(msg)
                if m:
                    self.peer_events.append([t, None, m.group(1), "capacity_missing", None])
            elif cat == "ssl" and addr and "AFTER handshake" in msg:
                self.peer_events.append([t, addr, None, "tls_ok", None])

        if first is not None:
            self.files.append((first[0], first[1], last[0], last[1], rel))

    def _clock_check(self, t0, up0, t1, up1, across_files=False):
        """boot = wallclock - uptime should be constant for one engine run.
        A drop in uptime = engine restart; uptime continuous but boot moved =
        the box's clock was stepped."""
        shift = (t1 - up1) - (t0 - up0)
        if abs(shift) <= 120:
            return
        if up1 >= 0 and up1 < (t1 - t0) - 120 or (up1 < up0 and 0 <= up1 < 1800):
            self.clock_events.append((t1, "restart", f"engine uptime reset {up0}s -> {up1}s; last line before it {utc(t0)} "
                                                       f"({dur(t1 - t0)} earlier)"))
        elif not across_files or abs((up1 - up0) - (t1 - t0)) > 120:
            self.clock_events.append((t1, "clock_step", f"wall clock moved {dur(shift)} relative to engine uptime "
                                                          f"(uptime {up0}s -> {up1}s, clock {utc(t0)} -> {utc(t1)})"))

    def finalize(self):
        self.files.sort()
        for a, b in zip(self.files, self.files[1:]):
            if a[3] is not None and b[1] is not None:
                self._clock_check(a[2], a[3], b[0], b[1], across_files=True)
        self.clock_events.sort()
        self.heartbeats.sort()
        self.emips.sort()
        self.app_logins.sort()
        self.app_closes.sort(key=lambda c: c[0])
        for rec in self.issues.values():
            rec.pop("_exc_done", None)


def find_gaps(times, floor):
    """Gaps in a periodic marker. Interval is inferred (median delta); a gap
    is anything over max(3x interval, floor)."""
    if len(times) < 3:
        return None, []
    deltas = [b - a for a, b in zip(times, times[1:])]
    interval = median(deltas)
    limit = max(3 * interval, floor)
    gaps = [(a, b) for a, b in zip(times, times[1:]) if b - a > limit]
    return interval, gaps


# ----------------------------------------------------------------------
# stats/today.log
# ----------------------------------------------------------------------

PROC_METRICS = frozenset((b"cpu", b"rss", b"mem.max", b"mem.free"))


class StatsAgg:
    def __init__(self):
        self.lines = 0
        self.tmin = None
        self.tmax = None
        self.cu_minutes = {}                  # minute -> pid
        self.cu_mem = {}                      # minute -> [free, total]
        self.queues = {}                      # "comp:queue" -> dict
        self.queue_minutes = defaultdict(dict)   # minute -> {"comp:queue": (drop, delay)}
        self.iac = defaultdict(Counter)       # peer nodeid -> {minute: msgs}
        self.vm = defaultdict(dict)           # minute -> {metric: value}
        self.plugin_down = defaultdict(set)   # plugin -> {minute}
        self.adm = Counter()                  # learn.adm.* totals
        # every component reports its own process once a minute: cpu (percent of ONE core, so
        # 3500 = 35 cores), rss, and for JVMs mem.max/mem.free (heap). The pid is column 4.
        # This is what found a plugin JVM sitting on 35 cores in a real case.
        self.procs = {}                       # comp -> {"cpu": {minute: v}, "pid": {minute: pid}, ...}
        self._last_t = None

    def feed(self, fobj):
        cu_minutes, cu_mem, queues, vm = self.cu_minutes, self.cu_mem, self.queues, self.vm
        procs = self.procs
        for raw in fobj:
            p = raw.split(b" ", 5)
            if len(p) < 6 or p[0] != b"p":
                continue
            self.lines += 1
            comp, metric = p[2], p[4]
            is_cu = comp == b"cu"
            is_proc = metric in PROC_METRICS
            if not is_cu and not is_proc and comp != b"stats" and b"queue." not in metric:
                continue
            try:
                t = int(p[1])
                val = float(p[5])
            except ValueError:
                continue
            # real files carry the odd corrupt line with a timestamp years out -- one of those
            # would stretch the bundle's whole "coverage" window
            if self._last_t is not None and abs(t - self._last_t) > 172800:
                continue
            self._last_t = t
            if is_proc:
                pr = procs.get(comp)
                if pr is None:
                    pr = procs[comp] = {"cpu": {}, "pid": {}, "free": {}, "max": 0.0, "rss": 0.0}
                m = t // 60
                if metric == b"cpu":
                    pr["cpu"][m] = val
                    pr["pid"][m] = p[3]
                elif metric == b"rss":
                    if val > pr["rss"]:
                        pr["rss"] = val
                elif metric == b"mem.max":
                    if val > pr["max"]:
                        pr["max"] = val
                elif not is_cu:                # mem.free of a plugin JVM (cu's own is handled below)
                    pr["free"][m] = val
                if not is_cu:
                    continue
            if self.tmin is None or t < self.tmin:
                self.tmin = t
            if self.tmax is None or t > self.tmax:
                self.tmax = t
            minute = t // 60

            if comp == b"stats":
                if metric.startswith(b"vmstat."):
                    vm[minute][metric[7:].decode()] = val
                continue

            if is_cu:
                if minute not in cu_minutes:
                    cu_minutes[minute] = p[3]
                if metric == b"mem.free":
                    cu_mem.setdefault(minute, [None, None])[0] = val
                    continue
                if metric == b"mem.total":
                    cu_mem.setdefault(minute, [None, None])[1] = val
                    continue
                if metric.startswith(b"msg.iac."):
                    if b".dist.count." in metric:
                        peer = metric[8:].split(b".", 1)[0]
                        if peer.isdigit():
                            self.iac[peer.decode()][minute] += int(val)
                    continue
                if metric.startswith(b"learn.adm."):
                    self.adm[metric.decode()] += int(val)
                    continue
                if metric.startswith(b"plugin.") and metric.endswith(b".connected"):
                    if val == 0:
                        self.plugin_down[metric[7:-10].decode()].add(minute)
                    continue

            if metric.startswith(b"queue."):
                name, _, field = metric[6:].rpartition(b".")
                if field not in (b"size", b"peak", b"drop", b"delay", b"add"):
                    continue
                key = comp.decode() + ":" + name.decode()
                q = queues.get(key)
                if q is None:
                    q = queues[key] = {"size": 0, "peak": 0, "drop": 0, "delay": 0, "add": 0,
                                       "t_delay": None, "t_drop": None}
                f = field.decode()
                if f == "add":
                    q["add"] += val
                elif f == "drop":
                    if val > 0:
                        q["drop"] += val
                        q["t_drop"] = q["t_drop"] or t
                        d = self.queue_minutes[minute].setdefault(key, [0, 0])
                        d[0] += val
                elif val > q[f]:
                    q[f] = val
                    if f == "delay":
                        q["t_delay"] = t
                if f == "delay" and val >= 1000:
                    d = self.queue_minutes[minute].setdefault(key, [0, 0])
                    d[1] = max(d[1], val)

    def cu_gaps(self):
        """Minutes with no cu sample at all (engine down/hung) and cu pid changes."""
        mins = sorted(self.cu_minutes)
        gaps, pid_changes = [], []
        for a, b in zip(mins, mins[1:]):
            if b - a > 2:
                gaps.append((a * 60, b * 60))
            if self.cu_minutes[a] != self.cu_minutes[b]:
                pid_changes.append((b * 60, self.cu_minutes[a].decode(), self.cu_minutes[b].decode()))
        return gaps, pid_changes


# ----------------------------------------------------------------------
# generic sweep of every other log
# ----------------------------------------------------------------------

SIGNATURES = [
    ("out-of-memory", rb"Out of memory|oom-killer|oom_kill|(?<!On)OutOfMemoryError(?!=)|Cannot allocate memory|Reached low free"),
    ("disk", rb"No space left on device|Read-only file system|Disk quota exceeded"),
    ("file-handles", rb"Too many open files"),
    ("kernel-hang", rb"blocked for more than \d+ seconds|hung_task|soft lockup|rcu_sched (?:self-)?detected"),
    ("io-error", rb"I/O error|Medium Error|EXT4-fs error"),
    ("crash", rb"segfault|core dumped|general protection|SIGSEGV|SIGABRT|Traceback \(most recent call last\)"),
    ("deadlock", rb"Found \d+ (?:Java-level )?deadlock|deadlock detected|Deadlocks \([1-9]"),
    ("nic-link", rb"NIC Link is Down|link is not ready|Link is Down|carrier lost"),
    ("net-unreachable", rb"No route to host|Network is unreachable|Host is unreachable|Name or service not known"),
    ("conn-refused-reset", rb"Connection refused|Connection reset|Broken pipe|Connection closed by"),
    ("timeout", rb"[Tt]imed out|TimeoutException"),
    ("tls-cert", rb"SSLHandshakeException|SSLException|certificate (?:has )?expired|bad_certificate|certificate_unknown|"
                 rb"handshake_failure|CertificateException"),
    ("db", rb"duplicate key value|could not (?:open|read|write|extend) (?:file|relation|segment|block)|PSQLException|"
           rb"DBD::Pg::\w+ \w+ failed|terminating connection|PANIC:  |too many clients|remaining connection slots"),
    ("queue-full-drop", rb"[Qq]ueue (?:is )?full|[Dd]ropping (?:message|event|packet)"),
    ("service-restart", rb"Watch dog .{0,40}starting|Restarting (?:service|plugin|CounterACT)|is not running|"
                        rb"is stalled|stalled for|respawn|Starting CounterACT|Stopping CounterACT|clock moved backwards"),
    ("java-exception", rb"\b(?:[a-z_][\w$]*\.)+[A-Z][\w$]*(?:Exception|StackOverflowError|NoClassDefFoundError)\b"),
    # A plugin handed a host key it cannot resolve -- in practice a placeholder (reserved-range)
    # address for a host known by MAC but not by IP. Added 2026-09-23 from a customer label case:
    # goodies.log threw 8 of these in an 8-minute window, for hosts other than the reported one.
    ("identity-resolve", rb"Got invalid primary Key|goodies_noip_action|goodies_noip_prop"),
]

# Stage 1 of the sweep. A multi-branch regex over raw log text ran at ~4MB/s -- a
# real 4GB bundle would have taken a quarter of an hour. bytes.find() on a literal
# runs at memory speed, so every signature above is reduced to the literal stem(s)
# it cannot match without; only lines holding a stem are handed to SWEEP_RX.
# Keep this a SUPERSET of SIGNATURES: a branch with no stem here can never fire.
STEMS = [
    b"Out of memory", b"oom-kill", b"oom_kill", b"OutOfMemoryError", b"Cannot allocate memory", b"Reached low free",
    b"No space left", b"Read-only file system", b"Disk quota", b"Too many open files",
    b"blocked for more than", b"hung_task", b"soft lockup", b"rcu_sched",
    b"I/O error", b"Medium Error", b"EXT4-fs error",
    b"segfault", b"core dumped", b"general protection", b"SIGSEGV", b"SIGABRT", b"Traceback (most",
    b"deadlock", b"Deadlocks (",
    b"ink is Down", b"link is not ready", b"carrier lost",
    b"No route to host", b"is unreachable", b"Name or service not known",
    b"Connection refused", b"Connection reset", b"Broken pipe", b"Connection closed by",
    b"imed out",
    b"certificate expired", b"certificate has expired", b"bad_certificate", b"certificate_unknown", b"handshake_failure",
    b"duplicate key", b"could not ", b"DBD::Pg", b"terminating connection", b"PANIC:", b"too many clients",
    b"remaining connection slots",
    b"ueue is full", b"ueue full", b"ropping message", b"ropping event", b"ropping packet",
    b"Watch dog", b"Restarting ", b"is not running", b"is stalled", b"stalled for", b"respawn",
    b"Starting CounterACT", b"Stopping CounterACT", b"clock moved backwards",
    b"Exception", b"StackOverflowError", b"NoClassDefFoundError",
    b"invalid primary Key", b"goodies_noip_",
]
SWEEP_RX = re.compile(b"|".join(b"(?P<s%d>%s)" % (i, pat) for i, (_, pat) in enumerate(SIGNATURES)))
RX_TS_FSTOOL = re.compile(rb"(?:^|:)(\d{10})\.\d+:")
RX_TS_TRACE = re.compile(rb"\|(\d{13})\|")
RX_TS_SYSLOG = re.compile(rb"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) ")
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

SWEEP_INCLUDE = (FS + "log/", "files/var/log/messages", "info/misc/dmesg.log", "info/misc/java-stack")
SWEEP_EXCLUDE_RX = re.compile(r"/Trace_|\.gz$|\.zip$|/jstats/|/sa/|\.hprof$|/install/")


class SweepAgg:
    def __init__(self):
        self.hits = {}                    # (family, signame, subkey) -> dict
        self.minutes = defaultdict(Counter)   # minute -> {family: n}   (epoch-stamped lines only)
        self.files = 0
        self.bytes = 0
        self.events = EventAgg()

    def feed(self, rel, fobj):
        fam = family(rel)
        self.files += 1
        carry = b""
        while True:
            chunk = fobj.read(4 * 1024 * 1024)
            if not chunk:
                break
            self.bytes += len(chunk)
            data = carry + chunk
            cut = data.rfind(b"\n")
            if cut < 0:
                carry = data[-65536:]
                continue
            carry = data[cut + 1:]
            self._scan(fam, data[:cut + 1])
        if carry:
            self._scan(fam, carry)

    def _scan(self, fam, data):
        find, rfind = data.find, data.rfind
        # structured events first (traps, learn events, plugin stop/start) -- same literal-stem
        # trick as the error sweep below, each hit line handed to EventAgg
        if fam.startswith("log/plugin/"):
            ev_starts = set()
            for stem in EVENT_STEMS:
                pos = find(stem)
                while pos >= 0:
                    ev_starts.add(rfind(b"\n", 0, pos) + 1)
                    nl = find(b"\n", pos)
                    if nl < 0:
                        break
                    pos = find(stem, nl + 1)
            for ls in sorted(ev_starts):
                le = find(b"\n", ls)
                self.events.line(fam, data[ls:le if le >= 0 else len(data)])
        starts = set()
        for stem in STEMS:
            pos = find(stem)
            while pos >= 0:
                starts.add(rfind(b"\n", 0, pos) + 1)
                nl = find(b"\n", pos)
                if nl < 0:
                    break
                pos = find(stem, nl + 1)
        search = SWEEP_RX.search
        for ls in sorted(starts):
            le = find(b"\n", ls)
            if le < 0:
                le = len(data)
            line = data[ls:min(le, ls + 4000)]
            if line.lstrip()[:3] == b"at ":
                continue                      # stack frame, not an event
            m = search(line)
            if m is None:
                continue
            idx = int(m.lastgroup[1:])
            signame = SIGNATURES[idx][0]
            sub = m.group(0).decode("latin-1") if signame == "java-exception" else ""
            if signame == "java-exception":
                sub = sub.rsplit(".", 1)[-1]
            ts = None
            mt = RX_TS_FSTOOL.search(line[:120]) or None
            if mt:
                ts = int(mt.group(1))
            else:
                mt = RX_TS_TRACE.search(line[:60])
                if mt:
                    ts = int(mt.group(1)) / 1000.0
            sys_t = None
            if ts is None:
                ms = RX_TS_SYSLOG.match(line)
                if ms and ms.group(1).decode() in MONTHS:
                    sys_t = (MONTHS[ms.group(1).decode()], int(ms.group(2)), int(ms.group(3)), int(ms.group(4)),
                             int(ms.group(5)))
            key = (fam, signame, sub)
            rec = self.hits.get(key)
            if rec is None:
                rec = self.hits[key] = {"count": 0, "first": None, "last": None,
                                        "sample": line[:260].decode("utf-8", "replace").strip(), "sys": [],
                                        "days": Counter(), "recent_sample": None}
            rec["count"] += 1
            if ts is not None:
                rec["first"] = ts if rec["first"] is None else min(rec["first"], ts)
                rec["last"] = ts if rec["last"] is None else max(rec["last"], ts)
                self.minutes[int(ts // 60)][fam] += 1
                rec["days"][int(ts // 86400)] += 1
                rec["recent_sample"] = line[:260].decode("utf-8", "replace").strip()
            elif sys_t is not None and len(rec["sys"]) < 2000:
                rec["sys"].append(sys_t)

    def resolve_syslog(self, year, end_month, tz_offset):
        """syslog lines carry no year or zone -- fill both in from the bundle's own
        snapshot.properties once it has been read (it can sit at the END of the archive)."""
        import calendar
        for (fam, _, _), rec in self.hits.items():
            for (mon, day, hh, mm, ss) in rec.pop("sys"):
                y = year - 1 if mon > end_month else year
                try:
                    ts = calendar.timegm((y, mon, day, hh, mm, ss)) - tz_offset
                except (ValueError, OverflowError):
                    continue
                rec["first"] = ts if rec["first"] is None else min(rec["first"], ts)
                rec["last"] = ts if rec["last"] is None else max(rec["last"], ts)
                self.minutes[int(ts // 60)][fam] += 1
                rec["days"][int(ts // 86400)] += 1


# ----------------------------------------------------------------------
# plugin-log events: link-down traps, learn events that flip a host online,
# plugin stop/start history
# ----------------------------------------------------------------------

EVENT_STEMS = [
    b"plugin_learn_cb", b"reporting trap [", b"sw_trap_handle_link_down", b"mac_removed_from_port_handle_mac",
    b"Plugin stopped", b"Running plugin Java daemon", b"Handling stop message",
]
RX_EV_EPOCH = re.compile(rb"^[\w.\-]+:(\d+):(\d{10})\.\d+:")
RX_EV_LEARN = re.compile(
    rb"plugin_learn_cb:\d+: msg: \{change=\{(.*?)\},host=\{(.*?)\},learnevent=\{agent=\{id=(\w+),nodeid=(-?\d+)\},entries=\[(.*)\]")
RX_EV_ENTRY = re.compile(rb"\{name=(\w+),value=([^}]*)\}")
RX_EV_HOST_IP = re.compile(rb"\bip=([0-9a-fA-F.:]+)")
RX_EV_HOST_MAC = re.compile(rb"\bmac=([0-9a-f]{12})")
RX_EV_TRAP_MAC = re.compile(rb"\[keys:([0-9.]+)[^\]]*\]:\d+: mac\[([0-9a-f]{12})\] reporting trap \[(up|down)\] event")
RX_EV_PORT_DOWN = re.compile(rb"sw_trap_handle_link_down:.*?ip\[([0-9.]+)\], port\[([^\]]+)\]")
RX_EV_STOPMSG = re.compile(rb"Handling stop message (\w+)")
MAX_LEARN_ROWS = 400000


class EventAgg:
    def __init__(self):
        self.learn_rows = []          # (t, agent, node, ip, mac, adm, online, online_change, channel)
        self.learn_total = 0
        self.learn_span = [None, None]
        self.learn_sources = Counter()    # which log family the learn lines came from
        self.trap_mac = []            # (t, switch ip, mac, "up"|"down")
        self.port_downs = Counter()   # (switch ip, port) -> n
        self.trap_span = [None, None]
        self.lifecycle = defaultdict(list)   # plugin -> [(t, kind, pid)]

    def line(self, fam, line):
        m = RX_EV_EPOCH.match(line)
        if not m:
            return
        pid, t = m.group(1).decode(), int(m.group(2))
        if b"plugin_learn_cb" in line:
            ml = RX_EV_LEARN.search(line)
            if not ml:
                return
            self.learn_total += 1
            self.learn_sources[fam] += 1
            sp = self.learn_span
            sp[0] = t if sp[0] is None else min(sp[0], t)
            sp[1] = t if sp[1] is None else max(sp[1], t)
            if len(self.learn_rows) >= MAX_LEARN_ROWS:
                return
            change, host, agent, node, entries = ml.groups()
            ent = dict(RX_EV_ENTRY.findall(entries))
            och = b""
            for piece in change.split(b","):
                if piece.startswith(b"online="):
                    och = piece[7:]
            ip = RX_EV_HOST_IP.search(host)
            mac = RX_EV_HOST_MAC.search(host)
            self.learn_rows.append((
                t, agent.decode(), node.decode(), ip.group(1).decode() if ip else "?",
                mac.group(1).decode() if mac else "?", ent.get(b"adm", b"").decode("latin-1"),
                ent.get(b"online", b"").decode("latin-1"), och.decode("latin-1"),
                ent.get(b"channel", b"").decode("latin-1")))
            return
        if b"reporting trap [" in line:
            mt = RX_EV_TRAP_MAC.search(line)
            if mt:
                self.trap_mac.append((t, mt.group(1).decode(), mt.group(2).decode(), mt.group(3).decode()))
                self._trap_t(t)
            return
        if b"sw_trap_handle_link_down" in line:
            mp = RX_EV_PORT_DOWN.search(line)
            if mp:
                self.port_downs[(mp.group(1).decode(), mp.group(2).decode())] += 1
                self._trap_t(t)
            return
        plugin = fam.split("/")[2] if fam.startswith("log/plugin/") and fam.count("/") >= 3 else fam
        if b"Plugin stopped" in line:
            self.lifecycle[plugin].append((t, "stopped", pid))
        elif b"Running plugin Java daemon" in line:
            self.lifecycle[plugin].append((t, "started", pid))
        elif b"Handling stop message" in line:
            ms = RX_EV_STOPMSG.search(line)
            self.lifecycle[plugin].append((t, "stop:" + (ms.group(1).decode() if ms else "?"), pid))

    def _trap_t(self, t):
        sp = self.trap_span
        sp[0] = t if sp[0] is None else min(sp[0], t)
        sp[1] = t if sp[1] is None else max(sp[1], t)

    def false_online(self):
        """A MAC the Switch plugin took down on a link-down trap, then flipped back online by some
        OTHER plugin before any link-up trap for it. Returns [(down_t, up_t|None, mac, switch, learn_row)]."""
        by_mac = defaultdict(list)
        for ev in sorted(self.trap_mac):
            by_mac[ev[2]].append(ev)
        flips = defaultdict(list)
        for r in self.learn_rows:
            if r[6] == "true" and r[7] in ("change", "new") and r[1] != "sw":
                flips[r[4]].append(r)
        out = []
        for mac, evs in by_mac.items():
            if mac not in flips:
                continue
            for i, (t, sw, _, kind) in enumerate(evs):
                if kind != "down":
                    continue
                up_t = next((e[0] for e in evs[i + 1:] if e[3] == "up"), None)
                for r in flips[mac]:
                    if r[0] > t and (up_t is None or r[0] < up_t):
                        out.append((t, up_t, mac, sw, r))
        return sorted(out)


# ----------------------------------------------------------------------
# jstack samples of the plugin JVMs (info/misc/java-stack/PluginMain/sample<pid>_N.log)
# ----------------------------------------------------------------------

RX_JS_IDLE = re.compile(r"socketRead0|epollWait|socketAccept|accept0|FileInputStream\.readBytes|PlainSocketImpl|"
                        r"poll0|UNIXProcess\.waitFor|LinuxWatchService\.poll|Object\.wait|Unsafe\.park|EPoll\.wait|"
                        r"Net\.accept|Net\.poll|NioSocketImpl|SocketDispatcher\.read0|FileDispatcherImpl\.read0|"
                        r"Thread\.sleep|ProcessImpl\.waitFor")
RX_JS_IDLE_APP = re.compile(r"\.(select|handleKeys|run)$")     # selector/accept loops: RUNNABLE but parked in native code
RX_JS_APP = re.compile(r"^(forescout\.|com\.secmatters|com\.forescout)")


class JstackAgg:
    def __init__(self):
        self.pids = {}     # pid -> {"samples": n, "hot": Counter, "gc": n, "plugins": Counter}

    def feed(self, pid, text):
        rec = self.pids.setdefault(pid, {"samples": 0, "hot": Counter(), "gc": 0, "plugins": Counter()})
        rec["samples"] += 1
        rec["gc"] = max(rec["gc"], text.count('"GC task thread'))
        seen = set()
        for block in text.split("\n\n"):
            lines = block.strip().splitlines()
            if len(lines) < 3 or not lines[0].startswith('"'):
                continue
            if "java.lang.Thread.State: RUNNABLE" not in lines[1]:
                continue
            frames = [ln.strip()[3:].split("(")[0] for ln in lines[2:] if ln.strip().startswith("at ")]
            if not frames or RX_JS_IDLE.search(frames[0]):
                continue
            app = next((f for f in frames if RX_JS_APP.match(f)), None)
            if app is None or (frames[0] == app and RX_JS_IDLE_APP.search(app)):
                continue
            mp = re.match(r"forescout\.plugin\.(\w+)\.", app)
            if mp:
                rec["plugins"][mp.group(1)] += 1
            name = re.sub(r"\d+", "N", lines[0].split('"')[1])
            if (name, app) not in seen:          # once per dump, however many pool threads share the frame
                seen.add((name, app))
                rec["hot"][(name, app)] += 1


# ----------------------------------------------------------------------
# `fstool hostinfo <ip>` dumps attached to a bundle (files/tmp/*.txt)
# ----------------------------------------------------------------------

RX_HI = re.compile(r"^(\S+), (\d+),([^,]*), ([^,]+), (.*), \(([^)]*)\), \d+, \d+\s*$")
RX_HI_ASSIGNED = re.compile(r"^(\S+), \d+,[^,]*, assigned-to, (\S+) \(IP: [^,]+, ID: (\d+)\)")


def parse_hostinfo(text):
    """-> {ip: {"assigned": (addr, nodeid), "props": [(epoch, field, value, source)]}} or {} if not a hostinfo dump."""
    hosts = {}
    for line in text.splitlines():
        ma = RX_HI_ASSIGNED.match(line)
        if ma:
            hosts.setdefault(ma.group(1), {"assigned": None, "props": []})["assigned"] = (ma.group(2), ma.group(3))
            continue
        m = RX_HI.match(line)
        if m:
            ip, epoch, _, field, value, source = m.groups()
            hosts.setdefault(ip, {"assigned": None, "props": []})["props"].append(
                (int(epoch), field.strip(), value.strip(), source.split(" ")[0]))
    return {ip: h for ip, h in hosts.items() if h["props"]}


# ----------------------------------------------------------------------
# host identity and labels (files/tmp/Allhosts.txt)
# ----------------------------------------------------------------------

# Forescout's reserved range, from fslib_is_reserved_ip: the stand-in primary key it
# allocates for a host it knows by MAC but not (yet) by IP.
RESIP_START = 224 << 24
RESIP_END = (247 << 24) | 0xFFFFFF


def is_placeholder_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    v = 0
    for part in parts:
        if not part.isdigit():
            return False
        n = int(part)
        if n > 255:
            return False
        v = (v << 8) | n
    return RESIP_START <= v <= RESIP_END


# Only the handful of fields this aggregate needs, matched in one pass -- Allhosts.txt
# runs to millions of lines on a real appliance, so everything else is rejected here.
RX_ALLHOSTS = re.compile(
    rb"^([0-9][0-9.]+), \d+,[^,]*, "
    rb"(goodies_label_list|access_ip|mac|sw_ipport|dhcp_class|"
    rb"action\.goodies_unlabel_action|action\.goodies_label_action), (.*)$")


class LabelAgg:
    """Every host record on the appliance, in `fstool hostinfo` line format.

    Built 2026-09-23 from a customer "Delete Label does nothing" case. A host that eyeSight
    keys with a placeholder address keeps its labels permanently: goodies.pl's
    assign_label resolves that placeholder to the host's MAC before writing, while
    remove_label clears against the placeholder itself -- which holds no label -- and
    still replies success. Policies that add a label and later delete it to re-trigger a
    check therefore never re-trigger on those hosts."""

    MAX_EXAMPLES = 8

    def __init__(self):
        self.seen = False
        self.keys = set()     # every distinct host key in the file
        self.ph = {}          # placeholder-keyed hosts only -> facts
        self._stats = None

    @property
    def hosts(self):
        return len(self.keys)

    def feed(self, fobj):
        self.seen = True
        self._stats = None
        ph = self.ph
        keys = self.keys
        known = {}
        for raw in fobj:
            # Count host keys directly: not every record carries an assigned-to line (7,069 of
            # 7,350 in the customer bundle), so that cannot be the total. The key must still look
            # like an address -- a wrapped multi-line value (a switch running-config, say) also
            # starts a line and would otherwise be counted as a host.
            end = raw.find(b",")
            if end <= 0:
                continue
            key_raw = raw[:end]
            if b"." in key_raw and key_raw.replace(b".", b"").isdigit():
                keys.add(key_raw)
            m = RX_ALLHOSTS.match(raw)
            if m is None:
                continue
            key_b, field, val = m.group(1), m.group(2), m.group(3)
            placeholder = known.get(key_b)
            if placeholder is None:
                placeholder = known[key_b] = is_placeholder_ip(key_b.decode("ascii", "replace"))
            if not placeholder:
                continue
            # an empty value sits straight against the source paren, so a cut at 0 counts
            cut = val.find(b", (")
            if cut >= 0:
                val = val[:cut]
            if val == b"???":      # Forescout's "could not resolve" marker -- not a value
                val = b""
            key = key_b.decode("ascii", "replace")
            h = ph.get(key)
            if h is None:
                h = ph[key] = {"labels": [], "ip": "", "mac": "", "switch": "", "cls": "", "del": 0, "add": 0}
            if field == b"goodies_label_list":
                if val:
                    h["labels"].append(val.decode("utf-8", "replace"))
            elif field == b"access_ip":
                if val:
                    h["ip"] = val.decode("ascii", "replace")
            elif field == b"mac":
                if val:
                    h["mac"] = val.decode("ascii", "replace")
            elif field == b"sw_ipport":
                if val:
                    h["switch"] = val.decode("ascii", "replace")
            elif field == b"dhcp_class":
                if val:
                    h["cls"] = val.decode("utf-8", "replace")
            elif field == b"action.goodies_unlabel_action":
                h["del"] += 1
            else:
                h["add"] += 1

    def stats(self):
        if self._stats is not None:
            return self._stats
        # every placeholder-keyed host in the file, not just the ones carrying a field this
        # aggregate tracks -- self.ph only gains a host when one of those fields is seen
        placeholder = sum(1 for k in self.keys if is_placeholder_ip(k.decode("ascii", "replace")))
        out = {"hosts": self.hosts, "placeholder": placeholder, "ph_ip": 0, "ph_mac": 0, "ph_switch": 0,
               "labelled": 0, "labelled_ip": 0, "stuck": 0, "retry": 0,
               "labels": Counter(), "classes": Counter(), "examples": []}
        for h in self.ph.values():
            if h["ip"]:
                out["ph_ip"] += 1
            if h["mac"]:
                out["ph_mac"] += 1
            if h["switch"]:
                out["ph_switch"] += 1
            if not h["labels"]:
                continue
            out["labelled"] += 1
            out["stuck"] += len(h["labels"])
            if h["ip"]:
                out["labelled_ip"] += 1
            if h["del"]:
                out["retry"] += 1
            for name in h["labels"]:
                out["labels"][name] += 1
            if h["cls"]:
                out["classes"][h["cls"]] += 1
        # worst first: a delete already attempted, then the most labels held
        out["examples"] = sorted(((k, h) for k, h in self.ph.items() if h["labels"]),
                                 key=lambda kv: (-kv[1]["del"], -len(kv[1]["labels"])))[:self.MAX_EXAMPLES]
        self._stats = out
        return out


# ----------------------------------------------------------------------
# one bundle
# ----------------------------------------------------------------------

RX_CMD_START = re.compile(r"^Start: (.+?), \(utc: (\d+)\)")
RX_TZ_OFFSET = re.compile(r"GMT ([+-])(\d\d):(\d\d)")


class Bundle:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path.rstrip("/\\"))
        self.props = {}
        self.nodeid_file = None
        self.trace = TraceAgg()
        self.stats = StatsAgg()
        self.sweep = SweepAgg()
        self.errors_summary = ""
        self.events_txt = ""
        self.relinfo = []
        self.db_events = Counter()
        self.db_events_window = Counter()
        self.host = {}
        self.cmd_clock = []
        self.members = 0
        self.warnings = []
        self.index = 0             # 1-based position in the report, set once all bundles are read
        self.jstack = JstackAgg()
        self.ps_plugins = {}       # pid -> (plugin, "-Xmx..." or "")
        self.hostinfo = {}         # ip -> parsed `fstool hostinfo` dump attached under files/tmp
        self.node_addr = {}        # node id -> appliance address, from etc/*.properties
        self.trace_ip_list = ""    # fs.trace.ip.list / fs.trace.mac.list, if per-host tracing was configured
        self.trace_ip_set_at = None
        self.summary = {}          # collection command / elapsed seconds, from summary.txt
        self.wireless_controllers = None
        self.labels = LabelAgg()   # files/tmp/Allhosts.txt -- identity + label state

    # ---- identity ------------------------------------------------------
    @property
    def nodeid(self):
        # a real EM bundle's snapshot.properties says nodeid=0 -- its true node ID is only in
        # files/var/forescout/nodeid
        n = self.props.get("nodeid")
        if n and n != "0":
            return n
        return self.nodeid_file or n or "?"

    @property
    def role(self):
        t = (self.props.get("type") or "").lower()
        vote = self.trace.app_votes.most_common(1)
        tv = vote[0][0].lower() if vote else ""
        if tv == "em" or t in ("em", "enterprise_manager", "enterprise manager", "manager"):
            return "EM"
        if tv == "app" or "appliance" in t:
            return "Appliance"
        return t or "unknown"

    @property
    def tz_offset(self):
        m = RX_TZ_OFFSET.search(self.props.get("timezonefull", ""))
        if not m:
            return 0
        off = int(m.group(2)) * 3600 + int(m.group(3)) * 60
        return off if m.group(1) == "+" else -off

    @property
    def label(self):
        return f"[{self.index}] {self.role} {self.nodeid}"

    def window_start(self):
        """Start of the period this bundle was collected for -- hits older than
        this are history, not the incident."""
        if self.props.get("start"):
            return int(self.props["start"])
        lo = self.trace.tmin or self.stats.tmin
        return lo if lo is not None else 0

    def watchdog_restarts(self):
        return sorted(e for e in (self.host.get("watchdog") or []) if "restarting CounterACT" in e[1]
                      or "Watch dog for" in e[1])

    def coverage(self):
        lo = [x for x in (self.trace.tmin, self.stats.tmin) if x is not None]
        hi = [x for x in (self.trace.tmax, self.stats.tmax) if x is not None]
        return (min(lo) if lo else None, max(hi) if hi else None)

    # ---- reading -------------------------------------------------------
    def read(self):
        if os.path.isdir(self.path):
            self._read_dir()
        else:
            self._read_tar()
        self.trace.finalize()
        end = int(self.props.get("end") or (self.coverage()[1] or time.time()))
        lt = time.gmtime(end + self.tz_offset)
        self.sweep.resolve_syslog(lt.tm_year, lt.tm_mon, self.tz_offset)

    def _read_tar(self):
        try:
            with tarfile.open(self.path, "r|*") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    rel = rel_member(member.name)
                    if not rel or not self._wanted(rel):
                        continue
                    fobj = tar.extractfile(member)
                    if fobj is None:
                        continue
                    self._dispatch(rel, fobj)
        except (tarfile.TarError, EOFError, OSError) as e:
            self.warnings.append(f"archive read stopped early: {e} -- results cover what was read before that point")

    def _read_dir(self):
        root = self.path
        # accept either the bundle dir itself or a dir holding exactly one bundle dir
        if not os.path.isdir(os.path.join(root, "info")):
            subs = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d, "info"))]
            if len(subs) == 1:
                root = os.path.join(root, subs[0])
        for dirpath, _, files in os.walk(root):
            for fn in files:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if not self._wanted(rel):
                    continue
                try:
                    with open(full, "rb") as fobj:
                        self._dispatch(rel, fobj)
                except OSError as e:
                    self.warnings.append(f"{rel}: {e}")

    @staticmethod
    def _wanted(rel):
        if rel.startswith(("info/", "errors/", "db/relinfo", "db/samples/events.", "files/var/forescout/nodeid")):
            return not rel.startswith(("info/misc/lsof", "info/misc/ls.", "info/misc/rpm"))
        if rel == "summary.txt" or rel.startswith(("files/tmp/", "db/samples/audit.")):
            return True
        if rel.startswith(FS + "stats/today.log"):
            return True
        if rel.startswith(FS + "etc/") and rel.endswith(".properties") and rel.count("/") == 5:
            return True
        return rel.startswith(SWEEP_INCLUDE)

    def _dispatch(self, rel, fobj):
        self.members += 1
        base = rel.rsplit("/", 1)[-1]
        if rel == "info/snapshot.properties":
            for line in fobj.read().decode("utf-8", "replace").splitlines():
                k, sep, v = line.partition("=")
                if sep:
                    self.props[k.strip()] = v.strip()
        elif rel == "files/var/forescout/nodeid":
            self.nodeid_file = fobj.read(200).decode("utf-8", "replace").strip()
        elif rel.startswith(FS + "log/") and base.startswith("Trace_cu_"):
            self.trace.feed(rel, fobj)
        elif rel == FS + "stats/today.log":
            self.stats.feed(fobj)
        elif rel == "errors/summary.txt":
            self.errors_summary = fobj.read(20000).decode("utf-8", "replace")
        elif rel == "info/events.txt":
            self.events_txt = fobj.read(200000).decode("utf-8", "replace")
        elif rel == "db/relinfo.txt":
            self._relinfo(fobj.read(400000).decode("utf-8", "replace"))
        elif rel == "db/samples/events.txt.gz":
            self._db_events(fobj.read())
        elif rel == "summary.txt":
            text = fobj.read(200000).decode("utf-8", "replace")
            m = re.search(r"Snapshot collection elapsed time: \S+ \((\d+) seconds\)", text)
            if m:
                self.summary["elapsed"] = int(m.group(1))
            m = re.search(r"\| Command\s+\| (.*?)\s*\|", text)
            if m:
                self.summary["command"] = m.group(1)
        elif rel == "info/misc/ps-auxww.log":
            for line in fobj.read(8000000).decode("utf-8", "replace").splitlines():
                m = re.search(r"-Dfs\.plugin=(\w+)", line)
                if m:
                    cols = line.split(None, 2)
                    x = re.search(r"-Xmx\w+", line)
                    if len(cols) > 1 and cols[1].isdigit():
                        self.ps_plugins[cols[1]] = (m.group(1), x.group(0) if x else "")
        elif rel.startswith("info/misc/java-stack/") and re.search(r"/sample(\d+)_\d+\.log$", rel):
            pid = re.search(r"/sample(\d+)_\d+\.log$", rel).group(1)
            self.jstack.feed(pid, fobj.read(8000000).decode("utf-8", "replace"))
        elif rel.startswith("files/tmp/"):
            if base == "wireless_controllers":
                m = re.search(r"Total Elements: \[(\d+)\]", fobj.read(4000).decode("utf-8", "replace"))
                if m:
                    self.wireless_controllers = int(m.group(1))
            elif base.lower().startswith("allhosts") and base.endswith((".txt", ".log")):
                # every host record on the appliance -- streamed, never held whole (millions of lines)
                self.labels.feed(fobj)
            elif base.endswith((".txt", ".log")) and "hostinfo" in base.lower():
                self.hostinfo.update(parse_hostinfo(fobj.read(4000000).decode("utf-8", "replace")))
        elif rel.startswith(FS + "etc/") and base.endswith(".properties"):
            for line in fobj.read(4000000).decode("utf-8", "replace").splitlines():
                m = re.match(r"^(\d{15,22})=(\S+)\s*$", line)
                if m:
                    self.node_addr[m.group(1)] = m.group(2)
                elif line.startswith(("fs.trace.ip.list=", "fs.trace.mac.list=")) and line.split("=", 1)[1].strip():
                    self.trace_ip_list += line.strip() + "  "
        elif rel.startswith("db/samples/audit."):
            try:
                text = gzip.decompress(fobj.read()).decode("utf-8", "replace")
            except (OSError, EOFError):
                text = ""
            for line in text.splitlines():
                if "setting property: fs.trace.ip.list" in line or "setting property: fs.trace.mac.list" in line:
                    m = re.search(r"\|\s*(\d{10})\s*\|", line)
                    if m and line.split("with value:", 1)[-1].strip(" |"):
                        t = int(m.group(1))
                        self.trace_ip_set_at = t if self.trace_ip_set_at is None else min(self.trace_ip_set_at, t)
        elif rel.startswith("info/misc/") and base in ("df.log", "uptime.log", "top.log", "sar-r.log"):
            text = fobj.read(60000).decode("utf-8", "replace")
            self._cmd_clock(text)
            self.host[base] = text
        elif rel.startswith(SWEEP_INCLUDE) and not SWEEP_EXCLUDE_RX.search(rel):
            if rel.startswith(FS + "log/watch_dog.log"):
                data = fobj.read()
                self._watchdog(data)
                self.sweep.feed(rel, io.BytesIO(data))
            else:
                self.sweep.feed(rel, fobj)

    def _cmd_clock(self, text):
        for line in text.splitlines()[:4]:
            m = RX_CMD_START.match(line)
            if m:
                self.cmd_clock.append((m.group(1), int(m.group(2))))
                return

    def _relinfo(self, text):
        self._cmd_clock(text)
        for line in text.splitlines():
            m = re.match(r"^(Table|Index): (\S+): (\d+) K", line)
            if m:
                self.relinfo.append((int(m.group(3)), m.group(1), m.group(2)))
        self.relinfo.sort(reverse=True)

    def _db_events(self, blob):
        try:
            text = gzip.decompress(blob).decode("utf-8", "replace")
        except (OSError, EOFError):
            return
        header = None
        for line in text.splitlines():
            cols = [c.strip() for c in line.split("|")]
            if header is None:
                if "event_id" in cols and "event_time" in cols:
                    header = {c: i for i, c in enumerate(cols)}
                continue
            if len(cols) < len(header):
                continue
            key = f"{cols[header.get('group_id', 0)]}/{cols[header['event_id']]}"
            self.db_events[key] += 1

    def _watchdog(self, data):
        evs = self.host.setdefault("watchdog", [])
        for m in re.finditer(rb"^[^\n]*?:(\d{10})\.\d+:[^\n]*?: (Watch dog for [^\n]{0,80}starting[^\n]{0,40}|"
                             rb"[^\n]{0,60}(?:is not running|[Rr]estarting|[Ss]talled)[^\n]{0,120})", data, re.M):
            evs.append((int(m.group(1)), m.group(2).decode("utf-8", "replace").strip()))


# ----------------------------------------------------------------------
# EM-side outage derivation
# ----------------------------------------------------------------------

def em_peer_outages(trace, merge_gap=300):
    """Per peer (keyed by node ID where the trace let us learn it, else by
    address): merge runs of login failures into outage windows."""
    addr2node = dict(trace.monitors)
    node2addr = {}
    for a, n in addr2node.items():
        node2addr.setdefault(n, a)
    per_peer = defaultdict(list)
    for t, addr, node, kind, detail in sorted(trace.peer_events, key=lambda e: e[0]):
        if node is None and addr is not None:
            node = addr2node.get(addr)
        key = node or addr
        if key is None:
            continue
        per_peer[key].append((t, kind, detail))
    result = {}
    for key, evs in per_peer.items():
        outages, cur = [], None
        watchdog = Counter()
        tls_ok = []
        sess_starts = []
        was_down, last_healthy = True, None    # "down" until proven up: the first healthy line is a session start
        for t, kind, detail in evs:
            if kind in ("sess_up", "logout"):
                # a session (re)start = first healthy line after a failure, or the "login"
                # category line the EM writes as it opens a session
                if was_down or (kind == "logout" and last_healthy is not None and t - last_healthy > 5):
                    if not sess_starts or t - sess_starts[-1] > 5:
                        sess_starts.append(t)
                was_down, last_healthy = False, t
            elif kind in ("fail", "wd_down"):
                was_down = True
            if kind in ("wd_up", "wd_down"):
                watchdog[kind] += 1
            if kind == "tls_ok":
                tls_ok.append(t)
            is_down = kind in ("fail", "wd_down")
            is_up = kind in ("wd_up", "login_ok", "sess_up", "logout")
            if is_down:
                if cur is not None and t - cur["end"] > merge_gap:
                    outages.append(cur)
                    cur = None
                if cur is None:
                    cur = {"start": t, "end": t, "fails": 0, "reasons": Counter(), "recovered": None, "tls_ok": 0}
                cur["end"] = t
                if kind == "fail":
                    cur["fails"] += 1
                    cur["reasons"][detail or "no exception logged"] += 1
                else:
                    cur["reasons"]["LoginWatchdog connected=false"] += 1
            elif is_up and cur is not None:
                cur["recovered"] = t
                outages.append(cur)
                cur = None
        if cur is not None:
            outages.append(cur)
        for o in outages:
            o["tls_ok"] = sum(1 for x in tls_ok if o["start"] - 5 <= x <= o["end"] + 5)
        result[key] = {
            "addr": node2addr.get(key, key if not key.isdigit() else "?"),
            "conntype": trace.peer_conntype.get(node2addr.get(key, key), "?"),
            "outages": outages, "watchdog": watchdog,
            "capacity_missing": sum(1 for _, k, _ in evs if k == "capacity_missing"),
            "sess_starts": sess_starts,
            "logouts": [t for t, k, _ in evs if k == "logout"],
        }
    return result


def regularity(starts):
    """David's periodic-pattern check (same idea as high-admission-trace.sh's
    REGULAR SPACING): 3+ events whose spacing has a CV <= 40%."""
    if len(starts) < 3:
        return None
    deltas = [b - a for a, b in zip(starts, starts[1:])]
    mean = sum(deltas) / len(deltas)
    if mean <= 0:
        return None
    var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    cv = (var ** 0.5) / mean
    return mean, cv


# ----------------------------------------------------------------------
# report
# ----------------------------------------------------------------------

class Report:
    def __init__(self):
        self.lines = []

    def h(self, title):
        self.lines += ["", "=" * 78, f"=== {title}", "=" * 78]

    def sub(self, title):
        self.lines += ["", f"--- {title}"]

    def p(self, text=""):
        self.lines.append(text)

    def text(self):
        return "\n".join(self.lines) + "\n"


def context_block(rep, bundle, t, window, offset=0.0, indent="      "):
    """What one bundle logged around time t (t is in the reference clock;
    offset converts it into this bundle's own clock)."""
    tl = t + offset
    lo, hi = int((tl - window) // 60), int((tl + window) // 60)
    tr, st, sw = bundle.trace, bundle.stats, bundle.sweep
    cov = bundle.coverage()
    if cov[0] is None or tl < cov[0] - window or tl > cov[1] + window:
        rep.p(f"{indent}{bundle.label}: outside this bundle's coverage ({utc(cov[0])} .. {utc(cov[1])} UTC)")
        return
    rep.p(f"{indent}{bundle.label}, +/-{dur(window)}:")
    sigs = []
    for sig, mins in tr.issue_minutes.items():
        n = sum(c for m, c in mins.items() if lo <= m <= hi)
        if n:
            sigs.append((n, sig))
    sigs.sort(reverse=True)
    for n, sig in sigs[:5]:
        exc = tr.issues[sig]["exc"].most_common(1)
        rep.p(f"{indent}  trace  {n:>5}x {sig}" + (f"   <- {exc[0][0]}" if exc else ""))
    if not sigs:
        active = sum(1 for m in range(lo, hi + 1) if m in tr.active_minutes)
        rep.p(f"{indent}  trace  no Error/Warning lines ({active}/{hi - lo + 1} minutes had any trace output)")
    fams = Counter()
    for m in range(lo, hi + 1):
        fams.update(sw.minutes.get(m, {}))
    for fam, n in fams.most_common(4):
        rep.p(f"{indent}  logs   {n:>5}x error signatures in {fam}")
    qd = {}
    for m in range(lo, hi + 1):
        for key, (drop, delay) in st.queue_minutes.get(m, {}).items():
            d = qd.setdefault(key, [0, 0])
            d[0] += drop
            d[1] = max(d[1], delay)
    for key, (drop, delay) in sorted(qd.items(), key=lambda kv: (-kv[1][0], -kv[1][1]))[:4]:
        rep.p(f"{indent}  stats  queue {key}: dropped {int(drop)}, max delay {int(delay)}")
    vm = [st.vm[m] for m in range(lo, hi + 1) if m in st.vm]
    if vm:
        wa = max(v.get("cpu_wa", 0) for v in vm)
        si = sum(v.get("swap_si", 0) + v.get("swap_so", 0) for v in vm)
        rq = max(v.get("proc_r", 0) for v in vm)
        blk = max(v.get("proc_b", 0) for v in vm)
        rep.p(f"{indent}  stats  vmstat: max iowait {wa:.0f}%, run-queue {rq:.0f}, blocked {blk:.0f}, swap in+out {si:.0f}")
    mem = [st.cu_mem[m] for m in range(lo, hi + 1) if m in st.cu_mem and None not in st.cu_mem[m] and st.cu_mem[m][1]]
    if mem:
        worst = min(100.0 * f / tot for f, tot in mem)
        rep.p(f"{indent}  stats  engine JVM heap free, worst minute: {worst:.0f}%")
    missing = [m for m in range(lo, hi + 1) if st.cu_minutes and m not in st.cu_minutes
               and st.tmin // 60 <= m <= st.tmax // 60]
    if missing:
        rep.p(f"{indent}  stats  NO engine (cu) stats samples for {len(missing)} of {hi - lo + 1} minutes -- engine down or hung")


SEV = {3: "HIGH  ", 2: "MEDIUM", 1: "INFO  "}


def add_finding(findings, sev, bundle, title, evidence):
    findings.append((sev, bundle.label if bundle is not None else "all", title, list(evidence)))


def _avg(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def section_processes(rep, b, args, findings):
    """Per-process CPU, JVM heap, thread dumps, plugin queues with onset/recovery, plugin stop/start
    history, 'blamed vs measured' per plugin. Built from a real case where the
    wireless plugin's SNMP walks were blamed and the numbers pointed at a different plugin's JVM."""
    st, ev = b.stats, b.sweep.events
    rep.sub(b.label + "  --  " + b.name)
    cpus = int(b.props.get("cpu_count") or 0)

    # ---- collection itself
    if b.summary.get("command"):
        rep.p(f"    collected with : {b.summary['command']}")
    el = b.summary.get("elapsed")
    if el is not None:
        rep.p(f"    collection took: {dur(el)}" + ("   <-- SLOW: the box was struggling while this ran" if el > 900 else ""))
        if el > 900:
            add_finding(findings, 2, b, f"Tech-support collection took {dur(el)}",
                        ["A healthy appliance packs a bundle in 1-5 minutes; a long collection is itself a load symptom."])

    # ---- CPU per process
    rows = []
    for comp, pr in st.procs.items():
        if not pr["cpu"]:
            continue
        vals = list(pr["cpu"].values())
        rows.append((_avg(vals), max(vals), comp.decode("latin-1"), pr))
    rows.sort(key=lambda r: -r[0])
    if rows:
        rep.p(f"    busiest processes (today.log, percent of ONE core -- 100 = one core"
              + (f"; this box has {cpus}" if cpus else "") + "):")
    for avg, peak, comp, pr in rows[:8]:
        mins = sorted(pr["cpu"])
        pids = []
        for m in mins:
            pid = pr["pid"].get(m)
            if pid is not None and (not pids or pids[-1][0] != pid):
                pids.append((pid, m))
        line = f"        {comp:<28} avg {avg:>7.0f}%  peak {peak:>7.0f}%  rss {pr['rss'] / 1048576:>6.0f}MB"
        heap = ""
        if pr["max"] and pr["free"]:
            frees = list(pr["free"].values())
            heap = (f"  heap max {pr['max'] / 1048576:.0f}MB, free min {min(frees) / 1048576:.0f}MB "
                    f"avg {_avg(frees) / 1048576:.0f}MB")
        rep.p(line + heap)
        segs = []
        for i, (pid, m0) in enumerate(pids):
            m1 = pids[i + 1][1] if i + 1 < len(pids) else mins[-1] + 1
            seg = [pr["cpu"][m] for m in mins if m0 <= m < m1]
            segs.append((pid.decode("latin-1"), m0 * 60, _avg(seg), len(seg)))
        if len(segs) > 1 and (avg >= 50 or max(x[2] for x in segs) >= 100):
            rep.p("            restarts: " + "  ->  ".join(
                f"pid {p} from {utc_hm(t)} avg {a:.0f}% ({n} min)" for p, t, a, n in segs[-4:]))
        if avg >= 400 or (len(segs) > 1 and max(s[2] for s in segs) >= 400):
            worst = max(segs, key=lambda s: s[2]) if segs else None
            evd = [f"avg {avg:.0f}% = {avg / 100:.1f} cores, peak {peak:.0f}%"
                   + (f" of {cpus} cores on this box" if cpus else "") + f"; rss {pr['rss'] / 1048576:.0f}MB"]
            if heap:
                evd.append(heap.strip())
            thrash = bool(pr["max"] and pr["free"] and min(pr["free"].values()) < 0.12 * pr["max"])
            after = None
            if len(segs) > 1 and worst is not None:
                idx = segs.index(worst)
                if idx + 1 < len(segs):
                    after = segs[idx + 1]
                    evd.append(f"restart at {utc(after[1])}: avg CPU {worst[2]:.0f}% -> {after[2]:.0f}% "
                               f"(pid {worst[0]} -> {after[0]})")
            js = next((j for pid, j in b.jstack.pids.items()
                       if b.ps_plugins.get(pid, ("",))[0] and comp.startswith(b.ps_plugins[pid][0])
                       or (j["plugins"] and comp.startswith(j["plugins"].most_common(1)[0][0]))), None)
            if js:
                if js["gc"]:
                    evd.append(f"{js['gc']} parallel GC threads in its thread dump")
                for (tname, frame), n in js["hot"].most_common(2):
                    if n * 2 >= js["samples"]:
                        evd.append(f"thread '{tname}' on-CPU in {frame} in {n} of {js['samples']} dumps")
            title = f"{comp} is burning {(worst[2] if worst else avg) / 100:.0f} cores"
            if thrash:
                title += " with its JVM heap nearly full -- probable garbage-collection thrash"
            if after and after[2] < 0.25 * worst[2]:
                title += "; a restart cleared it"
            add_finding(findings, 3 if (worst[2] if worst else avg) >= 1000 else 2, b, title, evd)

    # ---- thread dumps
    shown = 0
    for pid, js in sorted(b.jstack.pids.items(), key=lambda kv: -sum(kv[1]["hot"].values())):
        hot = [(k, n) for k, n in js["hot"].most_common(4) if n * 2 >= js["samples"]]
        if not hot or shown >= 4:
            continue
        shown += 1
        who = b.ps_plugins.get(pid, ("", ""))
        name = who[0] or (js["plugins"].most_common(1)[0][0] if js["plugins"] else "?")
        rep.p(f"    thread dumps, plugin JVM '{name}' pid {pid} {who[1]} ({js['samples']} samples, {js['gc']} GC threads):")
        for (tname, frame), n in hot:
            rep.p(f"        on-CPU in {n}/{js['samples']} dumps: thread '{tname}' in {frame}")

    # ---- queues: onset / recovery
    series = defaultdict(list)
    for minute, qs in st.queue_minutes.items():
        for key, (drop, delay) in qs.items():
            series[key].append((minute, drop, delay))
    qrows = []
    for key, pts in series.items():
        late = sorted(m for m, _, d in pts if d >= 60000)
        q = st.queues.get(key)
        if q and (late or q["drop"] > 0):
            qrows.append((q["delay"], key, q, late))
    qrows.sort(key=lambda r: -r[0])
    if qrows:
        rep.p("    queues that backed up (delay >= 60s) or dropped:")
    for delay, key, q, late in qrows[:args.top]:
        span = f"backed up {utc_hm(late[0] * 60)} -> {utc_hm(late[-1] * 60 + 60)} ({len(late)} min)" if late else "no long delay"
        # DB_connections_queue is the pool of 10 DB connections: its "delay" read 23h on a perfectly
        # healthy EM -- it is connection age, not a backlog. Shown, never flagged.
        pool = key.endswith("DB_connections_queue")
        rep.p(f"        {key:<40} peak delay {dur(delay / 1000.0):>8}  peak size {int(q['size']):>8}  "
              f"dropped {int(q['drop']):>8}   " + ("(connection-pool age, not a backlog)" if pool else span))
        if key.endswith(":log-writer"):
            if q["drop"] > 0:
                add_finding(findings, 1, b, f"{key.split(':')[0]} dropped {int(q['drop'])} of its own log lines",
                            ["Its log writer could not keep up -- that plugin's log has holes, and its debug level may be too high."])
            continue
        if not pool and (delay >= 300000 or q["drop"] > 0):
            evd = [f"peak delay {dur(delay / 1000.0)}, peak size {int(q['size'])}, dropped {int(q['drop'])}; {span}"]
            if late:
                end_t = late[-1] * 60
                cleared = []
                for comp, pr in st.procs.items():
                    mins = sorted(pr["pid"])
                    for a, c in zip(mins, mins[1:]):
                        if pr["pid"][a] != pr["pid"][c] and abs(c * 60 - end_t) <= 900:
                            cleared.append((comp.decode("latin-1"), c * 60))
                            break
                if cleared:
                    evd.append("cleared within 15 min of a restart of: "
                               + ", ".join(f"{c} ({utc_hm(t)})" for c, t in cleared[:4]))
            add_finding(findings, 3 if delay >= 1800000 or q["drop"] > 10000 else 2, b,
                        f"Queue {key} backed up to {dur(delay / 1000.0)}"
                        + (f" and dropped {int(q['drop'])} messages" if q["drop"] else ""), evd)

    # ---- blamed vs measured, per plugin
    plug = {}
    for key, q in st.queues.items():
        m = re.match(r"cu:plugin\.(\w+)\.msg$", key)
        if m:
            plug[m.group(1)] = q
    if plug:
        minutes = max(1, len(st.cu_minutes))
        rep.p("    per plugin -- measured load (so a theory can be checked at a glance):")
        rep.p(f"        {'plugin':<22}{'proc avg CPU':>13}{'msgs/s to engine':>18}{'peak queue delay':>18}{'dropped':>10}")
        order = sorted(plug.items(), key=lambda kv: -(kv[1]["delay"] * 1000 + kv[1]["add"]))
        for name, q in order[:12]:
            cpu = [(_avg(pr["cpu"].values())) for c, pr in st.procs.items()
                   if pr["cpu"] and c.decode("latin-1") in (name + "_java", "fstool_" + name)
                   or (pr["cpu"] and c.decode("latin-1").startswith("fstool_" + name + "-"))]
            rep.p(f"        {name:<22}{(f'{sum(cpu):.0f}%' if cpu else '-'):>13}{q['add'] / (minutes * 60.0):>18.1f}"
                  f"{dur(q['delay'] / 1000.0):>18}{int(q['drop']):>10}")
    if b.wireless_controllers is not None:
        rep.p(f"    wireless controllers assigned to this appliance (attached wireless_controllers): {b.wireless_controllers}"
              + ("   <-- none: this box does no WLC polling" if b.wireless_controllers == 0 else ""))

    # ---- plugin stop/start history
    recent_from = (b.coverage()[1] or time.time()) - 14 * 86400      # a plugin log can go back months
    for plugin, evs in sorted(ev.lifecycle.items(), key=lambda kv: -len(kv[1])):
        evs = sorted(e for e in evs if e[0] >= recent_from)
        if not evs:
            continue
        manual = [e for e in evs if e[1] == "stop:stop_stop"]
        starts = [e for e in evs if e[1] == "started"]
        if len(manual) < 2:        # config-change restarts are routine; hand stops are the signal
            continue
        rep.p(f"    plugin '{plugin}': started {len(starts)}x, manual stops {len(manual)}, config restarts "
              f"{sum(1 for e in evs if e[1] == 'stop:stop_config')}  ({utc_hm(evs[0][0])} .. {utc_hm(evs[-1][0])})")
        for t, kind, pid in evs[-6:]:
            rep.p(f"        {utc(t)}  {kind:<18} pid {pid}")
        if len(manual) >= 4:
            add_finding(findings, 2, b, f"Plugin '{plugin}' was stopped by hand {len(manual)} times "
                                        f"between {utc_hm(manual[0][0])} and {utc_hm(manual[-1][0])}",
                        ["Repeated manual stop/start is usually someone working round a problem -- "
                         "compare the stop times with when the queues and CPU recover."])

    # ---- admissions per endpoint
    eps = int(b.props.get("endpoints") or 0)
    if st.adm and eps and st.tmin and st.tmax and st.tmax > st.tmin:
        hours = (st.tmax - st.tmin) / 3600.0
        total = sum(st.adm.values())
        rate = total / eps / hours
        top = ", ".join(f"{k[10:]}={v}" for k, v in st.adm.most_common(4))
        rep.p(f"    admissions: {total} over {hours:.1f}h for {eps} endpoints = {rate:.2f} per endpoint per hour  ({top})"
              + ("   <-- HIGH" if rate >= 2 else ""))
        if rate >= 2:
            add_finding(findings, 3 if rate >= 10 else 2, b,
                        f"Admission rate {rate:.1f} per endpoint per hour ({total} admissions, {eps} endpoints)",
                        [f"by type: {top}", "Normal churn is well under 1/endpoint/hour; see the Live Analyze / "
                                            "Analyze admissions report for the switch/port/MAC breakdown."])


def section_online(rep, bundles, args, findings):
    """Host online state: link-down traps vs. who flips hosts back online. Built from a real
    case: devices unplugged (down trap) came back 'online' via a REMOTE appliance's
    packet engine (agent 'dpi'), the DHCP classifier, and pxGrid re-asserting online=true at the EM."""
    node_addr = {}
    for b in bundles:
        node_addr.update(b.node_addr)

    def where(b, node):
        if node == b.nodeid or node == "0":
            return "local"
        return "REMOTE " + node_addr.get(node, "node " + node)

    for b in bundles:
        ev, tr = b.sweep.events, b.trace
        if not (ev.learn_total or ev.trap_mac or ev.port_downs or tr.online_by_agent or b.hostinfo or tr.fwd_loop):
            continue
        rep.sub(b.label + "  --  " + b.name)

        if ev.trap_mac or ev.port_downs:
            downs = [e for e in ev.trap_mac if e[3] == "down"]
            rep.p(f"    Switch-plugin traps in sw.log, {utc(ev.trap_span[0])} .. {utc_hm(ev.trap_span[1])}: "
                  f"{len(downs)} MAC down, {len(ev.trap_mac) - len(downs)} MAC up, "
                  f"{sum(ev.port_downs.values())} port link-downs on {len(ev.port_downs)} port(s)")
            flappers = [(n, k) for k, n in ev.port_downs.most_common(5) if n >= 5]
            for n, (sw, port) in flappers:
                rep.p(f"        flapping: {sw} port {port} went down {n}x")
            if flappers:
                add_finding(findings, 2 if flappers[0][0] >= 100 else 1, b,
                            f"{len(flappers)} switch port(s) flapping (worst: {flappers[0][0]} link-downs)",
                            [f"{sw} port {port}: {n} link-downs" for n, (sw, port) in flappers])
        if ev.learn_total:
            rep.p(f"    Host learn events in plugin logs: {ev.learn_total}, {utc(ev.learn_span[0])} .. "
                  f"{utc_hm(ev.learn_span[1])} (from {', '.join(f for f, _ in ev.learn_sources.most_common(3))})")
            if ev.learn_total and ev.learn_span[1] - ev.learn_span[0] < 300:
                rep.p("        NOTE: that is a very short window -- learn events are only logged while that plugin's debug is up.")
            asserts, flips = Counter(), Counter()
            for r in ev.learn_rows:
                if r[6] == "true":
                    k = (r[1], where(b, r[2]), r[5] or "-")
                    asserts[k] += 1
                    if r[7] in ("change", "new"):
                        flips[k] += 1
            rep.p("        who reports hosts online (agent plugin, where it runs, admission type):")
            rep.p(f"        {'asserts':>8} {'flipped online':>15}   agent / where / adm")
            for k, n in asserts.most_common(args.top):
                rep.p(f"        {n:>8} {flips[k]:>15}   {k[0]} / {k[1]} / adm={k[2]}")
            remote = [(k, n) for k, n in flips.items() if k[1] != "local" and k[0] not in ("sw", "wireless")]
            if remote:
                add_finding(findings, 2, b,
                            f"{sum(n for _, n in remote)} host(s) flipped to ONLINE by a plugin on another appliance "
                            "with no switch-port evidence",
                            [f"{n}x by {k[0]} on {k[1]} (adm={k[2]})" for k, n in sorted(remote, key=lambda x: -x[1])[:5]]
                            + ["Agent 'dpi' is the packet engine seeing the host's IP on a mirror port -- it is reported even "
                               "when the DPI plugin itself is stopped."])
            fo = ev.false_online()
            if fo:
                rep.p(f"    *** {len(fo)} host(s) brought back ONLINE after a link-down trap with no link-up in between:")
                evd = []
                for t, up_t, mac, sw, r in fo[:args.top * 2]:
                    line = (f"{r[3]} ({mac}) down-trap {utc_hm(t)} on switch {sw} -> online again {utc_hm(r[0])} "
                            f"(+{dur(r[0] - t)}) by {r[1]} on {where(b, r[2])}, adm={r[5] or '-'}"
                            + (f", seen on {r[8]}" if r[8] else "")
                            + (f"; real link-up only at {utc_hm(up_t)}" if up_t else "; no link-up trap at all"))
                    rep.p("        " + line)
                    evd.append(line)
                add_finding(findings, 3, b, f"{len(fo)} host(s) reported ONLINE after a switch link-down trap, "
                                            "by a plugin that cannot see the port", evd[:6])
            elif ev.trap_mac:
                lo = max(ev.trap_span[0], ev.learn_span[0])
                hi = min(ev.trap_span[1], ev.learn_span[1])
                rep.p("    Down-trap -> re-online check: no host was flipped online between a down trap and the next link-up"
                      + (f" (the two logs only overlap for {dur(max(0, hi - lo))})." if hi - lo < 3600 else "."))
        elif ev.trap_mac:
            rep.p("    Down-trap -> re-online check NOT possible: no plugin log in this bundle carries learn events "
                  "(plugin_learn_cb). Raise a plugin's debug on the host's managing appliance during the test.")

        if tr.online_by_agent:
            rep.p(f"    `online` assertions seen in this system's Trace_cu ({tr.learn_events} learn events, "
                  f"{utc_hm(tr.tmin)} .. {utc_hm(tr.tmax)}):")
            span_min = max(1.0, (tr.learn_t1 - tr.learn_t0) / 60.0) if tr.learn_t0 else 1.0
            rep.p(f"        (learn events are only traced at Detailed level: {utc_hm(tr.learn_t0)} .. {utc_hm(tr.learn_t1)}, "
                  f"{span_min:.0f} min)")
            for agent, rec in sorted(tr.online_by_agent.items(), key=lambda kv: -(kv[1]["true"] + kv[1]["false"])):
                total = rec["true"] + rec["false"]
                re_assert = total - rec["changed"]
                tops = ", ".join(f"{h} x{n}" for h, n in rec["hosts"].most_common(3))
                rep.p(f"        {agent:<14} online=true {rec['true']:>6}  online=false {rec['false']:>6}  "
                      f"actually changed {rec['changed']:>6}  hosts {len(rec['hosts']):>6}   busiest: {tops}")
                if rec["true"] >= 500 and re_assert >= 0.7 * total:
                    add_finding(findings, 2, b,
                                f"'{agent}' re-asserts online=true {rec['true']} times "
                                f"({rec['true'] / span_min:.0f}/min) -- {100 * re_assert // total}% change nothing",
                                [f"{len(rec['hosts'])} hosts; busiest {tops}",
                                 "A plugin that keeps stamping online=true holds a host online whatever the switch says -- "
                                 "for pxGrid that means an ISE session that was never closed."])

        if tr.fwd_loop:
            rep.p("    Learn events bouncing between appliances: "
                  + ", ".join(f"{k} x{n}" for k, n in tr.fwd_loop.most_common()))
            if tr.fwd_loop_macs:
                rep.p("        MACs: " + ", ".join(f"{m} x{n}" for m, n in tr.fwd_loop_macs.most_common(6))
                      + f"  ({len(tr.fwd_loop_macs)} distinct)")
            if tr.fwd_loop["reached forwarding limit"] >= 50:
                add_finding(findings, 2, b,
                            f"Learn-event forwarding loop: hop limit hit {tr.fwd_loop['reached forwarding limit']} times",
                            [f"{len(tr.fwd_loop_macs)} MAC(s): " + ", ".join(m for m, _ in tr.fwd_loop_macs.most_common(6)),
                             "No appliance accepts responsibility for these hosts' IPs, so their learn events ping-pong."])

        for ip, h in sorted(b.hostinfo.items()):
            props = h["props"]
            active = next((p for p in props if p[1] == "active"), None)
            rep.p(f"    attached hostinfo: {ip}"
                  + (f"  managed by {h['assigned'][0]} (node {h['assigned'][1]})" if h["assigned"] else ""))
            has_sw = any(p[1] in ("sw_ip", "sw_port", "sw_port_desc", "sw_ipport_desc") for p in props)
            for p in sorted(props):
                if p[0] == 0 or p[1].startswith("In Group") or p[1] in ("last_offsite",):
                    continue
                src = p[3]
                node = src.split("@", 1)[1] if "@" in src else ""
                src_txt = src.replace("@" + node, "@" + node_addr.get(node, node)) if node else src
                mark = "   <== same second the host was marked active" if active and abs(p[0] - active[0]) <= 1 \
                    and p[1] not in ("active", "last_onsite", "_times") else ""
                val = p[2]
                if p[1] == "recent_apps":
                    val = node_addr.get(p[2], p[2])
                rep.p(f"        {utc(p[0])}  {p[1]:<24} {val[:50]:<50} {src_txt}{mark}")
            notes = []
            if not has_sw:
                notes.append("no switch ip/port property left (consistent with the Switch plugin wiping the port on a down trap)")
            onl = [p for p in props if p[1] == "online" and p[2] == "true"]
            for p in onl:
                notes.append(f"online=true held by {p[3]} since {utc(p[0])}")
            if active:
                same = [p for p in props if abs(p[0] - active[0]) <= 1 and p[1] in ("recent_apps", "mac")]
                def _src(p):
                    if p[1] == "recent_apps":
                        return "appliance " + node_addr.get(p[2], p[2])
                    plugin, _, node = p[3].partition("@")
                    return f"{plugin} on {node_addr.get(node, node)}" if node else p[3]
                who = ", ".join(sorted({_src(p) for p in same}))
                notes.append(f"marked active {utc(active[0])}" + (f" -- reported at that second by: {who}" if who else ""))
            for n in notes:
                rep.p(f"        -> {n}")
            if active:
                add_finding(findings, 1, b, f"Attached host {ip}: " + notes[-1], notes[:-1])
        set_at = b.trace_ip_set_at
        if b.trace_ip_list:
            rep.p(f"    per-host tracing configured: {b.trace_ip_list.strip()}"
                  + (f"  (set {utc(set_at)})" if set_at else ""))
    # trace-started-too-late: compare across the whole set (hostinfo in one bundle, audit row in another)
    set_times = [b.trace_ip_set_at for b in bundles if b.trace_ip_set_at]
    actives = [(p[0], ip) for b in bundles for ip, h in b.hostinfo.items() for p in h["props"] if p[1] == "active"]
    if set_times and actives:
        late = [(t, ip) for t, ip in actives if min(set_times) > t + 300]
        if late:
            add_finding(findings, 2, None,
                        f"Per-host tracing was switched on at {utc(min(set_times))} -- AFTER the events it was meant to catch",
                        [f"{ip} was marked active at {utc(t)} ({dur(min(set_times) - t)} earlier)" for t, ip in sorted(late)]
                        + ["The real-time event trail for these hosts is therefore not in the bundles. "
                           "Start `fstool trace_ip` BEFORE reproducing, then collect."])


def section_identity_labels(rep, bundles, args, findings):
    """Placeholder-keyed hosts and the labels stuck on them (see LabelAgg)."""
    shown = False
    for b in bundles:
        if not b.labels.seen:
            continue
        shown = True
        st = b.labels.stats()
        pct = (100.0 * st["placeholder"] / st["hosts"]) if st["hosts"] else 0.0
        rep.p(f"  {b.label}: {st['hosts']:,} host record(s); {st['placeholder']:,} ({pct:.1f}%) keyed with a placeholder "
              f"address (224.0.0.0-247.255.255.255 -- allocated when a host is known by MAC but not by IP)")
        rep.p(f"      of those placeholder-keyed hosts: {st['ph_mac']:,} have a MAC, {st['ph_ip']:,} have a real IP "
              f"(access_ip), {st['ph_switch']:,} are on a switch port")
        if not st["labelled"]:
            rep.p("      none of them carry a label -- Delete Label has nothing to fail on here")
            continue
        rep.p(f"      {st['labelled']:,} carry {st['stuck']:,} label(s) that Delete Label cannot remove; "
              f"{st['labelled_ip']:,} of those hosts have a known IP; {st['retry']:,} have had a delete attempted already")
        if st["labels"]:
            top = ", ".join(f"{n} ({c})" for n, c in st["labels"].most_common(6))
            rep.p(f"      labels stuck: {top}")
        if st["classes"]:
            top = ", ".join(f"{n} ({c})" for n, c in st["classes"].most_common(4))
            rep.p(f"      device classes: {top}")
        rep.p("      worst hosts:")
        for key, h in st["examples"]:
            ident = f"mac {h['mac'] or '?'}"
            if h["ip"]:
                ident += f", ip {h['ip']}"
            if h["switch"]:
                ident += f", on {h['switch']}"
            rep.p(f"        {key}  ({ident})")
            rep.p(f"           {len(h['labels'])} label(s): {', '.join(h['labels'][:6])}"
                  + (f"   [{h['del']} delete attempt(s) recorded]" if h["del"] else ""))
    if not shown:
        rep.p("  No files/tmp/Allhosts.txt in these bundle(s) -- host identity and label state not available.")
        return
    for b in bundles:
        if not b.labels.seen:
            continue
        st = b.labels.stats()
        cause = ("goodies.pl: assign_label resolves a placeholder key to the host's MAC before writing, "
                 "remove_label clears against the placeholder itself and still replies success")
        if st["retry"]:
            add_finding(findings, 3, b,
                        f"Delete Label is failing silently -- {st['retry']:,} host(s) had a delete recorded and still carry the label",
                        [f"{st['labelled']:,} placeholder-keyed host(s) hold {st['stuck']:,} label(s) that cannot be removed",
                         f"{st['labelled_ip']:,} of those hosts have a known IP address, so they are not 'hosts without an IP'",
                         f"cause: {cause}",
                         "a policy that deletes a label to re-trigger a check never re-triggers on these hosts",
                         "worst: " + "; ".join(f"{k} ({h['del']} delete(s), {len(h['labels'])} label(s))"
                                               for k, h in st["examples"][:3])])
        elif st["labelled"]:
            add_finding(findings, 2, b,
                        f"{st['labelled']:,} placeholder-keyed host(s) carry {st['stuck']:,} label(s) that Delete Label cannot remove",
                        [f"no delete has been attempted on them yet in this data -- the failure is latent",
                         f"{st['labelled_ip']:,} of those hosts have a known IP address",
                         f"cause: {cause}"])
        if st["ph_ip"]:
            add_finding(findings, 2, b,
                        f"{st['ph_ip']:,} host(s) keep a placeholder primary key although their real IP is known",
                        [f"{st['ph_switch']:,} of the placeholder-keyed hosts are live on a switch port; "
                         f"{st['ph_mac']:,} have a MAC",
                         "the record is keyed by the placeholder while the real address sits in the access_ip property, "
                         "so `fstool hostinfo <real ip>` answers under the placeholder address",
                         "this is the precondition for the Delete Label failure above, and the product's own reply text "
                         "for this path ('Action not applicable on hosts without an IP address') does not describe them"])


def render_findings(findings):
    rep = Report()
    rep.h("0. Findings (most serious first)")
    if not findings:
        rep.p("  Nothing crossed a threshold. The detail sections below still show what was measured.")
        return rep.lines
    seen = set()
    for sev, who, title, evidence in sorted(findings, key=lambda f: -f[0]):
        if (who, title) in seen:
            continue
        seen.add((who, title))
        rep.p("")
        rep.p(f"  [{SEV[sev].strip()}] {who}: {title}")
        for e in evidence:
            rep.p(f"           - {e}")
    return rep.lines


def build_report(bundles, args):
    rep = Report()
    findings = []
    header = f"bundle-correlate {VERSION} -- {len(bundles)} bundle(s). All times UTC unless marked local."

    # ------------------------------------------------------------------ 1
    rep.h("1. Bundles")
    for i, b in enumerate(bundles, 1):
        p = b.props
        rep.sub(f"[{i}] {b.name}")
        rep.p(f"    role        : {b.role}   (snapshot type={p.get('type', '?')}, "
              f"trace application column={dict(b.trace.app_votes) or 'no trace'})")
        rep.p(f"    node id     : {b.nodeid}")
        rep.p(f"    version     : {p.get('version', '?')}    endpoints={p.get('endpoints', '?')}  "
              f"mem={p.get('mem', '?')}MB  cpus={p.get('cpu_count', '?')}")
        rep.p(f"    timezone    : {p.get('timezonefull') or p.get('timezone', '?')}")
        if p.get("start") and p.get("end"):
            rep.p(f"    asked window: {utc(int(p['start']))} .. {utc(int(p['end']))}  ({dur(int(p['end']) - int(p['start']))})")
        rep.p(f"    Trace_cu    : {len(b.trace.files)} file(s), {b.trace.lines} lines, "
              f"{utc(b.trace.tmin)} .. {utc(b.trace.tmax)}")
        rep.p(f"    today.log   : {b.stats.lines} lines, {utc(b.stats.tmin)} .. {utc(b.stats.tmax)}")
        rep.p(f"    other logs  : {b.sweep.files} file(s), {b.sweep.bytes / 1048576:.0f}MB swept")
        for w in b.warnings:
            rep.p(f"    WARNING     : {w}")
        if not b.props:
            rep.p("    WARNING     : no info/snapshot.properties found -- is this a tech-support bundle?")

    # ------------------------------------------------------------------ 2
    rep.h("2. Time alignment")
    covs = [(b, b.coverage()) for b in bundles]
    for b, (lo, hi) in covs:
        rep.p(f"  {b.label:<34} first stamp {utc(lo)}   last stamp {utc(hi)}")
    have = [(lo, hi) for _, (lo, hi) in covs if lo is not None]
    common = None
    if len(have) == len(bundles) and have:
        lo, hi = max(x[0] for x in have), min(x[1] for x in have)
        if len(bundles) > 1:
            if hi > lo:
                common = (lo, hi)
                rep.p(f"  Common window (every bundle has data): {utc(lo)} .. {utc(hi)}  ({dur(hi - lo)})")
            else:
                rep.p(f"  *** NO OVERLAP: the bundles' data do not cover any common time ({dur(lo - hi)} apart). ***")
                rep.p("      Cross-bundle correlation below will be empty -- collect bundles covering the same incident.")
    for b in bundles:
        tr = b.trace
        notes = []
        if tr.neg_uptime:
            notes.append(f"{tr.neg_uptime} trace lines carry a NEGATIVE engine uptime -- the clock was set back after the engine started")
        for t, kind, detail in tr.clock_events:
            if kind == "clock_step":
                notes.append(f"{utc(t)} clock step: {detail}")
        for local, epoch in b.cmd_clock[:1]:
            rep.p(f"  {b.label}: collection-time clock check: local '{local}' = epoch {epoch} = {utc(epoch)} UTC")
        if notes:
            add_finding(findings, 2, b, f"Clock anomalies on this box ({len(notes)})", notes[:3])
        for n in notes[:8]:
            rep.p(f"  {b.label}: CLOCK WARNING: {n}")
        if len(notes) > 8:
            rep.p(f"  {b.label}: ... {len(notes) - 8} more clock steps")

    # ------------------------------------------------------------------ 3
    ems = [b for b in bundles if b.role == "EM"]
    apps = [b for b in bundles if b.role == "Appliance"]
    rep.h("3. EM <-> appliance connectivity")
    offsets = {}
    app_gaps = {}
    for a in apps:
        hb_int, hb_gaps = find_gaps(a.trace.heartbeats, args.gap)
        em_int, em_gaps = find_gaps(a.trace.emips, args.gap)
        app_gaps[a.index] = (hb_int, hb_gaps, em_int, em_gaps)

    if not ems:
        rep.p("  No EM bundle in this set -- EM-side view unavailable. Appliance-side evidence only.")
    for em in ems:
        peers = em_peer_outages(em.trace)
        rep.sub(f"{em.label}: peers seen in its trace")
        if not peers:
            rep.p("    (no peer session lines in this EM's Trace_cu -- no login failures, no LoginWatchdog checks)")
        for key, info in sorted(peers.items(), key=lambda kv: -len(kv[1]["outages"])):
            outs = info["outages"]
            match = next((a for a in apps if a.nodeid == key), None)
            tag = f"  <== bundle [{match.index}]" if match else ""
            down = sum(o["end"] - o["start"] for o in outs)
            rep.p(f"    peer {key} ({info['addr']}, {info['conntype']}): {len(outs)} outage window(s), "
                  f"{sum(o['fails'] for o in outs)} failed logins, ~{dur(down)} failing; LoginWatchdog "
                  f"up={info['watchdog']['wd_up']} down={info['watchdog']['wd_down']}; "
                  f"capacity-missing warnings={info['capacity_missing']}{tag}")
            ss = info["sess_starts"]
            if ss:
                rep.p(f"         session came (back) up {len(ss)}x: " + ", ".join(utc_hm(t) for t in ss[-6:]))
            if outs:
                why = Counter()
                for o in outs:
                    why.update(o["reasons"])
                add_finding(findings, 3 if len(outs) >= 3 or down >= 3600 else 2, em,
                            f"EM could not hold a session to {key} ({info['addr']}): {len(outs)} outage window(s), "
                            f"~{dur(down)} failing",
                            [", ".join(f"{r} x{n}" for r, n in why.most_common(3)),
                             "See section 3 for each episode with the appliance-side view and a verdict."])
            reg = regularity([o["start"] for o in outs])
            if reg:
                mean, cv = reg
                flag = "REGULAR SPACING" if cv <= 0.4 else "irregular"
                rep.p(f"         outage starts every {dur(mean)} on average (CV {cv * 100:.0f}%) -- {flag}")
            if len(outs) > args.top:
                rep.p(f"         (most recent {args.top} of {len(outs)})")
            for o in outs[-args.top:]:
                reasons = ", ".join(f"{r} x{n}" for r, n in o["reasons"].most_common(3))
                rec = f"recovered {utc_hm(o['recovered'])}" if o["recovered"] else "no recovery seen in trace"
                rep.p(f"         {utc(o['start'])} -> {utc_hm(o['end'])} ({dur(o['end'] - o['start'])}, "
                      f"{o['fails']} fails, TLS reached peer {o['tls_ok']}x) {rec}")
                rep.p(f"             reason: {reasons}")

        # ---- pair with each appliance bundle
        for a in apps:
            info = peers.get(a.nodeid)
            hb_int, hb_gaps, em_int, em_gaps = app_gaps[a.index]
            rep.sub(f"{em.label}  x  {a.label}")
            if info is None:
                rep.p(f"    The EM's trace never names node {a.nodeid} in a session/login line. Either the link was healthy")
                rep.p("    for the whole EM trace window, or this appliance does not belong to this EM.")
                outs = []
            else:
                outs = info["outages"]
            # clock offset estimate. Best evidence: the same login seen from both ends -- the
            # appliance logs "login success of admin@<EM ip>" within milliseconds of the EM's
            # session thread for that appliance coming alive. Fallback: outage start vs emIps gap.
            est = None
            starts = sorted(info["sess_starts"]) if info else []
            logins = [t for t, _, ip in a.trace.app_logins if not a.trace.em_ips or ip in a.trace.em_ips]
            if starts and logins:
                deltas = []
                for ta in logins:
                    te = min(starts, key=lambda x: abs(x - ta))
                    if abs(ta - te) < 6 * 3600:
                        deltas.append(ta - te)
                if deltas:
                    med = median(deltas)
                    support = sum(1 for d in deltas if abs(d - med) <= 5)
                    if support >= 2 or len(deltas) == 1:
                        est = (med, support, "+/-1s, matched EM logins")
            if est is None and outs and em_gaps:
                bins = Counter()
                for o in outs:
                    for g0, _ in em_gaps:
                        d = g0 - o["start"]
                        if abs(d) < 6 * 3600:
                            bins[int(round(d / 60.0))] += 1
                if bins:
                    best, support = bins.most_common(1)[0]
                    if support >= 2 or (len(outs) == 1 and len(em_gaps) == 1):
                        est = (best * 60, support, "+/-60s, matched outages")
            if est and abs(est[0]) > (5 if "1s" in est[2] else 90):
                offsets[a.index] = est[0]
                rep.p(f"    CLOCK OFFSET: the appliance clock reads {est[0]:+.1f}s ({dur(est[0])}) against the EM clock "
                      f"({est[1]} matching event(s), resolution {est[2]}). Applied to everything below.")
            elif est:
                rep.p(f"    Clocks agree: measured offset {est[0]:+.1f}s ({est[1]} matching event(s), resolution {est[2]}).")
            else:
                rep.p("    Clock offset NOT measurable (needs a login or an outage seen from both sides) -- clocks treated as equal.")
            ident = a.trace.em_identity.most_common(1)
            if ident:
                (em_node, em_name), _ = ident[0]
                same = "matches this EM bundle" if em_node == em.nodeid else f"DOES NOT match this EM bundle ({em.nodeid})"
                rep.p(f"    The appliance says its EM is node {em_node} ('{em_name}') -- {same}.")
            off = offsets.get(a.index, 0.0)

            acov = a.coverage()
            rows = []
            used = set()
            for o in outs:
                s, e = o["start"] + off, (o["recovered"] or o["end"]) + off
                hit = [i for i, (g0, g1) in enumerate(em_gaps) if g0 <= e + 120 and g1 >= s - 120]
                used.update(hit)
                rows.append((o["start"], o, [em_gaps[i] for i in hit]))
            for i, g in enumerate(em_gaps):
                if i not in used:
                    rows.append((g[0] - off, None, [g]))
            rows.sort(key=lambda r: r[0])
            total_rows = len(rows)
            if common:
                rows = [r for r in rows if common[0] - 300 <= r[0] <= common[1] + 300
                        or (r[1] and r[1]["end"] >= common[0] and r[1]["start"] <= common[1])]
            if not rows:
                rep.p("    No disconnects seen from either side inside the common window."
                      + (f" ({total_rows} outside it -- see each system's own evidence.)" if total_rows else ""))
            else:
                rep.p(f"    {len(rows)} disconnect episode(s) inside the common window"
                      + (f" ({total_rows - len(rows)} more outside it)" if total_rows > len(rows) else "")
                      + (f"; showing the most recent {args.top}" if len(rows) > args.top else "") + ".")
                reg = regularity([r[0] for r in rows])
                if reg:
                    rep.p(f"    Episodes start every {dur(reg[0])} on average (CV {reg[1] * 100:.0f}%) -- "
                          + ("REGULAR SPACING: look for a timer, a scheduled job or a keepalive/idle timeout"
                             if reg[1] <= 0.4 else "irregular"))
            first_n = max(0, len(rows) - args.top)
            for n, (t_ref, o, gaps) in enumerate(rows[first_n:], first_n + 1):
                rep.p("")
                rep.p(f"    #{n}  {utc(t_ref)} UTC")
                if o:
                    reasons = ", ".join(f"{r} x{c}" for r, c in o["reasons"].most_common(2))
                    rep.p(f"      EM side : login failing {utc_hm(o['start'])} -> {utc_hm(o['end'])} "
                          f"({o['fails']} fails; {reasons}; TLS reached peer {o['tls_ok']}x)")
                else:
                    rep.p("      EM side : nothing logged (no login failure in the EM trace at this time)")
                tl = t_ref + off
                if acov[0] is None or tl < acov[0] or tl > acov[1]:
                    rep.p(f"      APP side: outside the appliance bundle's coverage ({utc(acov[0])} .. {utc(acov[1])})")
                    verdict = "cannot say -- the appliance bundle holds nothing for this moment"
                else:
                    for g0, g1 in gaps:
                        rep.p(f"      APP side: no EM 'emIps' message received {utc_hm(g0)} -> {utc_hm(g1)} "
                              f"({dur(g1 - g0)}; normally every {dur(em_int)})")
                    win0, win1 = tl - 120, (gaps[0][1] if gaps else tl) + 120
                    restarts = [ev for ev in a.trace.clock_events if ev[1] == "restart" and win0 <= ev[0] <= win1]
                    hbs = [g for g in hb_gaps if g[0] <= win1 and g[1] >= win0]
                    silent = [m for m in range(int(win0 // 60), int(win1 // 60) + 1) if m not in a.trace.active_minutes]
                    relog = [x for x in a.trace.app_logins if win0 <= x[0] <= win1 + 600]
                    if relog:
                        rep.p(f"      APP side: EM logged back in at {utc_hm(relog[0][0])} ({relog[0][1]}@{relog[0][2]})"
                              + (f", {len(relog)} logins in this episode" if len(relog) > 1 else ""))
                    for ev in restarts:
                        rep.p(f"      APP side: ENGINE RESTART at {utc_hm(ev[0])} -- {ev[2]}")
                    for wt, wtext in a.watchdog_restarts():
                        if win0 - 600 <= wt <= win1:
                            rep.p(f"      APP side: watch_dog {utc_hm(wt)} -- {wtext}")
                            restarts = restarts or [(wt, "restart", wtext)]
                    for g0, g1 in hbs:
                        rep.p(f"      APP side: heartbeat timer silent {utc_hm(g0)} -> {utc_hm(g1)} ({dur(g1 - g0)})")
                    if restarts:
                        verdict = "appliance engine restarted -- the disconnect is a symptom; look at why the engine went down"
                    elif hbs or len(silent) > 2:
                        verdict = ("appliance engine stalled or the box was down (no heartbeat / no trace output) -- "
                                   "check memory, iowait and the kernel log lines below")
                    elif gaps and o:
                        r = " ".join(o["reasons"])
                        if "NoRouteToHost" in r or "ConnectException" in r or "SocketTimeout" in r or "UnknownHost" in r:
                            verdict = ("appliance engine stayed up and kept heartbeating while the EM could not reach it -- "
                                       "network path / firewall / DNS between EM and appliance")
                        else:
                            verdict = ("appliance engine stayed up; the EM session itself failed -- look at the login-failure "
                                       "reason (TLS/cert, auth, EM-side load)")
                    elif gaps:
                        verdict = ("appliance stopped hearing from the EM but the EM logged no failure -- EM-side stall, or the "
                                   "EM bundle's trace does not cover this moment")
                    else:
                        verdict = ("EM failed to log in, yet the appliance kept receiving EM messages -- likely a second "
                                   "session/EM (HA pair) or a login-only fault")
                rep.p(f"      VERDICT : {verdict}")
                context_block(rep, em, t_ref, args.context)
                context_block(rep, a, t_ref, args.context, offset=off)

    # appliance-only view (also shown when there IS an EM, as the raw evidence)
    for a in apps:
        hb_int, hb_gaps, em_int, em_gaps = app_gaps[a.index]
        rep.sub(f"{a.label}: own liveness evidence")
        rep.p(f"    EM addresses it was told about: {', '.join(sorted(a.trace.em_ips)) or 'none seen'}")
        if em_int is None:
            rep.p("    emIps messages from the EM: fewer than 3 in the trace -- cannot judge gaps")
        else:
            rep.p(f"    emIps messages from the EM: {len(a.trace.emips)}, normally every {dur(em_int)}, {len(em_gaps)} gap(s)")
            if len(em_gaps) > args.top:
                rep.p(f"        (most recent {args.top})")
            for g0, g1 in em_gaps[-args.top:]:
                rep.p(f"        gap {utc(g0)} -> {utc_hm(g1)} ({dur(g1 - g0)})")
            reg = regularity([g[0] for g in em_gaps])
            if reg:
                rep.p(f"        gaps start every {dur(reg[0])} on average (CV {reg[1] * 100:.0f}%) -- "
                      f"{'REGULAR SPACING' if reg[1] <= 0.4 else 'irregular'}")
        if hb_int is None:
            rep.p("    heartbeats: fewer than 3 in the trace (the 'application' category may not be at Detailed level)")
        else:
            rep.p(f"    heartbeats: {len(a.trace.heartbeats)}, normally every {dur(hb_int)}, {len(hb_gaps)} gap(s)")
            if len(hb_gaps) > args.top:
                rep.p(f"        (most recent {args.top})")
            for g0, g1 in hb_gaps[-args.top:]:
                rep.p(f"        gap {utc(g0)} -> {utc_hm(g1)} ({dur(g1 - g0)})")
        by_src = defaultdict(list)
        for t, user, ip in a.trace.app_logins:
            by_src[(user, ip)].append(t)
        for (user, ip), ts in sorted(by_src.items(), key=lambda kv: -len(kv[1])):
            who = " (its EM)" if ip in a.trace.em_ips else ""
            rep.p(f"    logins received from {user}@{ip}{who}: {len(ts)}  -- every fresh login is a session that had to be rebuilt")
            reg = regularity(ts)
            if reg:
                rep.p(f"        every {dur(reg[0])} on average (CV {reg[1] * 100:.0f}%) -- "
                      + ("REGULAR SPACING" if reg[1] <= 0.4 else "irregular"))
            rep.p("        most recent: " + ", ".join(utc_hm(t) for t in ts[-6:]))
        by_peer = defaultdict(list)
        for c in a.trace.app_closes:
            by_peer[(c[1], c[2])].append(c)
        for (node, ip), cs in sorted(by_peer.items(), key=lambda kv: -len(kv[1])):
            reasons = Counter(c[4] or "no exception logged" for c in cs)
            life = median([c[3] for c in cs]) / 1000.0
            rep.p(f"    appliance-to-appliance connection to node {node} ({ip}) closed {len(cs)}x; typical connection "
                  f"lifetime {dur(life)}; " + ", ".join(f"{r} x{n}" for r, n in reasons.most_common(3)))
            reg = regularity([c[0] for c in cs])
            if reg:
                rep.p(f"        every {dur(reg[0])} on average (CV {reg[1] * 100:.0f}%) -- "
                      + ("REGULAR SPACING" if reg[1] <= 0.4 else "irregular") + f";  last {utc_hm(cs[-1][0])}")
        for node, ts in sorted(a.trace.iac_reopen.items(), key=lambda kv: -len(kv[1])):
            rep.p(f"    'Connection to node {node} is closed. Reopening...' {len(ts)}x, {utc_hm(min(ts))} .. {utc_hm(max(ts))}")
        for ip, sigs in a.trace.session_issues.items():
            rep.p(f"    errors raised on the message session with {ip}:")
            for sig, n in sigs.most_common(5):
                rep.p(f"        {n:>6}x {sig}")
        # inter-appliance message counters going quiet
        for peer, mins in sorted(a.stats.iac.items()):
            ms = sorted(mins)
            quiet = [(x * 60, y * 60) for x, y in zip(ms, ms[1:]) if y - x > 5]
            who = "the EM in this set" if any(e.nodeid == peer for e in ems) else (
                "an appliance in this set" if any(x.nodeid == peer for x in apps) else "not in this set")
            rep.p(f"    message counters to/from node {peer} ({who}): active {len(ms)} min, {len(quiet)} quiet spell(s) >5min")
            for g0, g1 in quiet[-5:]:
                rep.p(f"        quiet {utc(g0)} -> {utc_hm(g1)} ({dur(g1 - g0)})")

    # ------------------------------------------------------------------ 4
    rep.h("4. Per-bundle health: engine, memory, queues, host")
    for b in bundles:
        tr, st = b.trace, b.stats
        rep.sub(b.label + "  --  " + b.name)
        restarts = [e for e in tr.clock_events if e[1] == "restart"]
        rep.p(f"    engine restarts seen in trace: {len(restarts)}")
        if len(restarts) > args.top:
            rep.p(f"        (most recent {args.top})")
        for t, _, detail in restarts[-args.top:]:
            rep.p(f"        {utc(t)}  {detail}")
        gaps, pids = st.cu_gaps()
        if pids:
            rep.p(f"    engine (cu) process id changed {len(pids)}x in today.log:")
            for t, old, new in pids[:args.top]:
                rep.p(f"        {utc(t)}  pid {old} -> {new}")
        if gaps:
            rep.p(f"    minutes with NO engine stats at all: {len(gaps)} spell(s)")
            for g0, g1 in gaps[:args.top]:
                rep.p(f"        {utc(g0)} -> {utc_hm(g1)} ({dur(g1 - g0)})")
        wd = sorted(b.host.get("watchdog") or [])
        cov0 = (b.coverage()[0] or 0) - 3600
        recent = [e for e in wd if e[0] >= cov0]
        rep.p(f"    watch_dog.log: {len(wd)} restart/stall line(s) in total, {len(recent)} inside this bundle's data window")
        forced = [e for e in recent if "stalled" in e[1] or "clock moved backwards" in e[1]]
        if forced:
            add_finding(findings, 3, b, f"The watchdog force-restarted the engine {len(forced)}x in the data window",
                        [f"{utc(t)}  {text}" for t, text in forced[-4:]])
        for t, text in (recent or wd[-5:])[-args.top:]:
            rep.p(f"        {utc(t)}  {text}" + ("" if t >= cov0 else "   (before the window)"))
        if tr.min_free:
            pct, t, free, total = tr.min_free
            rep.p(f"    engine JVM heap: lowest free {pct:.0f}% ({free}MB of {total}MB) at {utc(t)}"
                  + ("   <-- LOW" if pct < 10 else ""))
        if st.vm:
            vals = list(st.vm.values())
            wa = max(v.get("cpu_wa", 0) for v in vals)
            swap_min = sum(1 for v in vals if v.get("swap_si", 0) + v.get("swap_so", 0) > 0)
            rq = max(v.get("proc_r", 0) for v in vals)
            cpus = int(b.props.get("cpu_count") or 0)
            rep.p(f"    host vmstat over {len(vals)} min: max iowait {wa:.0f}%"
                  + ("  <-- HIGH" if wa >= 20 else "")
                  + f", max run-queue {rq:.0f}" + (f" on {cpus} cpus" if cpus else "")
                  + ("  <-- CPU SATURATED" if cpus and rq > 2 * cpus else "")
                  + f", swapping in {swap_min} min" + ("  <-- SWAPPING" if swap_min > len(vals) * 0.05 else ""))
        bad = [(k, q) for k, q in st.queues.items() if q["drop"] > 0 or q["delay"] >= 5000]
        bad.sort(key=lambda kv: (-kv[1]["drop"], -kv[1]["delay"]))
        rep.p(f"    queues with drops or delay>=5000: {len(bad)} of {len(st.queues)}")
        for k, q in bad[:args.top]:
            rep.p(f"        {k:<44} dropped {int(q['drop']):>9}  max delay {int(q['delay']):>8}  max size {int(q['size']):>8}"
                  + (f"  first drop {utc_hm(q['t_drop'])}" if q["t_drop"] else "")
                  + ("  (connection-pool age, not a backlog)" if k.endswith("DB_connections_queue") else ""))
        for plug, mins in sorted(st.plugin_down.items(), key=lambda kv: -len(kv[1]))[:args.top]:
            rep.p(f"    plugin '{plug}' reported not connected to the engine for {len(mins)} min")
        if st.adm:
            rep.p("    admissions (today.log learn.adm.*): "
                  + ", ".join(f"{k[10:]}={v}" for k, v in st.adm.most_common(6)))
        for base in ("uptime.log", "top.log"):
            text = b.host.get(base, "")
            for line in text.splitlines():
                if "load average" in line or line.startswith(("MiB Mem", "MiB Swap", "KiB Mem", "KiB Swap", "%Cpu")):
                    rep.p(f"    {base[:-4]:<7}: {line.strip()}")
            if base == "uptime.log" and text:
                break
        for line in b.host.get("df.log", "").splitlines():
            m = re.search(r"\s(\d+)%\s+(/\S*)$", line)
            if m and int(m.group(1)) >= 85:
                rep.p(f"    disk   : {m.group(2)} is {m.group(1)}% full   <-- HIGH")
        if b.relinfo:
            rep.p("    largest database relations: "
                  + ", ".join(f"{name} {kb // 1024}MB" for kb, _, name in b.relinfo[:6]))
        if b.db_events:
            rep.p("    db events sample (group/event, up to 1000 rows): "
                  + ", ".join(f"{k} x{v}" for k, v in b.db_events.most_common(8)))
        es = [ln for ln in b.errors_summary.splitlines() if ln.startswith("|") and "Item" not in ln and "---" not in ln]
        for ln in es[:10]:
            rep.p(f"    tech-support errors table: {ln.strip()}")

    # ------------------------------------------------------------------ 5
    rep.h("5. Processes, JVM heap, plugin queues, plugin restarts")
    for b in bundles:
        section_processes(rep, b, args, findings)

    # ------------------------------------------------------------------ 6
    rep.h("6. Host online state: link-down traps, admissions, who brings hosts online")
    before = len(rep.lines)
    section_online(rep, bundles, args, findings)
    if len(rep.lines) == before:
        rep.p("  No trap, learn-event or attached-hostinfo evidence in this set. For a false-online case collect with")
        rep.p("  `-p sw` from the appliance that manages the switch AND raise a plugin's debug on the host's managing appliance.")

    # ------------------------------------------------------------------ 7
    rep.h("7. Host identity and labels: placeholder-keyed hosts, labels that cannot be deleted")
    section_identity_labels(rep, bundles, args, findings)

    # ------------------------------------------------------------------ 8
    rep.h("8. Trace_cu errors and warnings (grouped)")
    for b in bundles:
        tr = b.trace
        rep.sub(f"{b.label}: {sum(r['count'] for r in tr.issues.values())} Error/Warning lines, "
                f"{len(tr.issues)} distinct")
        ranked = sorted(tr.issues.items(), key=lambda kv: -kv[1]["count"])
        for sig, r in ranked[:args.top * 2]:
            exc = r["exc"].most_common(1)
            rep.p(f"    {r['count']:>7}x {sig}")
            rep.p(f"             {utc_hm(r['first'])} .. {utc_hm(r['last'])}" + (f"   exception: {exc[0][0]}" if exc else ""))
        if tr.err_minutes:
            worst = tr.err_minutes.most_common(3)
            rep.p("    busiest error minutes: " + ", ".join(f"{utc_hm(m * 60)} ({n})" for m, n in worst))
        chatty = [(n, c, lv) for (c, lv), n in tr.cat_level.items()]
        chatty.sort(reverse=True)
        rep.p("    busiest trace categories: " + ", ".join(f"{c}|{lv} {n}" for n, c, lv in chatty[:6]))

    # ------------------------------------------------------------------ 6
    rep.h("9. Error signatures in every other log (plugin, daemon, watchdog, syslog, kernel)")
    for b in bundles:
        sw = b.sweep
        rep.sub(f"{b.label}: {sw.files} files, {sw.bytes / 1048576:.0f}MB")
        by_sig = defaultdict(list)
        day0 = int((b.window_start() - 3600) // 86400)
        for (fam, signame, subkey), r in sw.hits.items():
            r["recent"] = sum(n for d, n in r["days"].items() if d >= day0)
            by_sig[signame].append((r["recent"], r["count"], fam, subkey, r))
        rep.p(f"    'in window' = stamped on or after {utc(day0 * 86400)[:10]}; older hits are history, listed after.")
        order = [s for s, _ in SIGNATURES]
        for signame in order:
            items = sorted(by_sig.get(signame, []), key=lambda x: (-x[0], -x[1]))
            if not items:
                continue
            rep.p(f"    [{signame}] {sum(i[0] for i in items)} in window, {sum(i[1] for i in items)} in total, "
                  f"{len(items)} place(s)")
            for recent, count, fam, subkey, r in items[:args.top if signame != 'java-exception' else args.top * 2]:
                span = f"{utc_hm(r['first'])} .. {utc_hm(r['last'])}" if r["first"] else "no timestamp on these lines"
                rep.p(f"        {recent:>7} in window / {count:>7} total  {fam}" + (f"  {subkey}" if subkey else "")
                      + f"   [{span}]")
                rep.p(f"                 e.g. {(r['recent_sample'] or r['sample'])[:200]}")

    # ------------------------------------------------------------------ 7
    if len(bundles) > 1 and common:
        rep.h("10. Minutes where more than one system was in trouble at once")
        lo, hi = int(common[0] // 60), int(common[1] // 60)
        scored = []
        for m in range(lo, hi + 1):
            per = []
            for b in bundles:
                mo = m + int(offsets.get(b.index, 0) // 60)
                n = b.trace.err_minutes.get(mo, 0) + sum(b.sweep.minutes.get(mo, {}).values())
                n += sum(int(d[0]) for d in b.stats.queue_minutes.get(mo, {}).values())
                per.append(n)
            if sum(1 for n in per if n > 0) >= 2:
                scored.append((min(n for n in per if n > 0), m, per))
        scored.sort(reverse=True)
        if not scored:
            rep.p("  None -- no minute in the common window had errors on two systems at once.")
        for _, m, per in scored[:args.top]:
            rep.p(f"  {utc(m * 60)}  " + "  ".join(f"[{b.label}: {n}]" for b, n in zip(bundles, per)))
    return "\n".join([header] + render_findings(findings) + rep.lines) + "\n"



# ----------------------------------------------------------------------
# --roaming <mac|ip>: where one device was seen connected, from a bundle's
# logs (Upload & Review view; David's ask 2026-09-18). Only as complete as
# the logs: at baseline debug the Switch plugin logs trap-driven MAC
# add/remove per port but not every admission, so it can be sparse.
# ----------------------------------------------------------------------

RX_RM_SW_ADD = re.compile(rb"sw_add_mac:\d+:\[[^\]]*\]:\[keys:([0-9.]+),([0-9.]+):([^,\]]+),([0-9a-f]{12})\]")
RX_RM_SW_DEL = re.compile(rb"deleting mac\[([0-9a-f]{12})\] from ipport\[([0-9.]+):([^\s\]]+)")
RX_RM_SW_TRAP = re.compile(rb"\[keys:([0-9.]+)[^\]]*\]:\d+: mac\[([0-9a-f]{12})\] reporting trap \[(up|down)\]")
RX_RM_SW_IPPORT = re.compile(rb"ip\[([0-9.]+)\],? port\[([^\]]+)\]")
RX_RM_LEARN_ENTRY = re.compile(rb"\{name=(sw_ip|sw_port|sw_port_desc|wifi_ap_name|wifi_ssid|wifi_bssid|adm),value=([^}]*)\}")
RX_RM_TRACE_FIELD = re.compile(rb"fieldName=(sw_ip|sw_port|sw_port_desc|wifi_ap_name|wifi_ssid|wifi_bssid), value=([^,]*),")
RX_RM_WIFI_CLEAR = re.compile(rb"wifi_clear_client:\d+: wifi_ip \[[^\]]*\] ip \[([0-9.]*)\] mac \[([0-9a-f]*)\]")


def _rm_time(line):
    m = RX_EV_EPOCH.match(line)
    if m:
        return int(m.group(2))
    m = RX_TS_TRACE.search(line[:60])
    if m:
        return int(m.group(1)) // 1000
    return None


def bundle_roaming(paths, key, top=400):
    key = key.strip().lower()
    mac = re.sub(r"[^0-9a-f]", "", key) if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", key) else None
    if mac is not None and len(mac) != 12:
        return {"error": f"'{key}' is neither an IPv4 address nor a MAC address"}
    if mac:
        variants = [mac.encode(), ":".join(mac[i:i + 2] for i in range(0, 12, 2)).encode(),
                    "-".join(mac[i:i + 2] for i in range(0, 12, 2)).encode(), mac.upper().encode(),
                    ":".join(mac[i:i + 2] for i in range(0, 12, 2)).upper().encode()]
    else:
        variants = [key.encode()]
    raw = []            # (t, kind, sw_or_ap, port_or_ssid, event, source family)
    seen = set()
    sources = Counter()
    lines_hit = 0

    def add(t, kind, a, b, event, fam):
        nonlocal lines_hit
        if t is None or not a:
            return
        k = (t, kind, a, b or "", event)
        if k in seen:
            return
        seen.add(k)
        raw.append((t, kind, a, b or "", event, fam))
        sources[fam] += 1

    def scan(rel, fobj):
        nonlocal lines_hit
        fam = family(rel)
        carry = b""
        while True:
            chunk = fobj.read(4 * 1024 * 1024)
            if not chunk:
                break
            data = carry + chunk
            cut = data.rfind(b"\n")
            if cut < 0:
                carry = data[-65536:]
                continue
            carry = data[cut + 1:]
            body = data[:cut + 1]
            starts = set()
            for v in variants:
                pos = body.find(v)
                while pos >= 0:
                    starts.add(body.rfind(b"\n", 0, pos) + 1)
                    nl = body.find(b"\n", pos)
                    if nl < 0:
                        break
                    pos = body.find(v, nl + 1)
            for ls in sorted(starts):
                le = body.find(b"\n", ls)
                line = body[ls:le if le >= 0 else len(body)][:6000]
                lines_hit += 1
                handle(line, fam)

    def handle(line, fam):
        t = _rm_time(line)
        d = lambda b: b.decode("utf-8", "replace").strip()
        if b"plugin_learn_cb" in line:
            ent = dict((a.decode(), d(b)) for a, b in RX_RM_LEARN_ENTRY.findall(line))
            if ent.get("sw_ip") and ent.get("sw_port"):
                add(t, "switch", ent["sw_ip"], ent["sw_port"], "seen (learn event" + (", adm=" + ent["adm"] if ent.get("adm") else "") + ")", fam)
            if ent.get("wifi_ap_name"):
                add(t, "ap", ent["wifi_ap_name"], ent.get("wifi_ssid", ""), "seen (learn event" + (", adm=" + ent["adm"] if ent.get("adm") else "") + ")", fam)
            return
        if b"|" in line[:40] and (b"fieldName=sw_" in line or b"fieldName=wifi_" in line):
            f = dict((a.decode(), d(b)) for a, b in RX_RM_TRACE_FIELD.findall(line))
            if f.get("sw_ip") and f.get("sw_port"):
                add(t, "switch", f["sw_ip"], f["sw_port"], "seen (EM/appliance trace)", fam)
            if f.get("wifi_ap_name"):
                add(t, "ap", f["wifi_ap_name"], f.get("wifi_ssid", ""), "seen (EM/appliance trace)", fam)
            return
        m = RX_RM_SW_ADD.search(line)
        if m:
            add(t, "switch", d(m.group(2)), d(m.group(3)), "connected (link-up trap)", fam)
            return
        m = RX_RM_SW_DEL.search(line)
        if m:
            add(t, "switch", d(m.group(2)), d(m.group(3)), "disconnected (removed from port)", fam)
            return
        m = RX_RM_SW_TRAP.search(line)
        if m:
            add(t, "switch", d(m.group(1)), "", "trap " + d(m.group(3)), fam)
            return
        m = RX_RM_WIFI_CLEAR.search(line)
        if m:
            add(t, "ap", "(wireless client cleared)", "", "disconnected (client cleared)", fam)
            return
        m = RX_RM_SW_IPPORT.search(line)
        if m and fam.startswith("log/plugin/sw/") or (m and "mac_track" in fam):
            add(t, "switch", d(m.group(1)), d(m.group(2)), "seen (switch plugin)", fam)

    def wanted(rel):
        return (rel.startswith(FS + "log/") and not SWEEP_EXCLUDE_RX.search(rel)) or \
            (rel.startswith(FS + "log/") and "/Trace_cu_" in rel) or rel.startswith("files/tmp/")

    for path in paths:
        if os.path.isdir(path):
            for dirpath, _, files in os.walk(path):
                for fn in files:
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, path).replace(os.sep, "/")
                    rel = rel.split("/", 1)[1] if not os.path.isdir(os.path.join(path, "info")) and "/" in rel else rel
                    if wanted(rel):
                        with open(full, "rb") as f:
                            scan(rel, f)
        else:
            with tarfile.open(path, "r|*") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    rel = rel_member(member.name)
                    if rel and wanted(rel):
                        fobj = tar.extractfile(member)
                        if fobj is not None:
                            scan(rel, fobj)

    raw.sort()
    nodes = {}
    events = []
    for t, kind, a, b, event, fam in raw:
        k = kind + ":" + a + "/" + b
        n = nodes.get(k)
        if n is None and event.startswith("disconnected"):
            events.append({"time": utc(t), "t": t, "kind": kind, "label": a, "sub": b, "event": event + " -- " + fam})
            continue                      # a bare disconnect is a timeline event, not a place
        if n is None:
            n = nodes[k] = {"key": k, "kind": kind, "label": a, "sub": b, "count": 0, "first": t, "last": t,
                            "seconds": 0, "still_connected": False, "sources": Counter()}
        if not event.startswith("disconnected"):
            n["count"] += 1
        n["first"] = min(n["first"], t)
        n["last"] = max(n["last"], t)
        n["sources"][fam] += 1
        events.append({"time": utc(t), "t": t, "kind": kind, "label": a, "sub": b, "event": event + " -- " + fam})
    out = sorted(nodes.values(), key=lambda n: (-n["count"], -n["last"]))
    for n in out:
        n["first_display"] = utc(n["first"])
        n["last_display"] = utc(n["last"])
        n["sources"] = ", ".join(f"{f} x{c}" for f, c in n["sources"].most_common(3))
    return {"key": key, "nodes": out, "events": events[-top:], "rows": lines_hit,
            "from": utc(raw[0][0]) if raw else "-", "to": utc(raw[-1][0]) if raw else "-",
            "sources": ", ".join(f"{f} x{c}" for f, c in sources.most_common(6)) or "no matching lines",
            "note": "From the bundle's logs only: trap-driven MAC add/remove on switch ports, plugin learn events, "
                    "trace learn events, wireless client clears. Sparse unless plugin debug was raised."}


def main():
    ap = argparse.ArgumentParser(description="Correlate Forescout tech-support bundles (EM + appliance) offline.")
    ap.add_argument("bundles", nargs="+", help=".tgz/.tar.gz bundle, or an unpacked bundle directory")
    ap.add_argument("-g", "--gap", type=int, default=150, help="minimum silence (s) that counts as a gap [150]")
    ap.add_argument("-c", "--context", type=int, default=120, help="seconds of context either side of a disconnect [120]")
    ap.add_argument("-n", "--top", type=int, default=10, help="rows per section [10]")
    ap.add_argument("--json", action="store_true", help="emit {bundles:[...], output:'...'} instead of plain text")
    ap.add_argument("--roaming", metavar="MAC_OR_IP", help="instead of a report: where this one device was seen connected (JSON)")
    args = ap.parse_args()

    if args.roaming:
        for path in args.bundles:
            if not os.path.exists(path):
                print(json.dumps({"error": f"'{path}' does not exist."}))
                return 2
        print(json.dumps(bundle_roaming(args.bundles, args.roaming, top=args.top * 40)))
        return 0

    bundles = []
    for path in args.bundles:
        if not os.path.exists(path):
            print(f"Error: '{path}' does not exist.", file=sys.stderr)
            return 2
        b = Bundle(path)
        b.read()
        bundles.append(b)
    # EM first, so section 3 reads EM -> appliance
    bundles.sort(key=lambda b: 0 if b.role == "EM" else 1)
    for i, b in enumerate(bundles, 1):
        b.index = i
    text = build_report(bundles, args)
    if args.json:
        ident = [{
            "index": b.index, "path": b.path, "name": b.name, "role": b.role, "nodeid": b.nodeid,
            "version": b.props.get("version"), "timezone": b.props.get("timezone"),
            "start": b.coverage()[0], "end": b.coverage()[1],
        } for b in bundles]
        print(json.dumps({"bundles": ident, "output": text}))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
