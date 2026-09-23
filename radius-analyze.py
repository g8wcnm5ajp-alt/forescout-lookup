#!/usr/bin/env python3
"""
radius-analyze.py -- what is going wrong in a Forescout RADIUS (dot1x plugin /
FreeRADIUS) log, ranked, in plain English.

Reads the plugin's radiusd.log (the FreeRADIUS debug stream, in Forescout's
"radiusd:PID:EPOCH:date: date : Level: (req) text" wrapper, or plain
FreeRADIUS -X output) from:
  --file PATH ...        one or more files ('-' = stdin; .gz accepted)
  --live [--since E] [--until E]
                         this box's own /usr/local/forescout/log/plugin/dot1x/radiusd*.log,
                         only the files that overlap the window (default: last 24h)
  --bundle TGZ           a tech-support bundle: every files/.../log/plugin/dot1x/radiusd*.log
                         member, streamed, nothing unpacked to disk

Output: a text report (default) or --json {"output": <the text>, "findings": [...],
"summary": {...}}. Python 3.6+, standard library only -- it runs on the appliance.

Built 2026-09-22 for the Forescout Tech Support App from real logs: a customer
home server going zombie (proxied EAP never answered), the lab's own
"Proxy-To-Realm = LOCAL realm" misconfiguration, BlastRADIUS warnings,
unknown-intermediate-CA client certs, ntlm_auth/MS-CHAP failures, the EM's
radiusd restart loop on an undecryptable TLS key.
"""
import argparse
import calendar
import collections
import glob
import gzip
import io
import json
import os
import re
import statistics
import sys
import tarfile
import time

VERSION = "1.0.1"
DOT1X_LOG_DIR = "/usr/local/forescout/log/plugin/dot1x"

# radiusd:618496:1789461574.356601:Tue Sep 15 09:39:34 2026: Tue Sep 15 09:39:34 2026 : Debug: (9) text
WRAP_RE = re.compile(r"^radiusd:(\d+):(\d+(?:\.\d+)?):[^:]*:\d+:\d+ \d{4}: ([A-Za-z]{3} [A-Za-z]{3} +\d+ [\d:]+ \d{4}) : (.*)$")
# plain FreeRADIUS: "Tue Sep 15 09:39:34 2026 : Debug: (9) text"  or just "(9) text"
PLAIN_RE = re.compile(r"^(?:([A-Za-z]{3} [A-Za-z]{3} +\d+ [\d:]+ \d{4}) : )?(.*)$")
LEVEL_RE = re.compile(r"^(Debug|Info|Warning|Error|Auth|Proxy|ERROR|WARNING|INFO): ?(.*)$")
REQ_RE = re.compile(r"^\((\d+)\) ?(.*)$")
ATTR_RE = re.compile(r'^\s+([A-Za-z0-9\-:]+) = (.*)$')
RECV_RE = re.compile(r"^Received (Access-Request|Accounting-Request|Status-Server|CoA-Request|Disconnect-Request) Id (\d+) from ([\d.]+):(\d+) to ([\d.]+):(\d+)")
SENT_RE = re.compile(r"^Sent (Access-Accept|Access-Reject|Access-Challenge|Accounting-Response|Access-Request|CoA-ACK|CoA-NAK|Disconnect-ACK|Disconnect-NAK) Id (\d+) from ([\d.]+):(\d+) to ([\d.]+):(\d+)")
PROXY_SENT_RE = re.compile(r"^Sent Access-Request Id (\d+) from [\d.]+:\d+ to ([\d.]+):(\d+)")
PROXY_RECV_RE = re.compile(r"^Received (Access-Accept|Access-Reject|Access-Challenge) Id (\d+) from ([\d.]+):(\d+) to ([\d.]+):(\d+)")
PROXYING_RE = re.compile(r"^Proxying request to home server ([\d.]+) port (\d+) timeout ([\d.]+)")
ZOMBIE_RE = re.compile(r"Marking home server ([\d.]+) port (\d+) as (zombie|dead)")
ALIVE_RE = re.compile(r"home server ([\d.]+) port (\d+) (?:is alive|alive again|Marking .* as alive)|Marking home server ([\d.]+) port (\d+) alive")
NOPROXY_RE = re.compile(r"^No proxy response, giving up on request")
FAILPROXY_RE = re.compile(r'^Failing proxied request for user "([^"]*)", due to lack of any response from home server (?:[\d.]+ )?port (\d+)')
UNKNOWN_CLIENT_RE = re.compile(r"Ignoring request to (?:auth|acct|coa) address [^ ]+ port \d+ .*from unknown client ([\d.]+) port (\d+)")
BAD_MA_RE = re.compile(r"Received packet from ([\d.]+) with invalid Message-Authenticator!")
BLAST_NO_MA_RE = re.compile(r"packet does not contain Message-Authenticator")
BLAST_NO_PS_RE = re.compile(r"BlastRADIUS check: Received packet without Proxy-State")
BLAST_SET_RE = re.compile(r'(?:Please set|set) "([^"]+)" for client ([\d.]+)')
LOCAL_REALM_RE = re.compile(r"You set Proxy-To-Realm = ([^,]+), but it is a LOCAL realm!")
UNTRUSTED_CERT_RE = re.compile(r"untrusted certificate with depth \[(\d+)\] subject name (.*)$")
TLS_ALERT_RE = re.compile(r"(?:TLS Alert|\(TLS\) Alert) (read|write):(fatal|warning):(.+)$")
TLS_ERR_RE = re.compile(r"^(?:eap_tls: )?(?:\(TLS\) )?(?:ERROR: )?(?:TLS_accept: Error in error|SSL: SSL_read failed|.*certificate (?:has )?expired.*|.*certificate revoked.*|.*unknown CA.*|.*self signed certificate.*|.*handshake failure.*|.*unable to get (?:local )?issuer certificate.*)$", re.I)
TLS_KEY_ERR_RE = re.compile(r"tls: \(TLS\) .*(?:pkcs12|p12_decr|PKCS12|bad decrypt|mac verify failure|wrong tag|Failed to (?:load|read) private key|error:0[0-9A-F]+:)", re.I)
EAP_ERR_RE = re.compile(r"^(?:eap: )?ERROR: (.*)$")
MSCHAP_RE = re.compile(r"^(?:ERROR: )?mschap: (.*)$")
NTLM_RE = re.compile(r"^(?:ERROR: )?ntlm_auth: (.*)$")
MFM_RE = re.compile(r"Module-Failure-Message(?: :=| =|:) *(?:&request:Module-Failure-Message -> )?'?(.*?)'?$")
REJECT_REASON_RE = re.compile(r"^(?:Login incorrect|Invalid user|Rejected: (.*)|.*\[(\w+)\] = reject$|.*Failed to authenticate the user)")
READY_RE = re.compile(r"^Ready to process requests")
# FreeRADIUS's own radius.log (Auth: lines), when a customer sends that instead of the debug stream
AUTH_RE = re.compile(r"^(?:\(\d+\) )?Login (OK|incorrect)(?: \(([^)]*)\))?: \[([^\]]*)\](?: \(from client ([^ ]+) port (\d+)(?: cli ([^ )]+))?[^)]*\))?")
EXIT_RE = re.compile(r"^(?:Exiting normally|Signalled to terminate|Exiting|Received signal .*terminating)")
THREAD_RE = re.compile(r"^(?:Thread spawn failed|No free threads|The server is too busy|Dropping request .* too many outstanding|Threads: total/active/spare threads = (\d+)/(\d+)/(\d+))")
DUP_RE = re.compile(r"^(?:Discarding duplicate request|Ignoring duplicate packet|Received conflicting packet|Dropping packet without response because of error: Received conflicting)")
STATE_ERR_RE = re.compile(r"no EAP session matching the State attribute|State attribute is invalid|Aborting! Client is trying")
REDIS_RE = re.compile(r"^rlm_redis .*(Opening additional connection|Closing expired connection|Failed|failed|Unable|error)", re.I)
CONF_WARN_RE = re.compile(r"^/usr/local/forescout/plugin/dot1x/fs_radius/etc/raddb/[^:]+\[\d+\]: (.*)$")
RESPONSE_WINDOW_RE = re.compile(r"^\s*response_window = (\d+)")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ts_from_date(s):
    """A plain-format line's date, taken exactly as written (no timezone guessing)."""
    try:
        return calendar.timegm(time.strptime(s, "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return None


TZ_OFFSET = [None]  # seconds to add to an epoch to get the log's own wall clock (learned from the first wrapped line)


def fmt_ts(ts):
    """Times are shown in the LOG's own timezone (the box that wrote it), not the analysing machine's."""
    if not ts:
        return "-"
    off = TZ_OFFSET[0] if TZ_OFFSET[0] is not None else 0
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts + off))


def open_any(path):
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


class Analyzer:
    def __init__(self, since=None, until=None, examples=6):
        self.since, self.until, self.max_examples = since, until, examples
        self.lines = self.kept = 0
        self.first = self.last = None
        self.sources = []
        # per-request scratch: req id -> {"attrs": {}, "kind": ..., "nas": ..., "t": ts}
        self.req = {}
        self.pending_recv = None  # (req id) whose attribute dump is being read
        # counters
        self.recv = collections.Counter()
        self.sent = collections.Counter()
        self.per_nas = collections.defaultdict(lambda: collections.Counter())
        self.nas_names = {}
        self.home = collections.defaultdict(lambda: {"sent": 0, "accept": 0, "reject": 0, "challenge": 0, "timeouts": 0,
                                                     "zombie": 0, "alive": 0, "rtts": [], "users": collections.Counter(),
                                                     "first": None, "last": None, "timeout_cfg": None})
        self.proxy_inflight = {}  # (server, id) -> ts
        self.rejects = []  # (ts, nas, user, mac, reason)
        self.reject_reasons = collections.Counter()
        self.reject_users = collections.Counter()
        self.accepts_users = collections.Counter()
        self.findings = collections.OrderedDict()
        self.restarts = []  # ts of "Ready to process requests" from a NEW pid (a real start)
        self.reloads = []   # ... from the SAME pid (a SIGHUP config reload -- dot1x's housekeep re-pushes clients)
        self.ready_pid = None
        self.exits = []
        self.hourly = collections.defaultdict(lambda: collections.Counter())
        self.response_window = None
        self.cfg_warnings = collections.Counter()
        self.eap_methods = collections.Counter()
        self.last_mfm = {}  # req id -> module failure message
        self.ssl_ok = 0  # completed TLS handshakes
        self.ssl_fail = 0
        self.current_pid = None
        self.pids = []

    # ---- findings -------------------------------------------------------------------
    def hit(self, key, sev, title, ts, example=None, meaning="", check="", inc=1, **extra):
        f = self.findings.get(key)
        if f is None:
            f = self.findings[key] = {"key": key, "severity": sev, "title": title, "count": 0, "first": ts, "last": ts,
                                      "examples": [], "meaning": meaning, "check": check, "detail": collections.defaultdict(collections.Counter)}
        f["count"] += inc
        if ts:
            f["first"] = ts if not f["first"] else min(f["first"], ts)
            f["last"] = ts if not f["last"] else max(f["last"], ts)
        if example and len(f["examples"]) < self.max_examples and example not in f["examples"]:
            f["examples"].append(example[:220])
        for k, v in extra.items():
            if v not in (None, ""):
                f["detail"][k][str(v)] += inc
        return f

    # ---- parsing --------------------------------------------------------------------
    def feed(self, fh, source):
        self.sources.append(source)
        for raw in fh:
            self.lines += 1
            line = raw.rstrip("\n")
            m = WRAP_RE.match(line)
            if m:
                pid, ts, msg = m.group(1), float(m.group(2)), m.group(4)
                if TZ_OFFSET[0] is None:
                    try:
                        TZ_OFFSET[0] = calendar.timegm(time.strptime(m.group(3), "%a %b %d %H:%M:%S %Y")) - int(ts)
                    except ValueError:
                        TZ_OFFSET[0] = 0
                if pid != self.current_pid:
                    self.current_pid = pid
                    self.pids.append((ts, pid))
            else:
                m2 = PLAIN_RE.match(line)
                if not m2:
                    continue
                ts = _ts_from_date(m2.group(1)) if m2.group(1) else (self.last or 0)
                msg = m2.group(2)
                if not ts:
                    ts = self.last or 0
                if not ts:
                    continue  # an untimed line (e.g. a stray shell message) before any timestamped one
            if self.since and ts < self.since:
                continue
            if self.until and ts > self.until:
                continue
            self.kept += 1
            self.first = ts if self.first is None else min(self.first, ts)
            self.last = ts if self.last is None else max(self.last, ts)
            lm = LEVEL_RE.match(msg)
            level, text = (lm.group(1), lm.group(2)) if lm else ("", msg)
            rm = REQ_RE.match(text)
            rid, body = (int(rm.group(1)), rm.group(2)) if rm else (None, text)
            self.handle(ts, level, rid, body, line)

    def _hour(self, ts):
        off = TZ_OFFSET[0] or 0
        return int((ts + off) // 3600 * 3600) - off

    def handle(self, ts, level, rid, body, raw):
        req = self.req.get(rid) if rid is not None else None
        # attribute dump after a Received line
        if rid is not None and self.pending_recv == rid:
            am = ATTR_RE.match(body)
            if am:
                name, val = am.group(1), am.group(2).strip().strip('"')
                if req is not None and name in ("User-Name", "Calling-Station-Id", "Called-Station-Id", "NAS-IP-Address", "NAS-Identifier", "NAS-Port-Type", "EAP-Message", "Service-Type"):
                    req["attrs"][name] = val
                return
            self.pending_recv = None

        m = RECV_RE.match(body)
        if m and rid is not None:
            kind, pid, src = m.group(1), int(m.group(2)), m.group(3)
            self.recv[kind] += 1
            self.hourly[self._hour(ts)][kind] += 1
            self.req[rid] = {"attrs": {}, "kind": kind, "nas": src, "t": ts, "id": pid}
            self.per_nas[src][kind] += 1
            self.pending_recv = rid
            if len(self.req) > 5000:
                for k in list(self.req)[:1000]:
                    self.req.pop(k, None)
            return

        m = SENT_RE.match(body)
        if m and rid is not None:
            kind, dst = m.group(1), m.group(5)
            if kind == "Access-Request":
                # proxied out to a home server
                pm = PROXY_SENT_RE.match(body)
                if pm:
                    server = f"{pm.group(2)}:{pm.group(3)}"
                    h = self.home[server]
                    h["sent"] += 1
                    h["first"] = ts if not h["first"] else min(h["first"], ts)
                    h["last"] = ts if not h["last"] else max(h["last"], ts)
                    self.proxy_inflight[(server, int(pm.group(1)))] = ts
                    if req:
                        h["users"][req["attrs"].get("User-Name", "?")] += 1
                    self.hourly[self._hour(ts)]["proxied"] += 1
                return
            self.sent[kind] += 1
            self.hourly[self._hour(ts)][kind] += 1
            if req:
                self.per_nas[req["nas"]][kind] += 1
                user = req["attrs"].get("User-Name", "?")
                mac = req["attrs"].get("Calling-Station-Id", "")
                if kind == "Access-Reject":
                    reason = self.last_mfm.pop(rid, None) or req.get("reason") or "no reason logged"
                    self.rejects.append((ts, req["nas"], user, mac, reason))
                    self.reject_reasons[reason] += 1
                    self.reject_users[(user, mac)] += 1
                elif kind == "Access-Accept":
                    self.accepts_users[(user, mac)] += 1
                    self.per_nas[req["nas"]]["accept_users"] += 0
            return

        m = PROXY_RECV_RE.match(body)
        if m:
            kind, pid, server = m.group(1), int(m.group(2)), f"{m.group(3)}:{m.group(4)}"
            if server in self.home:
                h = self.home[server]
                h[{"Access-Accept": "accept", "Access-Reject": "reject", "Access-Challenge": "challenge"}[kind]] += 1
                t0 = self.proxy_inflight.pop((server, pid), None)
                if t0 is not None and ts >= t0:
                    h["rtts"].append(ts - t0)
            return

        m = PROXYING_RE.match(body)
        if m:
            server = f"{m.group(1)}:{m.group(2)}"
            self.home[server]["timeout_cfg"] = float(m.group(3))
            return

        m = ZOMBIE_RE.search(body)
        if m:
            server = f"{m.group(1)}:{m.group(2)}"
            self.home[server]["zombie"] += 1
            self.hit("home_server_zombie", "critical", f"Home server {server} marked {m.group(3)} -- no replies to proxied requests", ts, raw,
                     meaning="The appliance forwarded authentication requests to this RADIUS server and got no answer at all within the response window. "
                             "Silence (not a reject) almost always means the server is discarding the packets: this appliance's source IP is not a "
                             "configured RADIUS client there, or the shared secret is wrong (with EAP the Message-Authenticator is mandatory and a bad "
                             "secret makes NPS/ISE drop the packet silently) -- or UDP 1812 is not reaching it. While a server is zombie, every "
                             "request that would proxy to it fails immediately.",
                     check=f"On {m.group(1)}: is this appliance's real source IP a RADIUS client, and does the secret match? Look for 'unknown client' / "
                           "discard events there (NPS: Event ID 18). From the appliance: tcpdump -ni any host " + m.group(1) + " and port " + m.group(2) +
                           " -- requests leaving, nothing back = client/secret or path. Also lower response_window (30 s is far longer than any NAS waits).",
                     server=server)
            return
        m = ALIVE_RE.search(body)
        if m:
            server = f"{m.group(1) or m.group(3)}:{m.group(2) or m.group(4)}"
            self.home[server]["alive"] += 1
            return
        if NOPROXY_RE.match(body):
            self.hourly[self._hour(ts)]["proxy_timeout"] += 1
            return
        m = FAILPROXY_RE.match(body)
        if m:
            user = m.group(1)
            # attribute the timeout to the most recent home server with in-flight requests
            servers = [s for s in self.home if self.home[s]["sent"]]
            server = servers[-1] if servers else "?"
            self.home[server]["timeouts"] += 1 if server in self.home else 0
            nas = req["nas"] if req else None
            self.hit("proxy_timeout", "critical", "Proxied requests failed: no response from the home server", ts, raw,
                     meaning="Each of these is one authentication the appliance gave up on because the home server never replied. The NAS and the "
                             "client see a plain failure (or nothing) -- for EAP that shows up as devices stuck 'authenticating' or bounced off the SSID/port.",
                     check="See the home-server finding above for the cause; this one tells you who was affected.",
                     user=user, home_server=server, nas=nas)
            return

        m = UNKNOWN_CLIENT_RE.search(body)
        if m:
            self.hit("unknown_client", "critical", "Requests ignored from an unknown RADIUS client (NAS not configured on this appliance)", ts, raw,
                     meaning="A switch/WLC/NAS is sending RADIUS to this appliance but its IP is not in the plugin's client list, so every packet from it is "
                             "dropped without a reply. Devices behind that NAS cannot authenticate at all.",
                     check="Add the NAS (by its real source IP) with the right shared secret under the RADIUS plugin's clients, or fix the NAS to use its "
                           "configured source interface. Then re-check the log for this IP.",
                     client=m.group(1))
            return
        m = BAD_MA_RE.search(body)
        if m:
            self.hit("bad_secret", "critical", "Invalid Message-Authenticator -- shared secret mismatch with a NAS", ts, raw,
                     meaning="The NAS and this appliance disagree on the shared secret, so the packet's signature fails and it is dropped without a reply. "
                             "Looks identical to 'no response' from the NAS side.",
                     check="Compare the secret configured for this NAS on the appliance with the one on the NAS; re-enter both.", client=m.group(1))
            return
        if BLAST_NO_PS_RE.search(body) or BLAST_NO_MA_RE.search(body):
            sm = BLAST_SET_RE.search(body)
            self.hit("blastradius", "medium", "BlastRADIUS: NAS sending Access-Requests without Message-Authenticator", ts, raw,
                     meaning="FreeRADIUS (post-CVE-2024-3596) flags NAS packets that carry no Message-Authenticator. Today it only warns; once "
                             "require_message_authenticator is enforced these NAS will be refused.",
                     check="Upgrade the NAS firmware so it sends Message-Authenticator on every Access-Request, then set require_message_authenticator = yes "
                           "for that client. (The log names the client and the exact setting.)")
            return
        m = LOCAL_REALM_RE.search(body)
        if m:
            self.hit("local_realm_proxy", "high", f"Proxy cancelled: realm '{m.group(1)}' is LOCAL but the policy tries to proxy to it", ts, raw,
                     meaning="The authorize policy sets Proxy-To-Realm to a realm that is defined as LOCAL (authhost = LOCAL), so FreeRADIUS refuses to proxy "
                             "and authenticates locally instead. If the intent was to forward these users to an external RADIUS/NPS, that never happens "
                             "-- and local EAP/MS-CHAP then fails for accounts it doesn't know.",
                     check="In the RADIUS plugin configuration, either give the realm a real home server (so it is not LOCAL) or stop the policy from "
                           "proxying that realm. Count how many users hit this (below).",
                     realm=m.group(1), user=(req or {}).get("attrs", {}).get("User-Name"))
            return
        m = UNTRUSTED_CERT_RE.search(body)
        if m:
            self.hit("untrusted_client_cert", "high", "EAP-TLS client certificate issued by a CA the appliance does not itself trust", ts, raw,
                     meaning="The client's certificate chain includes an issuing/intermediate CA that is not in the appliance's own trusted-CA list, so it "
                             "is being trusted only because the client supplied it (reject_unknown_intermediate_ca is off). The handshake usually still "
                             "completes -- see the outcome counts -- but any client could present its own intermediate the same way, and the day "
                             "reject_unknown_intermediate_ca is turned on these users stop authenticating. AD CS certs often only carry an ldap:/// AIA, "
                             "so the appliance cannot fetch the issuer itself.",
                     check="Import the issuing CA (and its root, if two-tier) into the RADIUS plugin's trusted certificates; the warning stops and "
                           "reject_unknown_intermediate_ca = yes becomes safe.",
                     subject=m.group(2)[:120], depth=m.group(1))
            return
        m = TLS_ALERT_RE.search(body)
        if m and m.group(2) == "fatal":
            self.hit("tls_alert", "high", f"TLS fatal alert during EAP: {m.group(3).strip()}", ts, raw,
                     meaning="The EAP-TLS/PEAP handshake was aborted with a fatal alert. 'unknown CA' from the client = it does not trust the appliance's server "
                             "certificate; 'certificate expired/revoked/bad certificate' from the server = the client's certificate is the problem; "
                             "'handshake failure' = no common cipher/protocol version.",
                     check="Match the alert text to the side that sent it (read = from client, write = from server) and fix that certificate/trust.",
                     alert=m.group(3).strip(), direction=m.group(1), user=(req or {}).get("attrs", {}).get("User-Name"))
            return
        if TLS_KEY_ERR_RE.search(body):
            self.hit("tls_key_error", "critical", "radiusd cannot load its TLS server certificate/private key", ts, raw,
                     meaning="The EAP module fails to load the server certificate or decrypt its private key (wrong passphrase or a replaced key file), so "
                             "radiusd cannot start with EAP -- this appliance is not listening on 1812 at all while this repeats.",
                     check="Check the RADIUS plugin's server certificate and private-key passphrase (Console > Options > RADIUS); the plugin restart loop "
                           "('Ready to process requests' count) confirms the impact.")
            return
        m = EAP_ERR_RE.match(body)
        if m and rid is not None:
            self.hit("eap_error", "medium", "EAP errors", ts, raw,
                     meaning="Errors raised by the EAP modules while processing a client's authentication.",
                     check="The examples show the exact module message; the most common is a client re-using a stale State (a NAS retransmit after a "
                           "restart) -- harmless once, a problem if it repeats for the same client.",
                     message=m.group(1)[:100])
            if STATE_ERR_RE.search(body):
                self.findings["eap_error"]["detail"]["kind"]["stale State / aborted session"] += 1
            return
        m = NTLM_RE.match(body)
        if m and ("ERROR" in level or "ERROR" in body or "Program returned" in body or "No NT-Domain" in body):
            msg = m.group(1)
            self.hit("ntlm_auth", "high", "ntlm_auth (AD/winbind) failures behind MS-CHAP", ts, raw,
                     meaning="MS-CHAPv2 (PEAP/MSCHAPv2 or wired MAB with domain accounts) is checked through ntlm_auth/winbind against the domain. "
                             "'No NT-Domain was found in the User-Name' = the user logged in without a domain prefix and no default domain is set; "
                             "'invalid code'/'expecting NT_KEY: prefix' = winbind is not joined/running or the request failed -- every such user is rejected.",
                     check="On the appliance: is the domain join healthy (wbinfo -t)? Is a default domain configured for bare usernames?",
                     message=msg[:100], user=(req or {}).get("attrs", {}).get("User-Name"))
            if rid is not None:
                self.req.setdefault(rid, {"attrs": {}, "nas": None})["reason"] = "ntlm_auth: " + msg[:80]
            return
        m = MSCHAP_RE.match(body)
        if m and ("ERROR" in level or "ERROR" in body or "incorrect" in body or "FAILED" in body):
            msg = m.group(1)
            sev = "low" if "Response is incorrect" in msg else "high"
            self.hit("mschap_fail", sev, "MS-CHAP authentication failures", ts, raw,
                     meaning="'MS-CHAP2-Response is incorrect' is a wrong password (or a machine account whose password rotated); anything else "
                             "('Invalid output from ntlm_auth', 'No NT/LM-Password') is a server-side problem, not the user.",
                     check="Many for one user = that account; many across users = the AD/winbind path (see the ntlm_auth finding).",
                     message=msg[:100], user=(req or {}).get("attrs", {}).get("User-Name"))
            if rid is not None:
                self.req.setdefault(rid, {"attrs": {}, "nas": None})["reason"] = "mschap: " + msg[:80]
            return
        m = MFM_RE.search(body)
        if m and rid is not None:
            self.last_mfm[rid] = m.group(1).strip("'\" ")[:120]
            return
        if level == "Auth" or body.startswith("Login "):
            m = AUTH_RE.match(body)
            if m:
                ok, reason, user, client, mac = m.group(1) == "OK", m.group(2) or "", m.group(3), m.group(4) or "?", m.group(6) or ""
                user = user.split("/")[0] if "/" in user and not user.startswith("host/") else user
                self.hourly[self._hour(ts)]["Access-Accept" if ok else "Access-Reject"] += 1
                self.per_nas[client]["Access-Request"] += 1
                self.per_nas[client]["Access-Accept" if ok else "Access-Reject"] += 1
                self.sent["Access-Accept" if ok else "Access-Reject"] += 1
                self.recv["Access-Request"] += 1
                if ok:
                    self.accepts_users[(user, mac)] += 1
                else:
                    reason = reason or "no reason logged"
                    self.rejects.append((ts, client, user, mac, reason))
                    self.reject_reasons[reason] += 1
                    self.reject_users[(user, mac)] += 1
                return
        if READY_RE.match(body):
            if self.current_pid is not None and self.current_pid == self.ready_pid:
                self.reloads.append(ts)
            else:
                self.restarts.append(ts)
            self.ready_pid = self.current_pid
            return
        if EXIT_RE.match(body):
            self.exits.append(ts)
            return
        m = THREAD_RE.match(body)
        if m:
            if m.group(1) is None:
                self.hit("thread_pool", "high", "Thread pool exhausted / server too busy", ts, raw,
                         meaning="radiusd ran out of worker threads or hit its outstanding-request limit; requests are dropped and the NAS retransmits, "
                                 "which makes it worse. Usually a downstream stall (home server, LDAP, ntlm_auth) holding threads.",
                         check="Look at what each stuck request was waiting on (proxy timeouts, ntlm_auth) rather than only raising max_servers.")
            return
        if DUP_RE.match(body):
            self.hit("duplicates", "low", "Duplicate / conflicting packets from a NAS", ts, raw,
                     meaning="The NAS retransmitted before the appliance answered (or answered too late). A few are normal; a steady stream means the "
                             "appliance is too slow for the NAS's timeout -- typically because of the proxy/ntlm delays found above.",
                     check="Compare the NAS's RADIUS timeout with the appliance's actual response time (home-server RTT table).")
            return
        if REDIS_RE.match(body):
            if re.search(r"fail|unable|error", body, re.I):
                self.hit("redis", "high", "Redis (session/state store) errors", ts, raw,
                         meaning="The plugin keeps EAP/session state in Redis; if it cannot reach it, multi-round EAP conversations break.",
                         check="Check the dot1x plugin's redis-server.log and that redis is running on this appliance.")
            return
        m = CONF_WARN_RE.match(body)
        if m and level.lower().startswith("warn"):
            self.cfg_warnings[m.group(1)[:90]] += 1
            return
        m = RESPONSE_WINDOW_RE.match(body)
        if m:
            self.response_window = int(m.group(1))
            return
        if "SSL negotiation finished successfully" in body:
            self.ssl_ok += 1
            return
        if body.startswith("eap_tls: ") and ("TLS_accept: Error in error" in body or "[eaptls verify] = invalid" in body or "SSL_read failed" in body):
            self.ssl_fail += 1
            return
        if body.startswith("eap: Peer sent packet with method"):
            mm = re.search(r"method (EAP [A-Z\-]+|[A-Za-z0-9\-]+) \(", body)
            if mm:
                self.eap_methods[mm.group(1)] += 1
            return
        if level == "Error" and body.startswith("!!!!"):
            return
        if level in ("Error", "ERROR") and body and not body.startswith(("Setting ", "Please set", "The packet", "The client", "UPGRADE THE CLIENT", "Once the client")):
            self.hit("other_errors", "medium", "Other errors logged by radiusd", ts, raw,
                     meaning="Error-level lines not covered by a specific check.", check="Read the examples.", message=body[:90])

    # ---- reporting -------------------------------------------------------------------
    def finalize(self):
        f = self.findings.get("untrusted_client_cert")
        if f:
            f["detail"]["handshake outcome"]["completed (SSLOK)"] = self.ssl_ok
            f["detail"]["handshake outcome"]["failed"] = self.ssl_fail
            if self.ssl_ok and not self.ssl_fail:
                f["severity"] = "low"
                f["title"] += " -- handshakes still completing"
        self.restarts.sort()
        self.reloads.sort()
        self.exits.sort()
        self.rejects.sort(key=lambda r: r[0])
        # home-server summary findings
        for server, h in self.home.items():
            if h["sent"] and not (h["accept"] + h["reject"] + h["challenge"]):
                self.hit("home_server_silent", "critical", f"Home server {server}: {h['sent']} request(s) proxied, 0 replies ever seen", h["first"],
                         meaning="Not one proxied request to this server got any answer in this log. That is a configuration/path problem, not load.",
                         check="Same checks as the zombie finding: RADIUS client entry + secret on the server for this appliance's source IP, and UDP 1812 path.",
                         inc=0)
                self.findings["home_server_silent"]["count"] = h["sent"]
            if h["timeout_cfg"] and h["timeout_cfg"] >= 20:
                self.hit("response_window", "medium", f"Home server {server}: response window {h['timeout_cfg']:.0f} s is far longer than any NAS waits",
                         h["first"], meaning="The appliance waits this long for the home server before giving up, but switches/WLCs typically retry after "
                                              "3-5 s and give up within ~15 s -- so a slow answer arrives after the NAS has already failed the client, "
                                              "and every retransmit is proxied again on top, multiplying load.",
                         check="Set the home server's response_window to 5-10 s and enable status_server checks so a dead server is detected and revived cleanly.",
                         inc=0)
                self.findings["response_window"]["count"] = 1
        if len(self.restarts) >= 3:
            span = (self.restarts[-1] - self.restarts[0]) / 3600 if len(self.restarts) > 1 else 0
            sev = "critical" if (span and len(self.restarts) / max(span, 0.01) > 4) else "medium"
            self.hit("restarts", sev, f"radiusd process started {len(self.restarts)} times in this log", self.restarts[0],
                     meaning="Every start is a gap in authentication. Many starts close together = a crash/restart loop (usually a config or certificate "
                             "error logged just before each start); a few = plugin restarts/config pushes.",
                     check="Look at the Error lines immediately before each 'Ready to process requests'.", inc=0)
            self.findings["restarts"]["count"] = len(self.restarts)
            self.findings["restarts"]["last"] = self.restarts[-1]
        if len(self.reloads) >= 10:
            span_h = max((self.reloads[-1] - self.reloads[0]) / 3600, 0.01)
            per_h = len(self.reloads) / span_h
            self.hit("reloads", "medium" if per_h >= 6 else "low", f"radiusd configuration reloaded (SIGHUP) {len(self.reloads)} times (~{per_h:.0f}/hour)", self.reloads[0],
                     meaning="Same process, config re-read -- the dot1x plugin's housekeeping re-pushes the RADIUS client list / settings and HUPs radiusd. "
                             "Once a minute is churn: every reload re-reads certificates and modules and can drop an EAP conversation mid-handshake.",
                     check="dot1x.log around the same minutes: what the housekeep timer thinks changed (client list, AD reconf). If nothing really "
                           "changes, that is a plugin-side loop to raise with Forescout.", inc=0)
            self.findings["reloads"]["count"] = len(self.reloads)
            self.findings["reloads"]["last"] = self.reloads[-1]
        if self.reject_reasons:
            top = self.reject_reasons.most_common(1)[0]
            total = sum(self.reject_reasons.values())
            self.hit("rejects", "info" if total < 20 else "medium", f"{total} Access-Reject(s) sent", None,
                     meaning=f"Most common reason: {top[0]} ({top[1]}).", check="See the reject tables below for who and why.", inc=0)
            self.findings["rejects"]["count"] = total
            self.findings["rejects"]["first"] = self.rejects[0][0]
            self.findings["rejects"]["last"] = self.rejects[-1][0]
        for f in self.findings.values():
            f["detail"] = {k: dict(v.most_common(8)) for k, v in f["detail"].items()}
        return sorted(self.findings.values(), key=lambda f: (SEV_ORDER[f["severity"]], -f["count"]))

    def summary(self):
        return {
            "version": VERSION, "sources": self.sources, "lines": self.lines, "lines_in_window": self.kept,
            "first": self.first, "last": self.last, "span_hours": round((self.last - self.first) / 3600, 2) if self.first and self.last else 0,
            "received": dict(self.recv), "sent": dict(self.sent), "restarts": len(self.restarts), "reloads": len(self.reloads), "pids": len(set(p for _, p in self.pids)),
            "response_window": self.response_window, "eap_methods": dict(self.eap_methods),
            "home_servers": {s: {k: (v if k != "rtts" else {"n": len(v), "median_ms": round(statistics.median(v) * 1000, 1) if v else None,
                                                                "max_ms": round(max(v) * 1000, 1) if v else None})
                                 for k, v in h.items() if k != "users"} for s, h in self.home.items()},
            "nas": {n: dict(c) for n, c in self.per_nas.items()},
        }

    def text(self, findings):
        out = []
        s = self.summary()
        W = 100
        out.append("=" * W)
        out.append(f"RADIUS LOG ANALYSIS  (radius-analyze.py v{VERSION})")
        out.append("=" * W)
        out.append(f"Source(s): {', '.join(s['sources'])}")
        out.append(f"Lines: {s['lines']:,} read, {s['lines_in_window']:,} in window   Span: {fmt_ts(s['first'])} -> {fmt_ts(s['last'])} ({s['span_hours']} h)")
        rx, tx = s["received"], s["sent"]
        out.append(f"Received: {rx.get('Access-Request', 0):,} Access-Request, {rx.get('Accounting-Request', 0):,} Accounting, "
                   f"{rx.get('Status-Server', 0):,} Status-Server   Sent: {tx.get('Access-Accept', 0):,} Accept, {tx.get('Access-Reject', 0):,} Reject, "
                   f"{tx.get('Access-Challenge', 0):,} Challenge")
        if s["home_servers"]:
            proxied = sum(h["sent"] for h in s["home_servers"].values())
            out.append(f"Proxied to home servers: {proxied:,}   radiusd starts: {s['restarts']} (reloads {s['reloads']})   EAP methods: "
                       + (", ".join(f"{k} {v}" for k, v in sorted(s['eap_methods'].items(), key=lambda kv: -kv[1])) or "-"))
        else:
            out.append(f"radiusd starts: {s['restarts']} (reloads {s['reloads']})   EAP methods: " + (", ".join(f"{k} {v}" for k, v in sorted(s['eap_methods'].items(), key=lambda kv: -kv[1])) or "-"))
        out.append("")
        out.append("-" * W)
        out.append("FINDINGS (most serious first)")
        out.append("-" * W)
        if not findings:
            out.append("Nothing wrong found: no proxy timeouts, unknown clients, secret mismatches, TLS/EAP errors, restarts loops or rejects in this log.")
        for i, f in enumerate(findings, 1):
            out.append(f"{i}. [{f['severity'].upper()}] {f['title']}")
            out.append(f"   count: {f['count']:,}   first: {fmt_ts(f['first'])}   last: {fmt_ts(f['last'])}")
            for k, v in f["detail"].items():
                items = ", ".join(f"{a} ({b})" for a, b in v.items())
                out.append(f"   {k}: {items}")
            if f["meaning"]:
                out.append("   What it means: " + f["meaning"])
            if f["check"]:
                out.append("   Check: " + f["check"])
            for ex in f["examples"][:3]:
                out.append("   | " + ex)
            out.append("")
        if s["home_servers"]:
            out.append("-" * W)
            out.append("HOME SERVERS (proxy targets)")
            out.append("-" * W)
            out.append(f"{'server':<22}{'sent':>8}{'accept':>8}{'reject':>8}{'chall.':>8}{'timeouts':>10}{'zombie':>8}{'rtt med/max ms':>18}  window")
            for server, h in sorted(s["home_servers"].items()):
                r = h["rtts"]
                out.append(f"{server:<22}{h['sent']:>8}{h['accept']:>8}{h['reject']:>8}{h['challenge']:>8}{h['timeouts']:>10}{h['zombie']:>8}"
                           f"{(str(r['median_ms']) + '/' + str(r['max_ms'])) if r['n'] else '-':>18}  {h['timeout_cfg'] or '-'}")
                users = self.home[server]["users"].most_common(5)
                if users:
                    out.append("   top users: " + ", ".join(f"{u} ({c})" for u, c in users))
            out.append("")
        if self.per_nas:
            out.append("-" * W)
            out.append("PER NAS (switch / controller)")
            out.append("-" * W)
            out.append(f"{'NAS':<18}{'requests':>10}{'accept':>8}{'reject':>8}{'challenge':>10}{'acct':>8}")
            for nas, c in sorted(self.per_nas.items(), key=lambda kv: -kv[1].get("Access-Request", 0)):
                out.append(f"{nas:<18}{c.get('Access-Request', 0):>10}{c.get('Access-Accept', 0):>8}{c.get('Access-Reject', 0):>8}"
                           f"{c.get('Access-Challenge', 0):>10}{c.get('Accounting-Request', 0):>8}")
            out.append("")
        if self.rejects:
            out.append("-" * W)
            out.append("REJECTS")
            out.append("-" * W)
            out.append("By reason:")
            for reason, n in self.reject_reasons.most_common(10):
                out.append(f"   {n:>6}  {reason}")
            out.append("By user / MAC (top 15):")
            for (user, mac), n in self.reject_users.most_common(15):
                acc = self.accepts_users.get((user, mac), 0)
                out.append(f"   {n:>6}  {user:<40} {mac:<20} (accepted {acc}x)")
            out.append("Last 10:")
            for ts, nas, user, mac, reason in self.rejects[-10:]:
                out.append(f"   {fmt_ts(ts)}  {nas:<16} {user:<32} {mac:<20} {reason}")
            out.append("")
        if self.hourly:
            out.append("-" * W)
            out.append("PER HOUR")
            out.append("-" * W)
            out.append(f"{'hour':<18}{'requests':>10}{'accept':>8}{'reject':>8}{'proxied':>9}{'proxy t/o':>10}{'acct':>8}")
            for hour in sorted(self.hourly):
                c = self.hourly[hour]
                out.append(f"{fmt_ts(hour)[:13] + ':00' :<18}{c.get('Access-Request', 0):>10}{c.get('Access-Accept', 0):>8}"
                           f"{c.get('Access-Reject', 0):>8}{c.get('proxied', 0):>9}{c.get('proxy_timeout', 0):>10}{c.get('Accounting-Request', 0):>8}")
            out.append("")
        if self.cfg_warnings:
            out.append("-" * W)
            out.append(f"CONFIGURATION WARNINGS ({sum(self.cfg_warnings.values())} lines, {len(self.cfg_warnings)} distinct -- cosmetic unless a finding above names one)")
            out.append("-" * W)
            for w, n in self.cfg_warnings.most_common(6):
                out.append(f"   {n:>6}  {w}")
            out.append("")
        return "\n".join(out)


def live_files(since, until):
    """radiusd.log plus every rotated radiusd.<epoch>.<pid>.log whose content can overlap the window
    (rotation epoch is the START of that file; a file's mtime is its end)."""
    files = []
    for path in glob.glob(os.path.join(DOT1X_LOG_DIR, "radiusd*.log")) + glob.glob(os.path.join(DOT1X_LOG_DIR, "radius.log*"))             + glob.glob("/usr/local/forescout/plugin/dot1x/fs_radius/var/log/radius/radius.log*"):
        try:
            end = os.path.getmtime(path)
        except OSError:
            continue
        m = re.search(r"radiusd\.(\d+)\.", os.path.basename(path))
        start = int(m.group(1)) if m else 0
        if since and end < since:
            continue
        if until and start > until:
            continue
        files.append((start, path))
    return [p for _, p in sorted(files)]


def bundle_members(path):
    with tarfile.open(path, mode="r|*") as tar:
        for member in tar:
            name = member.name
            if member.isfile() and ("/log/plugin/dot1x/" in name or "/fs_radius/var/log/radius/" in name) and re.search(r"radiusd?(\.\d+\.\d+)?\.log(\.\d+)?$", name):
                fh = tar.extractfile(member)
                if fh is not None:
                    yield name, io.TextIOWrapper(fh, encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", nargs="+", help="log file(s), '-' for stdin, .gz ok")
    ap.add_argument("--live", action="store_true", help=f"read {DOT1X_LOG_DIR}/radiusd*.log on this box")
    ap.add_argument("--bundle", help="a tech-support bundle (.tgz/.tar.gz)")
    ap.add_argument("--since", type=float, help="epoch seconds; default for --live: now - 24h")
    ap.add_argument("--until", type=float)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--examples", type=int, default=6)
    a = ap.parse_args()
    if not (a.file or a.live or a.bundle):
        ap.error("give --file, --live or --bundle")
    since, until = a.since, a.until
    if a.live and since is None:
        since = time.time() - 86400
    an = Analyzer(since, until, a.examples)
    try:
        if a.file:
            for p in a.file:
                with open_any(p) as fh:
                    an.feed(fh, p if p != "-" else "stdin")
        if a.live:
            files = live_files(since, until)
            if not files:
                raise SystemExit(f"no radiusd*.log under {DOT1X_LOG_DIR} overlaps the window (is the RADIUS plugin installed here?)")
            for p in files:
                with open_any(p) as fh:
                    an.feed(fh, os.path.basename(p))
        if a.bundle:
            n = 0
            for name, fh in bundle_members(a.bundle):
                n += 1
                an.feed(fh, name.split("/")[-1])
            if n == 0:
                raise SystemExit("no log/plugin/dot1x/radiusd*.log inside that bundle (RADIUS plugin not installed on that box, or the bundle "
                                 "was built without plugin logs)")
    except (OSError, tarfile.TarError) as e:
        raise SystemExit(f"cannot read input: {e}")
    findings = an.finalize()
    text = an.text(findings)
    if a.json:
        print(json.dumps({"output": text, "findings": findings, "summary": an.summary()}, default=str))
    else:
        print(text)


if __name__ == "__main__":
    main()
