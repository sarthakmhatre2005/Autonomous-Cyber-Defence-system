from flask import Flask, request, jsonify, render_template, send_from_directory
import time
import os
import threading
import socket
import ipaddress
import json
import urllib.request

# Import from new architectural layers
from data.database import init_db, log_event, get_recent_events, get_recent_actions, get_stats, get_blocked_entities
from monitoring.process_monitor import start_process_monitor, get_active_window_title
from monitoring.persistence_monitor import start_persistence_monitor
from monitoring.packet_capture import start_packet_capture, packet_store, get_ip_type
from monitoring.traffic_analyzer import traffic_analyzer
from core.threat_engine import threat_engine
from defense.honeypot import start_honeypot

# ─── Threat source intelligence enrichment (lightweight + cached) ───────────

_SRC_CACHE_LOCK = threading.Lock()
_SRC_DOMAIN_CACHE = {}  # ip -> {"domain": str, "ts": float}
_SRC_ISP_CACHE = {}     # ip -> {"isp_org": str, "ts": float}
_DOMAIN_INFLIGHT = set()
_ISP_INFLIGHT = set()

_DOMAIN_TTL_SEC = 6 * 3600   # 6 hours
_ISP_TTL_SEC = 1 * 3600      # 1 hour


def _source_type_from_ip(ip: str) -> str:
    """Classify SYSTEM / LOCAL DEVICE / EXTERNAL SOURCE for dashboard context."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Requirement is IPv4-specific; keep deterministic behavior.
        if ip_obj.version != 4:
            return "EXTERNAL SOURCE"
        s = ip_obj.exploded
        if ip.startswith("127."):
            return "SYSTEM"
        if ip.startswith("10."):
            return "LOCAL DEVICE"
        if ip.startswith("192.168."):
            return "LOCAL DEVICE"
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                sec = int(parts[1])
                if 16 <= sec <= 31:
                    return "LOCAL DEVICE"
    except Exception:
        pass
    return "EXTERNAL SOURCE"


def _downgrade_threat_level_for_source(level: str, source_type: str) -> str:
    """Downgrade visual threat level for internal/system context only."""
    levels = ["NORMAL", "SUSPICIOUS", "MALICIOUS", "CRITICAL"]
    lvl = (level or "NORMAL").upper()
    try:
        idx = levels.index(lvl)
    except ValueError:
        idx = 0

    if source_type == "SYSTEM":
        idx = max(0, idx - 2)
    elif source_type == "LOCAL DEVICE":
        idx = max(0, idx - 1)
    return levels[idx]


def _context_label(source_type: str, threat_level: str) -> str:
    """Human-readable context-aware classification label for dashboard."""
    if source_type == "SYSTEM":
        return "SYSTEM ACTIVITY" if threat_level in ("NORMAL", "SUSPICIOUS") else "INTERNAL SYSTEM ANOMALY"
    if source_type == "LOCAL DEVICE":
        return "LOCAL DEVICE ACTIVITY" if threat_level in ("NORMAL", "SUSPICIOUS") else "INTERNAL DEVICE ANOMALY"
    return "EXTERNAL THREAT" if threat_level in ("MALICIOUS", "CRITICAL") else threat_level


def _safe_text(v, default="unknown"):
    try:
        s = str(v).strip()
        return s if s else default
    except Exception:
        return default


def _normalized_source_label(source_type: str) -> str:
    st = _safe_text(source_type, "EXTERNAL SOURCE").upper()
    if st == "SYSTEM":
        return "SYSTEM ACTIVITY"
    if st == "LOCAL DEVICE":
        return "LOCAL DEVICE ACTIVITY"
    return "EXTERNAL THREAT"


def _is_noise_domain(domain: str) -> bool:
    d = _safe_text(domain, "").lower().strip().rstrip(".")
    if not d:
        return True
    if d.endswith(".in-addr.arpa"):
        return True
    if d.endswith(".local"):
        return True
    if "_udp." in d or "_tcp." in d:
        return True
    if d == "unknown" or len(d) < 4:
        return True
    # Ignore IP literals and host:port values (not DNS domains).
    host = d
    if ":" in host and host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            host = left
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        pass
    return False


def _reverse_dns(ip: str) -> str:
    """Reverse DNS with safe fallbacks."""
    try:
        # Ensure resolver does not hang indefinitely in background.
        orig_timeout = None
        try:
            orig_timeout = socket.getdefaulttimeout()
        except Exception:
            orig_timeout = None
        try:
            socket.setdefaulttimeout(2.0)
            return socket.gethostbyaddr(ip)[0]
        finally:
            try:
                socket.setdefaulttimeout(orig_timeout)
            except Exception:
                pass
    except Exception:
        return "unknown"


def _fetch_isp_org_ip_api(ip: str) -> str:
    """Optional ISP/org enrichment via ip-api.com (no hard failures)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,isp,org"
        req = urllib.request.Request(url, headers={"User-Agent": "AutonomousCyberDefence/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        data = json.loads(raw) if raw else {}
        if data.get("status") != "success":
            return "unresolved"
        isp = data.get("isp") or ""
        org = data.get("org") or ""
        val = isp if isp else org
        return val.strip() if val else "unresolved"
    except Exception:
        return "unresolved"


def _schedule_reverse_dns(ip: str) -> None:
    now = time.time()
    with _SRC_CACHE_LOCK:
        cached = _SRC_DOMAIN_CACHE.get(ip)
        if cached and (now - cached.get("ts", 0)) <= _DOMAIN_TTL_SEC:
            return
        if ip in _DOMAIN_INFLIGHT:
            return
        _DOMAIN_INFLIGHT.add(ip)

    def _worker():
        domain = _reverse_dns(ip)
        with _SRC_CACHE_LOCK:
            _SRC_DOMAIN_CACHE[ip] = {"domain": domain, "ts": time.time()}
            _DOMAIN_INFLIGHT.discard(ip)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _schedule_isp(ip: str) -> None:
    now = time.time()
    with _SRC_CACHE_LOCK:
        cached = _SRC_ISP_CACHE.get(ip)
        if cached and (now - cached.get("ts", 0)) <= _ISP_TTL_SEC:
            return
        if ip in _ISP_INFLIGHT:
            return
        _ISP_INFLIGHT.add(ip)

    def _worker():
        isp_org = _fetch_isp_org_ip_api(ip)
        with _SRC_CACHE_LOCK:
            _SRC_ISP_CACHE[ip] = {"isp_org": isp_org, "ts": time.time()}
            _ISP_INFLIGHT.discard(ip)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _get_process_for_ip(ip: str, recent_packets: list) -> str:
    """Best-effort process enrichment using recent packet store only."""
    try:
        for p in reversed(recent_packets):
            if p.get("src_ip") == ip:
                proc = p.get("process") or ""
                if proc and proc != "None":
                    return proc
    except Exception:
        pass
    return "external traffic"

# Ensure templates and static folders are loaded relative to the dashboard directory
base_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(base_dir, 'templates'), static_folder=os.path.join(base_dir, 'static'))

# NEW: Check for Administrator privileges
from defense.firewall import is_admin
if not is_admin():
    print("\n" + "!"*60)
    print("WARNING: System is NOT running as Administrator.")
    print("Firewall blocking and high-level protection will NOT work.")
    print("Please restart with Administrator privileges.")
    print("!"*60 + "\n")

@app.before_request
def intercept_request():
    # Skip static files and API calls from dashboard
    if request.path.startswith('/static') or request.path.startswith('/api'):
        return

    # Check for Blocked Domain
    host = request.host.split(':')[0]
    blocked_entities = get_blocked_entities()
    blocked_domain = next((e for e in blocked_entities if e['entity_type'] == 'DOMAIN' and e['entity_value'] == host), None)

    if blocked_domain:
        return render_template('blocked.html', reason=blocked_domain['reason'])

    ip = request.remote_addr
    path = request.path
    method = request.method
    host = request.host.split(':')[0]

    # Log Event
    details = {"user_agent": request.user_agent.string, "path": path, "method": method}
    active_window = get_active_window_title()
    log_event(
        src_ip=ip, 
        dest_ip=host, 
        dst_port=80 if request.scheme == "http" else 443, 
        protocol="HTTP", 
        active_window=active_window, 
        details=details
    )


@app.route('/')
def index():
    return render_template('index.html')


# ─── Existing API Endpoints ────────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/events')
def api_events():
    try:
        rows = get_recent_events(limit=50) or []
    except Exception:
        return jsonify([])

    out = []
    for ev in rows:
        ev = ev or {}
        src_ip = _safe_text(ev.get("src_ip") or ev.get("source_ip"), "unknown")
        timestamp = ev.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%S")
        severity = _safe_text(ev.get("severity"), "LOW").upper()

        details_raw = ev.get("details")
        details = {}
        if isinstance(details_raw, dict):
            details = dict(details_raw)
        elif isinstance(details_raw, str):
            try:
                details = json.loads(details_raw) if details_raw.strip() else {}
            except Exception:
                details = {"detail": details_raw}

        source_type = _safe_text(details.get("source_type"), _source_type_from_ip(src_ip))
        reason = _safe_text(
            details.get("detail") or details.get("reason") or details_raw or "No additional context",
            "No additional context",
        )
        risk_score = int(details.get("risk_score", 0) or 0)
        attack_type = _safe_text(details.get("attack_type"), "SUSPICIOUS_BEHAVIOR")
        action = _safe_text(details.get("action"), "MONITOR").upper()
        process = _safe_text(details.get("process"), "unknown process")

        details.update({
            "ip": src_ip,
            "timestamp": timestamp,
            "risk_score": risk_score,
            "source_type": source_type,
            "source_label": _normalized_source_label(source_type),
            "attack_type": attack_type,
            "action": action,
            "reason": reason,
            "process": process,
        })

        ev["src_ip"] = src_ip
        ev["timestamp"] = timestamp
        ev["severity"] = severity
        ev["details"] = details
        out.append(ev)

    return jsonify(out)

@app.route('/api/actions')
def api_actions():
    try:
        return jsonify(get_recent_actions() or [])
    except Exception:
        return jsonify([])

@app.route('/api/blocked')
def api_blocked():
    try:
        # Return normalized blocked rows with cleanup for noisy malformed DOMAIN artifacts.
        rows = get_blocked_entities() or []
        cleaned = []
        for r in rows:
            ent_type = _safe_text(r.get("entity_type"), "").upper()
            ent_val = _safe_text(r.get("entity_value"), "")
            if ent_type == "DOMAIN" and _is_noise_domain(ent_val):
                continue

            atk = _safe_text(r.get("attack_type"), "SUSPICIOUS_BEHAVIOR").upper()
            reason = _safe_text(r.get("reason"), "Blocked by policy")
            if atk in ("RECONNAISSANCE", "PORT_SCAN", "SUSPICIOUS_PORTSCAN"):
                if "PORT_SCAN" not in reason.upper() and "RECONNAISSANCE" not in reason.upper():
                    reason = f"PORT_SCAN / RECONNAISSANCE: {reason}"
            r["reason"] = reason
            cleaned.append(r)
        return jsonify(cleaned)
    except Exception:
        return jsonify([])

@app.route('/api/top-ips')
def api_top_ips():
    from data.database import get_top_ips
    return jsonify(get_top_ips())



# ─── NEW: Network Traffic & Threat Intelligence API ───────────────────────────

@app.route('/api/network/stats')
def api_network_stats():
    """Real-time network capture statistics."""
    from monitoring.packet_capture import packet_store, get_network_throughput, get_interface_stats
    try:
        pkt_stats = packet_store.get_stats() or {}
    except Exception:
        pkt_stats = {}
    try:
        sent_rate, recv_rate = get_network_throughput()
    except Exception:
        sent_rate, recv_rate = 0.0, 0.0
    try:
        analyzer_stats = traffic_analyzer.get_stats() or {}
    except Exception:
        analyzer_stats = {}
    try:
        engine_stats = threat_engine.get_stats() or {}
    except Exception:
        engine_stats = {}

    return jsonify({
        "packet_capture": pkt_stats,
        "network_throughput": {
            "bytes_sent_per_sec": round(sent_rate, 2),
            "bytes_recv_per_sec": round(recv_rate, 2),
            "kb_sent_per_sec": round(sent_rate / 1024, 2),
            "kb_recv_per_sec": round(recv_rate / 1024, 2),
        },
        "traffic_analysis": analyzer_stats,
        "threat_engine": engine_stats,
        "interfaces": get_interface_stats() or [],
    })

@app.route('/api/network/ip-profiles')
def api_ip_profiles():
    """All tracked IP profiles (internal + external)."""
    profiles = traffic_analyzer.get_all_profiles()
    return jsonify(list(profiles.values()))

@app.route('/api/network/external-ips')
def api_external_ips():
    """Only external IP profiles."""
    profiles = traffic_analyzer.get_external_profiles()
    return jsonify(list(profiles.values()))

@app.route('/api/network/top-threats')
def api_top_threats():
    """Top threat IPs ranked by threat score."""
    try:
        threats = threat_engine.get_high_threat_ips(min_score=1) or []
    except Exception:
        return jsonify([])

    # Keep enrichment lightweight: compute process mapping from recent packets once.
    # This is in-memory only; no external I/O.
    recent_packets = packet_store.get_recent(n=250) or []
    proc_map = {}
    for t in threats:
        ip = t.get("ip", "") or ""
        if ip and ip not in proc_map:
            proc_map[ip] = _get_process_for_ip(ip, recent_packets)

    now = time.time()
    with _SRC_CACHE_LOCK:
        domain_snapshot = {ip: v for ip, v in _SRC_DOMAIN_CACHE.items()}
        isp_snapshot = {ip: v for ip, v in _SRC_ISP_CACHE.items()}

    filtered = []
    try:
        from monitoring.packet_capture import PROTECTED_IPS
        protected_ips = set(PROTECTED_IPS or [])
    except Exception:
        protected_ips = set()
    for t in threats:
        ip = _safe_text(t.get("ip", ""), "unknown")
        t["ip"] = ip

        source_type = _source_type_from_ip(ip)
        raw_level = (t.get("threat_level") or "NORMAL").upper()
        display_level = _downgrade_threat_level_for_source(raw_level, source_type)
        context_label = _context_label(source_type, display_level)

        cached_domain = domain_snapshot.get(ip, {}).get("domain") if domain_snapshot.get(ip) else None
        cached_isp = isp_snapshot.get(ip, {}).get("isp_org") if isp_snapshot.get(ip) else None

        # Safe fallbacks: never return undefined/null to UI.
        domain = cached_domain if cached_domain else "unknown"
        if _is_noise_domain(domain):
            domain = "unknown"
        isp_org = cached_isp if cached_isp else "unresolved"
        process_name = proc_map.get(ip, "external traffic")

        # Schedule missing/expired enrichment asynchronously.
        with _SRC_CACHE_LOCK:
            d_entry = _SRC_DOMAIN_CACHE.get(ip)
            i_entry = _SRC_ISP_CACHE.get(ip)
        if not d_entry or (now - d_entry.get("ts", 0)) > _DOMAIN_TTL_SEC:
            _schedule_reverse_dns(ip)
        if not i_entry or (now - i_entry.get("ts", 0)) > _ISP_TTL_SEC:
            _schedule_isp(ip)

        # Extend threat object without changing scoring/detection output.
        t["source_type"] = source_type
        t["source_label"] = _normalized_source_label(source_type)
        t["source_domain"] = domain
        t["domain"] = domain
        t["isp_org"] = isp_org
        raw_proc = str(process_name).strip().lower()
        if raw_proc in ("none", "", "unknown process"):
            process_name = "external traffic"
        t["process"] = process_name
        t["threat_level_raw"] = raw_level
        t["threat_level"] = display_level
        t["context_label"] = context_label
        t["risk"] = int(t.get("risk_score", 0) or 0)
        t["reason"] = _safe_text(t.get("reasoning"), "No reasoning available")
        t["action"] = _safe_text(t.get("action"), "MONITOR").upper()
        if t.get("is_blocked"):
            t["action"] = "BLOCK"
        t["attack_type"] = _safe_text(t.get("attack_type"), "SUSPICIOUS_BEHAVIOR")

        # Hide internal/deployment traffic from "Top Threats".
        is_internal = source_type in ("SYSTEM", "LOCAL DEVICE")
        is_protected = ip in protected_ips
        if is_internal or is_protected:
            t["_skip_noise"] = True
        # Hide noisy DNS artifacts from threat panel.
        if _safe_text(t.get("attack_type"), "").upper() == "DNS_THREAT" and _is_noise_domain(t.get("domain")):
            t["_skip_noise"] = True
        # Hard filter only for unknown IPs (allow partial enrichment instead of empty panel).
        if ip == "unknown":
            t["_skip_noise"] = True

        try:
            from core.cloud_intel import cloud_provider_hint

            prov = cloud_provider_hint(ip)
            t["cloud_provider"] = prov or ""
            if prov and raw_level in ("MALICIOUS", "CRITICAL") and int(t.get("risk_score", 0) or 0) < 80:
                t["threat_level"] = "SUSPICIOUS"
                t["threat_level_raw"] = "SUSPICIOUS"
                t["context_label"] = _context_label(source_type, "SUSPICIOUS")
        except Exception:
            t["cloud_provider"] = ""

        if not t.get("_skip_noise"):
            filtered.append(t)

    # Single fetch of blocked rows for threat panel (IPs + domains).
    blocked_entities = []
    try:
        blocked_entities = get_blocked_entities(limit=120) or []
    except Exception:
        blocked_entities = []

    # Include actively blocked IPs from DB so threat panel matches blocked tab.
    try:
        seen_blocked_ip = {x.get("ip") for x in filtered}
        for be in blocked_entities:
            if _safe_text(be.get("entity_type"), "").upper() != "IP":
                continue
            bip = _safe_text(be.get("entity_value") or be.get("ip"), "")
            if not bip or bip == "unknown" or bip in seen_blocked_ip:
                continue
            if _source_type_from_ip(bip) in ("SYSTEM", "LOCAL DEVICE"):
                continue
            seen_blocked_ip.add(bip)
            st = _source_type_from_ip(bip)
            filtered.append({
                "ip": bip,
                "source_type": st,
                "source_label": _normalized_source_label(st),
                "source_domain": _safe_text(be.get("domain"), "unknown"),
                "domain": _safe_text(be.get("domain"), "unknown"),
                "process": _safe_text(be.get("process"), "unknown process"),
                "isp_org": "unresolved",
                "threat_level_raw": "CRITICAL",
                "threat_level": "CRITICAL",
                "context_label": _context_label(st, "CRITICAL"),
                "risk": int(be.get("risk") or 0),
                "risk_score": int(be.get("risk") or 0),
                "attack_type": _safe_text(be.get("attack_type"), "SUSPICIOUS_BEHAVIOR"),
                "action": "BLOCK",
                "is_blocked": True,
                "reason": _safe_text(be.get("reason"), "Blocked by policy"),
                "reasoning": _safe_text(be.get("reason"), "Blocked by policy"),
                "evidence": [],
                "score": 10,
            })
    except Exception:
        pass

    # Include blocked domains/websites as threat entries for visibility in Threat Panel.
    try:
        from data.database import get_dns_history
        dns_hist = get_dns_history(limit=300) or []
        dns_by_domain = {}
        for d in dns_hist:
            dom = _safe_text(d.get("domain"), "")
            if dom and dom not in dns_by_domain:
                dns_by_domain[dom] = d

        blocked_rows = []
        for be in blocked_entities:
            if _safe_text(be.get("entity_type"), "").upper() != "DOMAIN":
                continue
            domain = _safe_text(be.get("entity_value"), "unknown")
            if _is_noise_domain(domain):
                continue
            dctx = dns_by_domain.get(domain, {})
            req_ip = _safe_text(dctx.get("requesting_ip"), "unknown")
            process = _safe_text(dctx.get("process"), "unknown process")
            threat_score = int(dctx.get("threat_score", 0) or 0)
            src_type = _source_type_from_ip(req_ip)
            blocked_rows.append({
                "ip": req_ip,
                "source_type": src_type,
                "source_label": _normalized_source_label(src_type),
                "source_domain": domain,
                "domain": domain,
                "process": process,
                "isp_org": "unresolved",
                "threat_level_raw": "CRITICAL",
                "threat_level": "CRITICAL",
                "context_label": "EXTERNAL THREAT",
                "risk": int(threat_score * 10),
                "risk_score": int(threat_score * 10),
                "attack_type": "DNS_THREAT",
                "action": "BLOCK",
                "is_blocked": True,
                "reason": _safe_text(be.get("reason"), "Blocked domain"),
                "evidence": [],
                "score": max(10, threat_score),
            })
        for x in blocked_rows:
            if _source_type_from_ip(_safe_text(x.get("ip"), "unknown")) in ("SYSTEM", "LOCAL DEVICE"):
                continue
            if _safe_text(x.get("ip"), "unknown") == "unknown":
                continue
            filtered.append(x)
    except Exception:
        pass

    # One row per IP: keep highest risk; drop duplicate IP / duplicate reason noise.
    by_ip = {}
    for x in filtered:
        ipk = _safe_text(x.get("ip"), "")
        if not ipk or ipk == "unknown":
            continue
        try:
            r = int(x.get("risk_score", 0) or x.get("risk", 0) or 0)
        except Exception:
            r = 0
        prev = by_ip.get(ipk)
        if prev is None or r >= int(prev.get("risk_score", 0) or prev.get("risk", 0) or 0):
            by_ip[ipk] = x

    dedup = []
    seen_reason = set()
    for x in by_ip.values():
        reason_key = (x.get("ip"), _safe_text(x.get("reason"), "")[:120])
        if reason_key in seen_reason:
            continue
        seen_reason.add(reason_key)
        dedup.append(x)
    return jsonify(dedup)

@app.route('/api/network/alerts')
def api_network_alerts():
    """Recent network alerts from the traffic analyzer."""
    return jsonify(traffic_analyzer.get_recent_alerts(n=100))

@app.route('/api/network/timeline')
def api_network_timeline():
    """Forensic event timeline from threat engine."""
    return jsonify(threat_engine.get_event_timeline(n=100))

@app.route('/api/network/packets')
def api_packets():
    """Recent captured packet metadata."""
    pkts = packet_store.get_recent(n=50)
    # Sanitize for JSON
    result = []
    for p in pkts:
        result.append({
            "datetime": p.get("datetime", ""),
            "src_ip": p.get("src_ip", ""),
            "dst_ip": p.get("dst_ip", ""),
            "ip_type": p.get("ip_type", ""),
            "protocol": p.get("protocol", ""),
            "src_port": p.get("src_port"),
            "dst_port": p.get("dst_port"),
            "payload_size": p.get("payload_size", 0),
            "flags": p.get("flags", ""),
            "process": p.get("process", ""),
            "dns_query": p.get("dns_query", "")
        })
    return jsonify(result)

@app.route('/api/network/ip/<ip_addr>')
def api_ip_detail(ip_addr):
    """Get detailed profile for a specific IP."""
    profile = traffic_analyzer.get_profile(ip_addr)
    state = threat_engine.get_state(ip_addr)
    if profile:
        return jsonify({
            "profile": profile.to_dict(),
            "threat_state": state,
        })
    return jsonify({"error": "IP not found"}), 404

@app.route('/api/network/unblock/<ip_addr>', methods=['POST'])
def api_unblock_ip(ip_addr):
    """Manually unblock an IP."""
    success = threat_engine.manual_unblock(ip_addr)
    from data.database import unblock_entity_db
    unblock_entity_db("IP", ip_addr)
    return jsonify({"success": success, "message": f"IP {ip_addr} unblocked"})






@app.route('/api/intelligence/dns-history')
def api_dns_history():
    from data.database import get_dns_history
    rows = get_dns_history(limit=100) or []
    rows = [r for r in rows if not _is_noise_domain(r.get("domain"))]
    return jsonify(rows)

@app.route('/api/intelligence/top-domains')
def api_top_domains():
    from data.database import get_dns_history
    # Simple top domains logic for now
    history = get_dns_history(limit=500)
    counts = {}
    for entry in history:
        domain = entry['domain']
        if _is_noise_domain(domain):
            continue
        counts[domain] = counts.get(domain, 0) + 1
    sorted_domains = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{"domain": d, "count": c} for d, c in sorted_domains])


@app.route('/api/honeypot/events')
def api_honeypot_events():
    from data.database import get_recent_honeypot_events
    return jsonify(get_recent_honeypot_events(limit=50))

# ─── NEW: Safety Controls - Whitelist API ───────────────────────────────────────

@app.route('/api/whitelist', methods=['GET', 'POST'])
def api_whitelist():
    from data.database import get_whitelist, add_to_whitelist
    if request.method == 'GET':
        return jsonify(get_whitelist())
    elif request.method == 'POST':
        data = request.json
        entity_type = data.get('entity_type')
        entity_value = data.get('entity_value')
        if not entity_type or not entity_value:
            return jsonify({"success": False, "message": "Missing type or value"}), 400
        success = add_to_whitelist(entity_type.upper(), entity_value)
        if success:
            return jsonify({"success": True, "message": f"Added {entity_value} to whitelist"})
        else:
            return jsonify({"success": False, "message": f"{entity_value} is already whitelisted"})

@app.route('/api/whitelist/<entity_type>/<path:entity_value>', methods=['DELETE'])
def api_whitelist_remove(entity_type, entity_value):
    from data.database import remove_from_whitelist
    remove_from_whitelist(entity_type.upper(), entity_value)
    return jsonify({"success": True, "message": f"Removed from whitelist"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

