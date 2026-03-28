from flask import Flask, request, jsonify, render_template, send_from_directory
import time
import os
import threading

# Import from new architectural layers
from data.database import init_db, log_event, get_recent_events, get_recent_actions, get_stats, get_blocked_entities
from monitoring.process_monitor import start_process_monitor, get_active_window_title
from monitoring.persistence_monitor import start_persistence_monitor
from monitoring.packet_capture import start_packet_capture, packet_store, get_ip_type
from monitoring.traffic_analyzer import traffic_analyzer
from core.threat_engine import threat_engine
from defense.honeypot import start_honeypot

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
    return jsonify(get_recent_events(limit=50))

@app.route('/api/actions')
def api_actions():
    return jsonify(get_recent_actions())

@app.route('/api/blocked')
def api_blocked():
    return jsonify(get_blocked_entities())

@app.route('/api/top-ips')
def api_top_ips():
    from data.database import get_top_ips
    return jsonify(get_top_ips())



# ─── NEW: Network Traffic & Threat Intelligence API ───────────────────────────

@app.route('/api/network/stats')
def api_network_stats():
    """Real-time network capture statistics."""
    from monitoring.packet_capture import packet_store, get_network_throughput, get_interface_stats
    pkt_stats = packet_store.get_stats()
    sent_rate, recv_rate = get_network_throughput()
    analyzer_stats = traffic_analyzer.get_stats()
    engine_stats = threat_engine.get_stats()

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
        "interfaces": get_interface_stats(),
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
    return jsonify(threat_engine.get_high_threat_ips(min_score=1))

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
    return jsonify(get_dns_history(limit=100))

@app.route('/api/intelligence/top-domains')
def api_top_domains():
    from data.database import get_dns_history
    # Simple top domains logic for now
    history = get_dns_history(limit=500)
    counts = {}
    for entry in history:
        domain = entry['domain']
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

