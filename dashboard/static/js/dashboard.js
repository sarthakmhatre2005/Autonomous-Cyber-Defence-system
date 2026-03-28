/* ══════════════════════════════════════════════════════════════════════════
   AUTONOMOUS CYBER DEFENSE — Dashboard JavaScript
   Handles all 8 tabs, real-time data, charts, packet display
   ══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ─── Global State ─────────────────────────────────────────────────────────────
const State = {
  charts: {},
  allIPProfiles: [],
  throughputHistory: { recv: Array(30).fill(0), sent: Array(30).fill(0) },
  maxThroughput: 1,          // never-zero baseline
  maxThroughputSamples: [],  // rolling 20-sample window to prevent bar collapse
  refreshIntervals: [],
};

// ─── Tab Switching ─────────────────────────────────────────────────────────────
function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  btn.classList.add('active');

  // Trigger tab-specific refresh
  if (tabId === 'packets') fetchPackets();
  if (tabId === 'forensics') fetchTimeline();
  if (tabId === 'threats') { fetchThreats(); fetchAlerts(); }
  if (tabId === 'dns') fetchDNSHistory();
  if (tabId === 'blocked') { fetchBlockedCards(); fetchActions(); }
  if (tabId === 'network') { fetchIPProfiles(); fetchNetworkStats(); }

  if (tabId === 'tools') { fetchInterfaces(); fetchWhitelist(); }
  if (tabId === 'honeypot') fetchHoneypotEvents();
}

// ─── Utility ──────────────────────────────────────────────────────────────────
function fmt(dt) {
  const d = new Date(dt);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

function fmtBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

function fmtRate(bps) {
  if (bps < 1024) return bps.toFixed(0) + ' B/s';
  if (bps < 1024 * 1024) return (bps / 1024).toFixed(1) + ' KB/s';
  return (bps / 1024 / 1024).toFixed(2) + ' MB/s';
}

function toast(msg, type = 'info') {
  const t = document.getElementById('toast');
  const colors = { info: '#3d8bff', warn: '#ff9500', danger: '#ff3d3d', success: '#00f5a0' };
  t.style.borderColor = colors[type] || colors.info;
  t.innerHTML = msg;
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 3500);
}

function scoreBadgeHTML(score) {
  let cls = 'score-n', bar = '#00f5a0', pct = Math.min((score / 15) * 100, 100);
  if (score >= 11) { cls = 'score-c'; bar = '#ff0000'; }
  else if (score >= 7) { cls = 'score-m'; bar = '#ff3d3d'; }
  else if (score >= 4) { cls = 'score-s'; bar = '#ff9500'; }
  return `<div class="score-meter">
    <div class="score-bar-bg"><div class="score-bar-fill" style="width:${pct}%;background:${bar}"></div></div>
    <span class="score-num ${cls}">${score}</span>
  </div>`;
}

function ipTypeBadge(ipType) {
  const cls = { EXTERNAL: 'badge-external', INTERNAL: 'badge-internal', LOOPBACK: 'badge-loopback' }[ipType] || 'badge-monitor';
  return `<span class="badge ${cls}">${ipType || 'UNKNOWN'}</span>`;
}

function severityBadge(sev) {
  const s = (sev || 'LOW').toUpperCase();
  return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`;
}

function tagsHTML(tags) {
  if (!tags || tags.length === 0) return '<span style="color:var(--text-muted);font-size:0.65rem">—</span>';
  return tags.map(t => `<span class="tag-pill">${t}</span>`).join('');
}

function threatLevelColor(level) {
  return { NORMAL: '#00f5a0', SUSPICIOUS: '#ff9500', MALICIOUS: '#ff3d3d', CRITICAL: '#ff0000' }[level] || '#aaa';
}


// ─── Charts ────────────────────────────────────────────────────────────────────
function initCharts() {
  // Severity doughnut — compact
  const sevCtx = document.getElementById('severity-chart').getContext('2d');
  State.charts.severity = new Chart(sevCtx, {
    type: 'doughnut',
    data: {
      labels: ['Low', 'Medium', 'High'],
      datasets: [{ data: [1, 0, 0], backgroundColor: ['#00f5a0', '#ff9500', '#ff3d3d'], borderWidth: 0, hoverOffset: 4 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#8fa8d0', font: { size: 10 }, boxWidth: 8, padding: 8 } }
      }
    }
  });

  // Throughput line chart — fixed height, smooth updates
  const thrCtx = document.getElementById('throughput-chart').getContext('2d');
  State.charts.throughput = new Chart(thrCtx, {
    type: 'line',
    data: {
      labels: Array(60).fill(''),
      datasets: [
        { label: 'Inbound (KB/s)', data: Array(60).fill(0), borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.08)', borderWidth: 1.5, tension: 0.4, pointRadius: 0, fill: true },
        { label: 'Outbound (KB/s)', data: Array(60).fill(0), borderColor: '#00f5a0', backgroundColor: 'rgba(0,245,160,0.06)', borderWidth: 1.5, tension: 0.4, pointRadius: 0, fill: true },
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          labels: { color: '#8fa8d0', boxWidth: 8, font: { size: 10 }, padding: 6 }
        }
      },
      scales: {
        x: { display: false },
        y: {
          min: 0,
          border: { display: false },
          grid: { color: 'rgba(30,80,200,0.1)' },
          ticks: { color: '#8fa8d0', font: { size: 9 }, maxTicksLimit: 4 }
        }
      }
    }
  });
  // Expand history to match new 60-point window
  State.throughputHistory.recv = Array(60).fill(0);
  State.throughputHistory.sent = Array(60).fill(0);

  // Protocol pie — compact
  const protoCtx = document.getElementById('protocol-chart').getContext('2d');
  State.charts.protocol = new Chart(protoCtx, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'OTHER'],
      datasets: [{ data: [0, 0, 0, 0], backgroundColor: ['#3d8bff', '#b44bff', '#ff9500', '#8fa8d0'], borderWidth: 0, hoverOffset: 4 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: {
        legend: { position: 'right', labels: { color: '#8fa8d0', boxWidth: 8, font: { size: 10 }, padding: 6 } }
      }
    }
  });
}


// ─── OVERVIEW: Stats & KPIs ────────────────────────────────────────────────────
async function fetchNetworkStats() {
  try {
    const res = await fetch('/api/network/stats');
    const d = await res.json();
    const pc = d.packet_capture || {};
    const ta = d.traffic_analysis || {};
    const te = d.threat_engine || {};
    const nt = d.network_throughput || {};

    // Top bar badges
    document.getElementById('ext-ip-count').textContent = pc.unique_ips || 0;
    document.getElementById('threat-count').textContent  = te.high_threat_ips || 0;
    document.getElementById('blocked-count').textContent = te.blocked_ips || 0;

    // KPI cards
    document.getElementById('kpi-total-packets').textContent = (pc.total_captured || 0).toLocaleString();
    document.getElementById('kpi-external-pkts').textContent = (pc.external_captured || 0).toLocaleString();
    document.getElementById('kpi-unique-ips').textContent    = pc.unique_ips || 0;
    document.getElementById('kpi-high-threats').textContent  = te.high_threat_ips || 0;
    document.getElementById('kpi-blocked-total').textContent = te.blocked_ips || 0;

    // Network tab KPIs (guarded — elements may not be present in current layout)
    const _s = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    _s('net-ext-ips', ta.external_ips || 0);
    _s('net-int-ips', ta.internal_ips || 0);
    _s('net-flagged',  ta.flagged_ips  || 0);
    _s('net-alerts',   ta.recent_alerts || 0);

    // Throughput bars — use rolling window max to prevent bars from freezing at 0%
    const recv = nt.kb_recv_per_sec || 0;
    const sent = nt.kb_sent_per_sec || 0;
    document.getElementById('thr-recv-val').textContent = fmtRate(nt.bytes_recv_per_sec || 0);
    document.getElementById('thr-sent-val').textContent = fmtRate(nt.bytes_sent_per_sec || 0);

    // Rolling max: keep last 30 samples, floor at 0.5 KB/s so bars never fully collapse
    State.maxThroughputSamples.push(Math.max(recv, sent, 0.01));
    if (State.maxThroughputSamples.length > 30) State.maxThroughputSamples.shift();
    const rollingMax = Math.max(...State.maxThroughputSamples, 0.5);
    State.maxThroughput = rollingMax;

    const recvPct = Math.min((recv / rollingMax) * 100, 100);
    const sentPct = Math.min((sent / rollingMax) * 100, 100);
    document.getElementById('thr-recv-bar').style.width = recvPct.toFixed(1) + '%';
    document.getElementById('thr-sent-bar').style.width = sentPct.toFixed(1) + '%';

    // Throughput chart — push samples into rolling history, then sync to chart
    State.throughputHistory.recv.push(recv);
    State.throughputHistory.recv.shift();
    State.throughputHistory.sent.push(sent);
    State.throughputHistory.sent.shift();

    if (State.charts.throughput) {
      // Write directly into existing dataset arrays (avoids allocation on every tick)
      const ds0 = State.charts.throughput.data.datasets[0].data;
      const ds1 = State.charts.throughput.data.datasets[1].data;
      const h = State.throughputHistory;
      for (let i = 0; i < h.recv.length; i++) { ds0[i] = h.recv[i]; ds1[i] = h.sent[i]; }
      State.charts.throughput.update();  // Let Chart.js use its own animation=false setting
    }

    // Interfaces (tools tab)
    if (d.interfaces) renderInterfaces(d.interfaces);

  } catch(e) {}
}

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    const d = await res.json();
  } catch(e) {}
}


// ─── OVERVIEW: Events Feed ────────────────────────────────────────────────────
async function fetchEvents() {
  try {
    const res = await fetch('/api/events');
    const data = await res.json();
    const tbody = document.getElementById('events-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0 };
    const protoCounts = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
    data.forEach(ev => {
      const ts = fmt(ev.timestamp);
      const sev = (ev.severity || 'LOW').toUpperCase();
      if (counts[sev] !== undefined) counts[sev]++;
 
      let eventName = (ev.protocol && ev.protocol !== '—') ? ev.protocol : 'HEURISTIC';
      let displayDetails = '';
      
      try {
        const d = typeof ev.details === 'string' ? JSON.parse(ev.details) : ev.details;
        
        // Pick the best event name
        eventName = ev.protocol || d.alert_type || d.type || 'SYSTEM';
        if (eventName === 'SYSTEM' && (d.app || d.title || d.pid)) {
            eventName = `PROC: ${d.app || d.title || d.pid}`;
        }
        
        // Format details nicely
        if (d.detail || d.reason) {
            displayDetails = d.detail || d.reason;
        } else {
            // Fallback: show key-value pairs briefly
            displayDetails = Object.entries(d)
                .filter(([k,v]) => !['threat_score', 'threat_level', 'alert_type', 'action'].includes(k))
                .map(([k,v]) => `${k}:${v}`).join(', ');
        }
        if (!displayDetails) displayDetails = ev.details || '';
      } catch(e) { displayDetails = ev.details || ''; }
 
      const score = ev.anomaly_score ? (ev.anomaly_score * 10).toFixed(1) : '0';
 
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);color:var(--text-muted)">${ts}</td>
        <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${ev.source_ip}</td>
        <td>${ipTypeBadge(ev.active_window === 'EXTERNAL' ? 'EXTERNAL' : (ev.active_window === 'LOOPBACK' ? 'LOOPBACK' : 'INTERNAL'))}</td>
        <td style="color:var(--text-secondary);font-weight:500">${eventName} ${ev.dest_ip && ev.dest_ip !== 'LOCAL' ? '→ ' + ev.dest_ip : ''}</td>
        <td>${severityBadge(sev)}</td>
        <td>${scoreBadgeHTML(parseFloat(score))}</td>
        <td style="color:var(--text-muted)">${displayDetails.substring(0, 70)}</td>
      `;
      tbody.appendChild(tr);
    });

    // Update severity chart
    if (State.charts.severity) {
      State.charts.severity.data.datasets[0].data = [counts.LOW, counts.MEDIUM, counts.HIGH];
      State.charts.severity.update('none');
    }

  } catch(e) {}
}


// ─── NETWORK TAB: IP Profiles ──────────────────────────────────────────────────
async function fetchIPProfiles() {
  try {
    const res = await fetch('/api/network/ip-profiles');
    State.allIPProfiles = await res.json();
    renderIPProfiles(State.allIPProfiles);
  } catch(e) {}
}

function filterIPProfiles() {
  const typeFilter = document.getElementById('ip-type-filter')?.value || 'ALL';
  const threatFilter = document.getElementById('threat-filter')?.value || 'ALL';

  let filtered = State.allIPProfiles;

  if (typeFilter !== 'ALL') {
    filtered = filtered.filter(p => p.ip_type === typeFilter);
  }

  if (threatFilter === 'SUSPICIOUS') {
    filtered = filtered.filter(p => p.threat_score >= 4);
  } else if (threatFilter === 'MALICIOUS') {
    filtered = filtered.filter(p => p.threat_score >= 7);
  }

  renderIPProfiles(filtered);
}

function renderIPProfiles(profiles) {
  const tbody = document.getElementById('ip-profiles-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  profiles.forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${p.ip}</td>
      <td>${ipTypeBadge(p.ip_type)}</td>
      <td style="text-align:right">${p.connection_count}</td>
      <td style="text-align:right">${p.unique_ports}</td>
      <td>${(p.protocols || []).join(', ') || '—'}</td>
      <td>${scoreBadgeHTML(p.threat_score || 0)}</td>
      <td>${tagsHTML(p.threat_tags)}</td>
      <td style="color:var(--text-muted)">${fmt(p.last_seen)}</td>
    `;
    tbody.appendChild(tr);
  });
}


// ─── EXTERNAL IPs TAB ──────────────────────────────────────────────────────────
async function fetchExternalIPs() {
  try {
    const res = await fetch('/api/network/external-ips');
    const data = await res.json();

    let total = data.length;
    let malicious = data.filter(p => p.threat_score >= 7).length;
    let suspicious = data.filter(p => p.threat_score >= 4 && p.threat_score < 7).length;
    let clean = data.filter(p => p.threat_score < 4).length;

    document.getElementById('ext-total').textContent = total;
    document.getElementById('ext-malicious').textContent = malicious;
    document.getElementById('ext-suspicious').textContent = suspicious;
    document.getElementById('ext-clean').textContent = clean;

    const tbody = document.getElementById('external-ips-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    // Sort by threat score desc
    data.sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0));

    data.forEach(p => {
      const level = p.threat_score >= 7 ? 'MALICIOUS' : p.threat_score >= 4 ? 'SUSPICIOUS' : 'NORMAL';
      const levelBadge = `<span class="badge badge-${level === 'MALICIOUS' ? 'high' : level === 'SUSPICIOUS' ? 'medium' : 'low'}">${level}</span>`;
      const actions = p.threat_score >= 4
        ? `<button class="unblock-btn" onclick="manualUnblockIP('${p.ip}')">🔓 Unblock</button>`
        : '—';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);color:var(--accent-orange)">${p.ip}</td>
        <td style="text-align:right">${p.connection_count}</td>
        <td style="text-align:right">${p.unique_ports}</td>
        <td>${fmtBytes(p.total_bytes || 0)}</td>
        <td>${scoreBadgeHTML(p.threat_score || 0)}</td>
        <td>${levelBadge}</td>
        <td>${tagsHTML(p.threat_tags)}</td>
        <td style="color:var(--text-muted);font-family:var(--font-mono)">${fmt(p.first_seen)}</td>
        <td>${actions}</td>
      `;
      tbody.appendChild(tr);
    });

  } catch(e) {}
}


// ─── PACKET CAPTURE TAB ────────────────────────────────────────────────────────
async function fetchPackets() {
  try {
    const res = await fetch('/api/network/packets');
    const data = await res.json();
    const tbody = document.getElementById('packets-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const protoCounts = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
    const portSet = new Set();
    const HIGH_RISK_PORTS = new Set([4444, 1234, 31337, 12345, 54321, 8080, 8443, 6666, 6667, 9001]);

    data.slice().reverse().forEach(p => {
      const ts = p.datetime ? fmt(p.datetime) : '';
      const proto = p.protocol || 'OTHER';
      if (protoCounts[proto] !== undefined) protoCounts[proto]++;
      else protoCounts.OTHER++;

      if (p.dst_port) portSet.add(p.dst_port);

      const ipTypeClass = p.ip_type === 'EXTERNAL' ? 'style="color:var(--accent-orange)"'
        : p.ip_type === 'INTERNAL' ? 'style="color:var(--accent-cyan)"'
        : 'style="color:var(--text-muted)"';

      const protoColor = { TCP: '#3d8bff', UDP: '#b44bff', ICMP: '#ff9500', QUIC: '#00f5a0', OTHER: '#8fa8d0' }[proto] || '#8fa8d0';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color:var(--text-muted)">${ts}</td>
        <td ${ipTypeClass}>${p.src_ip || '—'}</td>
        <td style="color:var(--text-secondary)">${p.dst_ip && p.dst_ip !== 'LOCAL' ? p.dst_ip : '→ localhost'}</td>
        <td>${ipTypeBadge(p.ip_type)}</td>
        <td style="color:${protoColor}">${proto}</td>
        <td>${p.src_port || '—'}</td>
        <td style="color:${HIGH_RISK_PORTS.has(p.dst_port) ? 'var(--accent-red)' : 'inherit'}">${p.dst_port || '—'}</td>
        <td>${fmtBytes(p.payload_size || 0)}</td>
        <td style="color:var(--text-muted)">${p.flags || '—'}</td>
        <td style="color:var(--accent-purple)">${p.process || '—'}</td>
      `;
      tbody.appendChild(tr);
    });

    // Update protocol chart
    if (State.charts.protocol) {
      State.charts.protocol.data.datasets[0].data = [
        protoCounts.TCP, protoCounts.UDP, protoCounts.ICMP, protoCounts.OTHER
      ];
      State.charts.protocol.update('none');
    }

    // Port activity
    const portGrid = document.getElementById('port-activity');
    if (portGrid) {
      portGrid.innerHTML = '';
      [...portSet].slice(0, 60).sort((a, b) => a - b).forEach(port => {
        const div = document.createElement('div');
        div.className = `port-tag${HIGH_RISK_PORTS.has(port) ? ' port-risky' : ''}`;
        div.textContent = port;
        portGrid.appendChild(div);
      });
    }

  } catch(e) {}
}


// ─── THREAT INTEL TAB ──────────────────────────────────────────────────────────
async function fetchThreats() {
  try {
    const res = await fetch('/api/network/top-threats');
    const data = await res.json();
    const grid = document.getElementById('threat-cards');
    if (!grid) return;
    grid.innerHTML = '';

    if (data.length === 0) {
      grid.innerHTML = '<div style="padding:1rem;color:var(--text-muted)">No threats detected yet — system is monitoring.</div>';
      return;
    }

    data.forEach(s => {
      const level = s.threat_level || 'NORMAL';
      const color = threatLevelColor(level);
      const evidence = s.evidence || [];

      const card = document.createElement('div');
      card.className = 'threat-card';
      card.innerHTML = `
        <div class="threat-card-header">
          <span class="threat-ip">${s.ip}</span>
          <span class="threat-score-big" style="color:${color}">${s.score}</span>
        </div>
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
          ${ipTypeBadge(s.threat_state?.ip_type || '')}
          <span class="badge" style="background:rgba(255,100,100,0.1);color:${color};border:1px solid ${color}40">${level}</span>
          <span class="badge badge-${(s.action||'monitor').toLowerCase().replace('_','-')}">${s.action || 'MONITOR'}</span>
        </div>
        <div class="threat-tags">${tagsHTML(s.threat_tags)}</div>
        <div class="threat-evidence">
          ${evidence.map(e => `
            <div class="threat-evidence-item">
              <span class="evidence-time">${e.timestamp ? fmt(e.timestamp) : ''}</span>
              <span class="evidence-detail">+${e.score_added||0} · ${e.type||''}: ${(e.reason||'').substring(0,60)}</span>
            </div>
          `).join('')}
        </div>
      `;
      grid.appendChild(card);
    });
  } catch(e) {}
}

async function fetchAlerts() {
  try {
    const res = await fetch('/api/network/alerts');
    const data = await res.json();
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    data.slice().reverse().slice(0, 50).forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);color:var(--text-muted)">${fmt(a.timestamp * 1000 || Date.now())}</td>
        <td style="font-family:var(--font-mono);color:var(--accent-orange)">${a.ip || '—'}</td>
        <td><span class="tag-pill">${a.type || '—'}</span></td>
        <td>${ipTypeBadge(a.ip_type)}</td>
        <td>${scoreBadgeHTML(a.score || 0)}</td>
        <td>${severityBadge(a.severity)}</td>
        <td style="color:var(--text-muted)">${(a.detail || '').substring(0, 80)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch(e) {}
}


// ─── BLOCKED TAB ───────────────────────────────────────────────────────────────
async function fetchBlockedCards() {
  try {
    const res = await fetch('/api/blocked');
    const data = await res.json();
    const grid = document.getElementById('blocked-cards-grid');
    if (!grid) return;
    grid.innerHTML = '';

    if (data.length === 0) {
      grid.innerHTML = '<div style="padding:1rem;color:var(--text-muted);grid-column:1/-1">No blocked entities. System is monitoring.</div>';
      return;
    }

    data.forEach(e => {
      const card = document.createElement('div');
      card.className = 'blocked-card';
      card.innerHTML = `
        <div class="blocked-card-header">
          <span class="blocked-type">${e.entity_type}</span>
          <span class="badge badge-block">BLOCKED</span>
        </div>
        <div class="blocked-value">${e.entity_value}</div>
        <div class="blocked-reason">${(e.reason || '').substring(0, 100)}</div>
        <div class="blocked-time">Blocked at: ${new Date(e.timestamp).toLocaleString()}</div>
        ${e.entity_type === 'IP' ? `<button class="unblock-btn" onclick="manualUnblockIP('${e.entity_value}')">🔓 Manual Unblock</button>` : ''}
      `;
      grid.appendChild(card);
    });
  } catch(e) {}
}

async function fetchActions() {
  try {
    const res = await fetch('/api/actions');
    const data = await res.json();
    const tbody = document.getElementById('actions-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    data.slice(0, 50).forEach(a => {
      const badgeCls = a.action_type === 'BLOCK' || a.action_type === 'TEMP_BLOCK' ? 'badge-high'
        : a.action_type === 'UNBLOCK' || a.action_type === 'MANUAL_UNBLOCK' ? 'badge-low'
        : 'badge-medium';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);color:var(--text-muted)">${fmt(a.timestamp)}</td>
        <td>${ipTypeBadge(a.entity_type === 'IP' ? 'EXTERNAL' : '')}<span style="margin-left:4px;color:var(--text-muted)">${a.entity_type}</span></td>
        <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${a.entity_value}</td>
        <td><span class="badge ${badgeCls}">${a.action_type}</span></td>
        <td style="color:var(--text-muted)">${(a.reason || '').substring(0, 80)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch(e) {}
}


// ─── FORENSICS TAB ────────────────────────────────────────────────────────────
async function fetchTimeline() {
  try {
    const res = await fetch('/api/network/timeline');
    const data = await res.json();
    const container = document.getElementById('forensic-timeline');
    if (!container) return;
    container.innerHTML = '';

    if (data.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:1rem">No forensic events yet.</div>';
      return;
    }

    data.slice().reverse().forEach(e => {
      const div = document.createElement('div');
      div.className = 'timeline-entry';
      const color = threatLevelColor(e.severity === 'HIGH' ? 'MALICIOUS' : e.severity === 'MEDIUM' ? 'SUSPICIOUS' : 'NORMAL');
      div.innerHTML = `
        <span class="tl-time">${e.timestamp ? fmt(e.timestamp) : '—'}</span>
        <span class="tl-ip">${e.ip || '—'}</span>
        <span class="tl-type"><span class="tag-pill">${e.event_type || '—'}</span></span>
        <span class="tl-score" style="color:${color}">+${e.score_delta||0} → ${e.cumulative_score||0}</span>
        <span class="tl-detail">${(e.detail || '').substring(0, 100)}</span>
      `;
      container.appendChild(div);
    });
  } catch(e) {}
}


// ─── TOOLS TAB ────────────────────────────────────────────────────────────────
async function checkPhishing() {
  const url = document.getElementById('phishing-url')?.value;
  const box = document.getElementById('phishing-result');
  if (!box) return;
  box.innerHTML = '<span style="color:var(--accent-blue)">Analyzing URL...</span>';

  try {
    const res = await fetch('/api/phishing/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const d = await res.json();
    const cls = d.risk_level === 'HIGH' ? 'badge-high' : d.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low';
    box.innerHTML = `<strong>Risk Level:</strong> <span class="badge ${cls}">${d.risk_level}</span><br><p style="margin-top:6px">${d.explanation || ''}</p>`;
    if (d.risk_level === 'HIGH') toast('🚨 HIGH RISK URL blocked!', 'danger');
  } catch(e) {
    box.innerHTML = '<span style="color:var(--accent-red)">Error analyzing URL.</span>';
  }
}

async function manualUnblock() {
  const ip = document.getElementById('unblock-ip')?.value?.trim();
  if (!ip) return;
  const box = document.getElementById('unblock-result');
  if (box) box.innerHTML = '<span style="color:var(--accent-blue)">Unblocking...</span>';

  await manualUnblockIP(ip, box);
}

async function manualUnblockIP(ip, resultBox) {
  try {
    const res = await fetch(`/api/network/unblock/${ip}`, { method: 'POST' });
    const d = await res.json();
    const msg = d.success ? `✅ ${ip} successfully unblocked.` : `⚠️ Failed to unblock ${ip}`;
    if (resultBox) resultBox.innerHTML = `<span style="color:${d.success ? 'var(--accent-green)' : 'var(--accent-orange)'}">${msg}</span>`;
    toast(msg, d.success ? 'success' : 'warn');
    // Refresh blocked lists
    fetchBlockedCards();
    fetchExternalIPs();
  } catch(e) {
    toast('Error during unblock.', 'danger');
  }
}

// ─── WHITELIST FUNCTIONS ──────────────────────────────────────────────────────

async function fetchWhitelist() {
  try {
    const res = await fetch('/api/whitelist');
    const data = await res.json();
    const tbody = document.getElementById('whitelist-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    data.forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge badge-info">${item.entity_type}</span></td>
        <td style="font-family:var(--font-mono);">${item.entity_value}</td>
        <td><button class="tool-btn btn-red" style="padding:4px 8px;font-size:0.8rem;" onclick="removeFromWhitelist('${item.entity_type}', '${item.entity_value}')">❌ Remove</button></td>
      `;
      tbody.appendChild(tr);
    });
  } catch(e) { console.error("Whitelist fetch error:", e); }
}

async function addToWhitelist() {
  const type = document.getElementById('wl-type')?.value;
  const value = document.getElementById('wl-value')?.value?.trim();
  if (!value) return;

  const box = document.getElementById('wl-result');
  try {
    const res = await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_type: type, entity_value: value })
    });
    const d = await res.json();
    if (d.success) {
      toast(d.message, 'success');
      document.getElementById('wl-value').value = '';
      fetchWhitelist();
    } else {
      toast(d.message, 'warn');
      if (box) box.innerHTML = `<span style="color:var(--accent-orange)">${d.message}</span>`;
    }
  } catch(e) { toast('Error adding to whitelist.', 'danger'); }
}

async function removeFromWhitelist(type, value) {
  try {
    const res = await fetch(`/api/whitelist/${encodeURIComponent(type)}/${encodeURIComponent(value)}`, {
      method: 'DELETE'
    });
    const d = await res.json();
    if (d.success) {
      toast(d.message, 'success');
      fetchWhitelist();
    }
  } catch(e) { toast('Error removing from whitelist.', 'danger'); }
}

function renderInterfaces(interfaces) {
  const grid = document.getElementById('interfaces-grid');
  if (!grid) return;
  grid.innerHTML = '';
  interfaces.forEach(iface => {
    const div = document.createElement('div');
    div.className = 'iface-card';
    div.innerHTML = `
      <div class="iface-name">${iface.interface}</div>
      <div class="iface-status">${iface.is_up ? '<span style="color:var(--accent-green)">● UP</span>' : '<span style="color:var(--text-muted)">○ DOWN</span>'} · ${iface.speed || 0} Mbps</div>
      <div class="iface-ips">${(iface.ips || []).join(', ') || 'No IPv4'}</div>
    `;
    grid.appendChild(div);
  });
}

async function fetchInterfaces() {
  try {
    const res = await fetch('/api/network/stats');
    const d = await res.json();
    if (d.interfaces) renderInterfaces(d.interfaces);
  } catch(e) {}
}



async function fetchAttackerProfiles() {
  try {
    const res = await fetch('/api/intelligence/attacker-profiles');
    const data = await res.json();
    const tbody = document.getElementById('profiles-tbody');
    tbody.innerHTML = '';
    
    data.forEach(p => {
      const row = `
        <tr>
          <td class="ip-cell">${p.source_ip}</td>
          <td>${p.first_seen.split('T')[1].split('.')[0]}</td>
          <td>${p.last_seen.split('T')[1].split('.')[0]}</td>
          <td><span class="badge ${p.scan_pattern.includes('AGGRESSIVE') ? 'badge-error' : 'badge-warning'}">${p.scan_pattern}</span></td>
          <td class="mono">${p.preferred_ports}</td>
          <td><span class="badge badge-info">${p.tool_guess}</span></td>
        </tr>
      `;
      tbody.insertAdjacentHTML('beforeend', row);
    });
  } catch(e) { console.error("Profile fetch error", e); }
}

async function fetchDeceptionLogs() {
    try {
        const res = await fetch('/api/intelligence/honeypot-logs');
        const logs = await res.json();
        const body = document.getElementById('deception-body');
        if (!body) return; // Added check for body
        body.innerHTML = '';

        logs.forEach(log => {
            const row = `<tr>
                <td>${log.timestamp.split('T')[1].split('.')[0]}</td>
                <td>${log.source_ip}</td>
                <td><span class="badge badge-warning">${log.target_port}</span></td>
                <td><code>${log.payload || 'None'}</code></td>
            </tr>`;
            body.innerHTML += row;
        });
    } catch (e) { console.error("Error fetching deception logs:", e); }
}

async function fetchDNSHistory() {
    try {
        const res = await fetch('/api/intelligence/dns-history');
        const history = await res.json();
        const body = document.getElementById('dns-body');
        if (!body) return;
        body.innerHTML = '';

        history.forEach(item => {
            const threatClass = item.threat_score >= 7 ? 'threat-high' : (item.threat_score >= 4 ? 'threat-medium' : '');
            const badgeClass = item.threat_score >= 7 ? 'badge-high' : (item.threat_score >= 4 ? 'badge-medium' : 'badge-low');
            
            const tr = document.createElement('tr');
            tr.className = threatClass;
            tr.innerHTML = `
                <td style="color:var(--text-muted)">${fmt(item.timestamp)}</td>
                <td><strong style="color:var(--text-primary)">${item.domain}</strong></td>
                <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${item.requesting_ip}</td>
                <td style="color:var(--accent-purple)">${item.process || '—'}</td>
                <td>${scoreBadgeHTML(item.threat_score)}</td>
                <td><span class="badge ${badgeClass}">${item.threat_score >= 6 ? 'RE-ROUTED' : 'CLEAN'}</span></td>
            `;
            body.appendChild(tr);
        });
    } catch (e) {
        console.error("Error fetching DNS history:", e);
    }
}

async function fetchTopDomains() {
    try {
        const res = await fetch('/api/intelligence/top-domains');
        const domains = await res.json();
        const container = document.getElementById('top-domains-list');
        if (!container) return; // Added check for container
        container.innerHTML = '';

        domains.forEach(d => {
            container.innerHTML += `<div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                <span>${d.domain}</span>
                <span class="badge badge-info">${d.count} reqs</span>
            </div>`;
        });
    } catch (e) {
        console.error("Error fetching top domains:", e);
    }
}

async function fetchHoneypotEvents() {
    try {
        const res = await fetch('/api/honeypot/events');
        const data = await res.json();
        const tbody = document.getElementById('honeypot-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        
        document.getElementById('kpi-honeypot-hits').textContent = data.length;

        data.forEach(ev => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family:var(--font-mono);color:var(--text-muted)">${new Date(ev.timestamp).toLocaleString()}</td>
                <td style="font-family:var(--font-mono);color:var(--accent-red)">${ev.source_ip}</td>
                <td>${ev.source_port}</td>
                <td><span class="badge badge-warning">${ev.honeypot_port}</span></td>
                <td style="color:var(--text-secondary)">${ev.data}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error fetching honeypot events:", e);
    }
}


// ─── Auto Refresh Setup ────────────────────────────────────────────────────────
function startAutoRefresh() {
  // Core stats — every 3s
  fetchNetworkStats();
  setInterval(fetchNetworkStats, 3000);

  // Events — every 2s
  fetchEvents();
  setInterval(fetchEvents, 2000);

  // Tab-specific pollers
  setInterval(() => {
    const activeTab = document.querySelector('.tab-btn.active')?.dataset?.tab;
    if (activeTab === 'network') fetchIPProfiles();
    if (activeTab === 'packets') fetchPackets();
    if (activeTab === 'threats') { fetchThreats(); fetchAlerts(); }
    if (activeTab === 'blocked') { fetchBlockedCards(); fetchActions(); }
    if (activeTab === 'forensics') fetchTimeline();
    if (activeTab === 'dns') { fetchDNSHistory(); fetchTopDomains(); }
    if (activeTab === 'honeypot') fetchHoneypotEvents();
  }, 5000);
}


// ─── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  startAutoRefresh();
  toast('🛡 Autonomous Cyber Defense System — ONLINE', 'success');
});
