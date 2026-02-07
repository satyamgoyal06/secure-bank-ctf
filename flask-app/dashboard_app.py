"""
Admin Dashboard Application - Separate from main website
Only accessible locally on port 8080
"""
from flask import Blueprint, jsonify, Response, request, session, redirect, url_for
from pymongo import MongoClient
import os

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')

# Use same config as main app via environment or passed explicitly?
# Vercel env vars are global.

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dashboard-secret')

# MongoDB connection
mongo_client = MongoClient(os.environ.get('MONGO_URI', 'mongodb://mongodb:27017/ctf_db'))
# MongoDB connection (duplicate, but acceptable for now)
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongodb:27017/ctf_db')
mongo_client = MongoClient(MONGO_URI, connect=False)
db = mongo_client.get_database('ctf_db')

# Dashboard HTML embedded directly to avoid file serving issues
DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff88;
            padding: 20px;
            min-height: 100vh;
        }
        .header {
            text-align: center;
            padding: 20px;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff88;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .header h1 { color: #00ff88; text-shadow: 0 0 10px #00ff88; font-size: 2rem; }
        .timestamp { color: #ffff00; margin-top: 10px; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab-btn {
            padding: 10px 20px;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff88;
            border-radius: 8px;
            color: #00ff88;
            cursor: pointer;
            font-family: inherit;
            font-size: 14px;
            transition: all 0.3s;
        }
        .tab-btn:hover, .tab-btn.active { background: #00ff88; color: #000; }
        .container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .panel {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff88;
            padding: 15px;
            border-radius: 10px;
        }
        .panel h2 {
            color: #00ff88;
            border-bottom: 1px solid #00ff88;
            padding-bottom: 10px;
            margin-bottom: 15px;
            font-size: 1.2rem;
        }
        .stat { padding: 8px 0; font-size: 14px; display: flex; justify-content: space-between; }
        .stat-label { color: #00aaff; }
        .stat-value { color: #ffff00; font-weight: bold; }
        .log-entry {
            padding: 10px;
            margin: 8px 0;
            background: rgba(0, 0, 0, 0.5);
            border-left: 4px solid #00ff88;
            font-size: 12px;
            border-radius: 0 5px 5px 0;
        }
        .log-entry.blocked { border-left-color: #ff0000; background: rgba(255, 0, 0, 0.1); }
        .log-ip { color: #00aaff; font-weight: bold; }
        .log-type { color: #ff6b6b; font-weight: bold; }
        .log-payload {
            color: #ffcc00;
            font-family: monospace;
            word-break: break-all;
            margin-top: 5px;
            padding: 5px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 3px;
        }
        .log-time { color: #888; font-size: 11px; }
        .full-width { grid-column: 1 / -1; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid rgba(0, 255, 136, 0.2); font-size: 12px; }
        th { color: #00aaff; background: rgba(0, 0, 0, 0.5); }
        td { color: #e0e0e0; }
        .no-data { color: #666; text-align: center; padding: 20px; }
        .user-card {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
        }
        .user-card .field { display: flex; margin-bottom: 8px; }
        .user-card .field-name { color: #00aaff; min-width: 120px; }
        .user-card .field-value { color: #e0e0e0; word-break: break-all; }
        .section { display: none; }
        .section.active { display: block; }
        .refresh-btn {
            background: transparent;
            border: 1px solid #00ff88;
            color: #00ff88;
            padding: 5px 10px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 10px;
        }
        .refresh-btn:hover { background: rgba(0, 255, 136, 0.2); }
        .db-panel { max-height: 500px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ADMIN SECURITY DASHBOARD 🛡️</h1>
        <div class="timestamp">Last Updated: <span id="current-time"></span></div>
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="showSection('security')">🚨 Security Logs</button>
        <button class="tab-btn" onclick="showSection('database')">🗄️ Database Viewer</button>
        <button class="tab-btn" onclick="showSection('commands')">💻 Command Logs</button>
        <button class="tab-btn" onclick="showSection('blocked')">⛔ Blocked IPs</button>
        <button class="tab-btn" onclick="showSection('visitors')">👁️ Active Visitors</button>
        <button class="tab-btn" onclick="showSection('ids')">🚨 IDS Alerts</button>
    </div>

    <div id="security-section" class="section active">
        <div class="container">
            <div class="panel">
                <h2>📊 Attack Statistics <button class="refresh-btn" onclick="loadAttackStats()">↻</button></h2>
                <div id="attack-stats"><div class="no-data">Loading...</div></div>
            </div>
            <div class="panel">
                <h2>🚫 Rate-Limited IPs</h2>
                <div id="blocked-ips"><div class="no-data">No blocked IPs</div></div>
            </div>
            <div class="panel full-width">
                <h2>🚨 Recent Attack Attempts <button class="refresh-btn" onclick="loadAttackLogs()">↻</button></h2>
                <div id="attack-logs"><div class="no-data">Waiting for attacks...</div></div>
            </div>
        </div>
    </div>

    <div id="database-section" class="section">
        <div class="container">
            <div class="panel">
                <h2>📈 Database Stats <button class="refresh-btn" onclick="loadDbStats()">↻</button></h2>
                <div id="db-stats"><div class="no-data">Loading...</div></div>
            </div>
            <div class="panel">
                <h2>👥 Users Collection <button class="refresh-btn" onclick="loadUsers()">↻</button></h2>
                <div id="db-users" class="db-panel"><div class="no-data">Loading...</div></div>
            </div>
            <div class="panel full-width">
                <h2>📋 Attack Logs Collection <button class="refresh-btn" onclick="loadAttackLogsDb()">↻</button></h2>
                <div id="db-attack-logs" class="db-panel"><div class="no-data">Loading...</div></div>
            </div>
        </div>
    </div>

    <div id="commands-section" class="section">
        <div class="container">
            <div class="panel full-width">
                <h2>💻 User Command Logs <button class="refresh-btn" onclick="loadCommandLogs()">↻</button></h2>
                <div id="command-logs" class="db-panel"><div class="no-data">Loading...</div></div>
            </div>
        </div>
    </div>

    <div id="blocked-section" class="section">
        <div class="container">
            <div class="panel full-width">
                <h2>⛔ Currently Blocked IPs <button class="refresh-btn" onclick="loadBlockedIps()">↻</button></h2>
                <div id="blocked-ips-list" class="db-panel"><div class="no-data">Loading...</div></div>
            </div>
        </div>
    </div>

    <div id="visitors-section" class="section">
        <div class="container">
            <div class="panel full-width">
                <h2>👁️ Active Visitors <button class="refresh-btn" onclick="loadActiveVisitors()">↻</button></h2>
                <div id="active-visitors" class="db-panel"><div class="no-data">Loading...</div></div>
            </div>
        </div>
    </div>

    <div id="ids-section" class="section">
        <div class="container">
            <div class="panel full-width">
                <h2>🚨 Suricata IDS Alerts <button class="refresh-btn" onclick="loadIdsAlerts()">↻</button></h2>
                <div id="ids-alerts" class="db-panel"><div class="no-data">Loading...</div></div>
            </div>
        </div>
    </div>

    <script>
        function updateTime() { document.getElementById('current-time').textContent = new Date().toLocaleString(); }
        function showSection(section) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(section + '-section').classList.add('active');
            event.target.classList.add('active');
            if (section === 'database') { loadDbStats(); loadUsers(); loadAttackLogsDb(); }
            if (section === 'commands') { loadCommandLogs(); }
            if (section === 'blocked') { loadBlockedIps(); }
            if (section === 'visitors') { loadActiveVisitors(); }
            if (section === 'ids') { loadIdsAlerts(); }
        }
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        async function loadAttackLogs() {
            try {
                const response = await fetch('api/attacks');
                const attacks = await response.json();
                const logsContainer = document.getElementById('attack-logs');
                if (attacks.length === 0) { logsContainer.innerHTML = '<div class="no-data">No attacks recorded yet</div>'; return; }
                const logsHtml = attacks.slice(0, 20).map(attack => {
                    let entryClass = 'log-entry';
                    if (attack.blocked) entryClass += ' blocked';
                    const time = attack.timestamp ? new Date(attack.timestamp).toLocaleString() : 'Unknown';
                    return `<div class="${entryClass}">
                        <div style="display: flex; justify-content: space-between;">
                            <span class="log-ip">${escapeHtml(attack.ip)}</span>
                            <span class="log-type">${escapeHtml(attack.attack_type || 'Unknown')}</span>
                        </div>
                        ${attack.payload ? `<div class="log-payload">${escapeHtml(attack.payload)}</div>` : ''}
                        <div class="log-time">${time} | ${escapeHtml(attack.endpoint)}</div>
                    </div>`;
                }).join('');
                logsContainer.innerHTML = logsHtml;
            } catch (error) { document.getElementById('attack-logs').innerHTML = '<div class="no-data">⚠️ Error loading</div>'; }
        }
        async function loadAttackStats() {
            try {
                const response = await fetch('api/attack-stats');
                const data = await response.json();
                const statsContainer = document.getElementById('attack-stats');
                if (data.stats && data.stats.length > 0) {
                    statsContainer.innerHTML = data.stats.map(stat => `<div class="stat"><span class="stat-label">${escapeHtml(stat._id || 'Unknown')}</span><span class="stat-value">${stat.count}</span></div>`).join('');
                } else { statsContainer.innerHTML = '<div class="no-data">No attacks</div>'; }
                const blockedContainer = document.getElementById('blocked-ips');
                if (data.blocked_ips && data.blocked_ips.length > 0) {
                    blockedContainer.innerHTML = data.blocked_ips.slice(0, 10).map(entry => `<div class="log-entry blocked"><span class="log-ip">${escapeHtml(entry.ip)}</span></div>`).join('');
                } else { blockedContainer.innerHTML = '<div class="no-data">No blocked IPs</div>'; }
            } catch (error) { console.error('Error:', error); }
        }
        async function loadDbStats() {
            try {
                const response = await fetch('api/database/stats');
                const data = await response.json();
                document.getElementById('db-stats').innerHTML = `
                    <div class="stat"><span class="stat-label">Database</span><span class="stat-value">${data.database}</span></div>
                    <div class="stat"><span class="stat-label">Users</span><span class="stat-value">${data.collections.users}</span></div>
                    <div class="stat"><span class="stat-label">Attack Logs</span><span class="stat-value">${data.collections.attack_logs}</span></div>`;
            } catch (error) { document.getElementById('db-stats').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        async function loadUsers() {
            try {
                const response = await fetch('api/database/users');
                const data = await response.json();
                if (data.documents.length === 0) { document.getElementById('db-users').innerHTML = '<div class="no-data">No users</div>'; return; }
                document.getElementById('db-users').innerHTML = data.documents.map(user => `
                    <div class="user-card">
                        <div class="field"><span class="field-name">_id:</span><span class="field-value">${user._id}</span></div>
                        <div class="field"><span class="field-name">username:</span><span class="field-value">${escapeHtml(user.username)}</span></div>
                        <div class="field"><span class="field-name">email:</span><span class="field-value">${escapeHtml(user.email)}</span></div>
                        <div class="field"><span class="field-name">role:</span><span class="field-value">${escapeHtml(user.role || 'user')}</span></div>
                        <div class="field"><span class="field-name">ip_registered:</span><span class="field-value">${escapeHtml(user.ip_registered || 'N/A')}</span></div>
                        <div class="field"><span class="field-name">created_at:</span><span class="field-value">${user.created_at ? new Date(user.created_at).toLocaleString() : 'N/A'}</span></div>
                    </div>`).join('');
            } catch (error) { document.getElementById('db-users').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        async function loadAttackLogsDb() {
            try {
                const response = await fetch('api/database/attack_logs');
                const data = await response.json();
                if (data.documents.length === 0) { document.getElementById('db-attack-logs').innerHTML = '<div class="no-data">No logs</div>'; return; }
                document.getElementById('db-attack-logs').innerHTML = `<table><thead><tr><th>Timestamp</th><th>IP</th><th>Type</th><th>Endpoint</th><th>Payload</th></tr></thead><tbody>${data.documents.map(log => `<tr><td>${log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}</td><td>${escapeHtml(log.ip)}</td><td>${escapeHtml(log.attack_type || 'N/A')}</td><td>${escapeHtml(log.endpoint)}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(log.payload || '')}</td></tr>`).join('')}</tbody></table>`;
            } catch (error) { document.getElementById('db-attack-logs').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        async function loadCommandLogs() {
            try {
                const response = await fetch('api/database/command_logs');
                const data = await response.json();
                if (data.documents.length === 0) { document.getElementById('command-logs').innerHTML = '<div class="no-data">No commands logged yet</div>'; return; }
                document.getElementById('command-logs').innerHTML = `<table><thead><tr><th>Timestamp</th><th>Username</th><th>Command</th><th>IP</th></tr></thead><tbody>${data.documents.map(log => `<tr><td>${log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}</td><td style="color:#00ff88;">${escapeHtml(log.username)}</td><td style="color:#ffcc00;font-family:monospace;">${escapeHtml(log.command)}</td><td>${escapeHtml(log.ip)}</td></tr>`).join('')}</tbody></table>`;
            } catch (error) { document.getElementById('command-logs').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        async function loadBlockedIps() {
            try {
                const response = await fetch('api/blocked-ips');
                const data = await response.json();
                if (data.length === 0) { document.getElementById('blocked-ips-list').innerHTML = '<div class="no-data">✅ No IPs currently blocked</div>'; return; }
                document.getElementById('blocked-ips-list').innerHTML = `<table><thead><tr><th>IP Address</th><th>Blocked At</th><th>Blocked Until</th><th>Reason</th></tr></thead><tbody>${data.map(ip => `<tr style="background:rgba(255,0,0,0.1);"><td style="color:#ff6666;font-weight:bold;">${escapeHtml(ip.ip)}</td><td>${ip.blocked_at ? new Date(ip.blocked_at).toLocaleString() : 'N/A'}</td><td>${ip.blocked_until ? new Date(ip.blocked_until).toLocaleString() : 'N/A'}</td><td>${escapeHtml(ip.reason || 'N/A')}</td></tr>`).join('')}</tbody></table>`;
            } catch (error) { document.getElementById('blocked-ips-list').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        async function loadActiveVisitors() {
            try {
                const response = await fetch('api/active-visitors');
                const data = await response.json();
                if (data.length === 0) { document.getElementById('active-visitors').innerHTML = '<div class="no-data">No recent visitors</div>'; return; }
                document.getElementById('active-visitors').innerHTML = `<table><thead><tr><th>IP Address</th><th>Username</th><th>Last Access</th><th>Access Count</th></tr></thead><tbody>${data.map(v => `<tr><td style="color:#00aaff;">${escapeHtml(v.ip)}</td><td style="color:#00ff88;">${escapeHtml(v.username || 'anonymous')}</td><td>${v.last_access ? new Date(v.last_access).toLocaleString() : 'N/A'}</td><td>${v.access_count || 0}</td></tr>`).join('')}</tbody></table>`;
            } catch (error) { document.getElementById('active-visitors').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        async function loadIdsAlerts() {
            try {
                const response = await fetch('api/ids-alerts');
                const data = await response.json();
                if (data.length === 0) { document.getElementById('ids-alerts').innerHTML = '<div class="no-data">✅ No IDS alerts detected</div>'; return; }
                document.getElementById('ids-alerts').innerHTML = `<table><thead><tr><th>Timestamp</th><th>Source IP</th><th>Event</th><th>Protocol</th><th>Payload</th></tr></thead><tbody>${data.map(a => `<tr style="border-left: 4px solid #ff0000; background:rgba(255,0,0,0.05);"><td>${a.timestamp ? new Date(a.timestamp).toLocaleString() : 'N/A'}</td><td style="color:#ff6666;font-weight:bold;">${escapeHtml(a.src_ip)}:${a.src_port}</td><td style="color:#ffcc00;">${escapeHtml(a.alert?.signature || a.event_type)}</td><td>${escapeHtml(a.proto)}</td><td style="font-family:monospace;font-size:11px;">${escapeHtml(JSON.stringify(a.http || a.payload || {}))}</td></tr>`).join('')}</tbody></table>`;
            } catch (error) { document.getElementById('ids-alerts').innerHTML = '<div class="no-data">⚠️ Error</div>'; }
        }
        setInterval(updateTime, 1000);
        updateTime();
        loadAttackLogs();
        loadAttackStats();
        setInterval(loadAttackLogs, 10000);
        setInterval(loadAttackStats, 10000);
    </script>
</body>
</html>'''


@dashboard_bp.route('/')
def dashboard():
    """Serve the dashboard HTML"""
    return Response(DASHBOARD_HTML, mimetype='text/html')


@dashboard_bp.route('/api/attacks')
def api_attacks():
    """API endpoint for attack logs"""
    attacks = list(db.attack_logs.find().sort('timestamp', -1).limit(50))
    
    for attack in attacks:
        attack['_id'] = str(attack['_id'])
        attack['timestamp'] = attack['timestamp'].isoformat() if attack.get('timestamp') else None
    
    return jsonify(attacks)


@dashboard_bp.route('/api/attack-stats')
def api_attack_stats():
    """API endpoint for attack statistics"""
    pipeline = [
        {'$group': {'_id': '$attack_type', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}}
    ]
    stats = list(db.attack_logs.aggregate(pipeline))
    blocked_ips = list(db.attack_logs.find({'blocked': True}).sort('timestamp', -1).limit(20))
    
    for ip_entry in blocked_ips:
        ip_entry['_id'] = str(ip_entry['_id'])
        ip_entry['timestamp'] = ip_entry['timestamp'].isoformat() if ip_entry.get('timestamp') else None
    
    return jsonify({
        'stats': stats,
        'blocked_ips': blocked_ips
    })


@dashboard_bp.route('/api/database/users')
def api_database_users():
    """API endpoint to view all users"""
    users = list(db.users.find())
    
    for user in users:
        user['_id'] = str(user['_id'])
        user['created_at'] = user['created_at'].isoformat() if user.get('created_at') else None
        if 'password_hash' in user:
            user['password_hash'] = '[HASHED]'
    
    return jsonify({
        'collection': 'users',
        'count': len(users),
        'documents': users
    })


@dashboard_bp.route('/api/database/attack_logs')
def api_database_attack_logs():
    """API endpoint to view attack logs"""
    logs = list(db.attack_logs.find().sort('timestamp', -1).limit(100))
    
    for log in logs:
        log['_id'] = str(log['_id'])
        log['timestamp'] = log['timestamp'].isoformat() if log.get('timestamp') else None
    
    return jsonify({
        'collection': 'attack_logs',
        'count': len(logs),
        'documents': logs
    })


@dashboard_bp.route('/api/database/stats')
def api_database_stats():
    """API endpoint for database statistics"""
    return jsonify({
        'database': 'ctf_db',
        'collections': {
            'users': db.users.count_documents({}),
            'attack_logs': db.attack_logs.count_documents({}),
            'command_logs': db.command_logs.count_documents({})
        }
    })


@dashboard_bp.route('/api/database/command_logs')
def api_database_command_logs():
    """API endpoint to view command logs"""
    logs = list(db.command_logs.find().sort('timestamp', -1).limit(100))
    
    for log in logs:
        log['_id'] = str(log['_id'])
        log['timestamp'] = log['timestamp'].isoformat() if log.get('timestamp') else None
    
    return jsonify({
        'collection': 'command_logs',
        'count': len(logs),
        'documents': logs
    })


@dashboard_bp.route('/api/blocked-ips')
def api_blocked_ips():
    """API endpoint to get currently blocked IPs"""
    from datetime import datetime
    now = datetime.utcnow()
    blocked = list(db.blocked_ips.find({'blocked_until': {'$gt': now}}))
    
    for ip in blocked:
        ip['_id'] = str(ip['_id'])
        ip['blocked_at'] = ip['blocked_at'].isoformat() if ip.get('blocked_at') else None
        ip['blocked_until'] = ip['blocked_until'].isoformat() if ip.get('blocked_until') else None
    
    return jsonify(blocked)


@dashboard_bp.route('/api/active-visitors')
def api_active_visitors():
    """API endpoint to get recently active IPs"""
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(hours=1)  # Last hour
    visitors = list(db.ip_access_logs.find({'last_access': {'$gt': cutoff}}).sort('last_access', -1).limit(50))
    
    for v in visitors:
        v['_id'] = str(v['_id'])
        v['last_access'] = v['last_access'].isoformat() if v.get('last_access') else None
    
    return jsonify(visitors)

@dashboard_bp.route('/api/ids-alerts')
def api_ids_alerts():
    """API endpoint to read Suricata logs"""
    import json
    alerts = []
    log_file = '/var/log/suricata/eve.json'
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                # Read last 50 lines efficiently? For now just read all and take last 50
                lines = f.readlines()
                for line in lines[-50:]:
                    try:
                        alerts.append(json.loads(line))
                    except: continue
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Sort by timestamp desc
    alerts.reverse()
    return jsonify(alerts)

# Removed app.run for blueprint compatibility
