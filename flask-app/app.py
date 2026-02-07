"""
CTF Vulnerable Web Application
Flask app with MongoDB, authentication, rate limiting, and attack logging
"""
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
import gridfs
from functools import wraps
import os
from datetime import datetime, timedelta

from config import Config
from auth import Auth
from logger import AttackLogger
from dashboard_app import dashboard_bp

app = Flask(__name__)
app.config.from_object(Config)

# MongoDB connection
mongo_client = MongoClient(app.config['MONGO_URI'])
db = mongo_client.ctf_db

# Initialize attack logger and auth
attack_logger = AttackLogger(db)
auth = Auth(db, attack_logger)

# Register Dashboard Blueprint
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

# GridFS for storing files
fs = gridfs.GridFS(db)

# Custom key function to get real client IP
def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or '127.0.0.1'

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=get_real_ip,
    default_limits=["100 per hour"]
)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function



# Concurrent User Limiting
@app.before_request
def check_concurrent_users():
    """Limit access to 3 distinct IPs at a time"""
    # Skip for static files and internal dashboard API
    if (request.path.startswith('/static') or 
        request.path.startswith('/api/ids-alerts') or
        request.endpoint == 'static'):
        return

    client_ip = get_real_ip()
    now = datetime.utcnow()
    
    # Check if we already have a session
    existing_session = db.active_sessions.find_one({'ip': client_ip})
    
    if existing_session:
        # Refresh session
        db.active_sessions.update_one(
            {'ip': client_ip},
            {'$set': {'last_active': now, 'expiry': now + timedelta(minutes=5)}}
        )
    else:
        # New session attempt - check limit
        # Count distinct active IPs (excluding expired ones)
        count = db.active_sessions.count_documents({'expiry': {'$gt': now}})
        
        # If 3 or more users are active, and we are not one of them, block
        if count >= 3:
            return render_template('loading.html', error="⛔ Server Full: Maximum 3 concurrent users allowed. Please try again in a few minutes."), 503
        
        # Create new session
        db.active_sessions.insert_one({
            'ip': client_ip,
            'last_active': now,
            'expiry': now + timedelta(minutes=5)
        })

# Trap non-buffer users - redirect them to loading on ANY page
@app.before_request
def check_trapped_user():
    """Redirect trapped users back to loading page"""
    # Allow these endpoints without trap check - let them try signing up again
    allowed_endpoints = ['loading', 'signout', 'signup', 'signin', 'static']
    
    if request.endpoint in allowed_endpoints:
        return None
    
    # If user is trapped, redirect to loading
    if session.get('trapped'):
        return redirect(url_for('loading'))
    
    return None


# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Basic validation
        if not username or not email or not password:
            return render_template('signup.html', error='All fields are required')
        
        if len(password) < 6:
            return render_template('signup.html', error='Password must be at least 6 characters')
        
        # Check for attack patterns in input
        for field in [username, email]:
            attack_type = attack_logger.detect_attack_type(field)
            if attack_type:
                attack_logger.log_request('/signup', field, attack_type)
        
        ip = get_real_ip()
        result = auth.signup(username, email, password, ip)
        
        if result['success']:
            return redirect(url_for('signin', registered=1))
        else:
            return render_template('signup.html', error=result['message'])
    
    return render_template('signup.html')


@app.route('/signin', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please try again later.")
def signin():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('signin.html', error='Username and password are required')
        
        ip = get_real_ip()
        result = auth.signin(username, password, ip)
        
        if result['success']:
            session['user'] = result['user']
            
            # SECRET: Only "buffer" with password "enjoy?" gets real access
            if username == 'buffer' and password == 'enjoy?':
                session.pop('trapped', None)  # Remove trap if exists
                return redirect(url_for('index'))
            else:
                # TRAP: Mark user as trapped - they can't escape!
                session['trapped'] = True
                session['refresh_count'] = 0
                return redirect(url_for('loading'))
        else:
            return render_template('signin.html', error=result['message'])
    
    registered = request.args.get('registered')
    return render_template('signin.html', success='Account created! Please sign in.' if registered else None)


@app.route('/loading')
@login_required
def loading():
    """Fake loading page that tracks refresh count"""
    # Increment refresh count
    refresh_count = session.get('refresh_count', 0) + 1
    session['refresh_count'] = refresh_count
    
    # After 10 refreshes, redirect to home
    if refresh_count >= 10:
        session.pop('refresh_count', None)  # Reset counter
        return redirect(url_for('index'))
    
    return render_template('loading.html')


@app.route('/signout')
def signout():
    session.pop('user', None)
    session.pop('refresh_count', None)
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    user = session.get('user')
    return render_template('profile.html', user=user)


# ==================== HIDDEN PAGES (no links to these) ====================

@app.route('/home/pirates/packets')
def hidden_pirates_packets():
    """Hidden page showing live command feed - only accessible by direct URL"""
    return render_template('hidden_packets.html')


@app.route('/secret/admin/vault')
def hidden_admin_vault():
    """Hidden admin vault page"""
    return render_template('hidden_vault.html')


@app.route('/dev/debug/console')
def hidden_debug_console():
    """Hidden debug console"""
    return render_template('hidden_console.html')


@app.route('/api/live-commands')
def api_live_commands():
    """API endpoint for live command feed"""
    commands = list(db.command_logs.find().sort('timestamp', -1).limit(50))
    for cmd in commands:
        cmd['_id'] = str(cmd['_id'])
        cmd['timestamp'] = cmd['timestamp'].isoformat() if cmd.get('timestamp') else None
    return jsonify(commands)


# ==================== API ENDPOINTS ====================

@app.route('/api/command', methods=['POST'])
@login_required
def api_command():
    """Handle command input from homepage - logs to MongoDB with rate limiting"""
    from datetime import datetime, timedelta
    
    ip = get_real_ip()
    now = datetime.utcnow()
    
    # Check if IP is blocked
    blocked = db.blocked_ips.find_one({'ip': ip, 'blocked_until': {'$gt': now}})
    if blocked:
        remaining = int((blocked['blocked_until'] - now).total_seconds() / 60)
        return jsonify({
            'success': False,
            'message': f'⛔ IP blocked. Try again in {remaining} minutes.'
        }), 429
    
    data = request.get_json()
    command = data.get('command', '').strip() if data else ''
    user = session.get('user', {})
    
    # Log the command to MongoDB
    command_log = {
        'username': user.get('username', 'unknown'),
        'command': command,
        'ip': ip,
        'timestamp': now,
        'user_agent': request.headers.get('User-Agent', '')
    }
    db.command_logs.insert_one(command_log)
    
    # Log IP access for monitoring
    db.ip_access_logs.update_one(
        {'ip': ip},
        {
            '$set': {'last_access': now, 'username': user.get('username', 'unknown')},
            '$inc': {'access_count': 1}
        },
        upsert=True
    )
    
    # Check for the secret command
    if command == 'get_jojo':
        # Reset failed attempts on success
        db.command_attempts.delete_one({'ip': ip})
        # Grant download access to this user
        session['can_download_secret'] = True
        return jsonify({
            'success': True,
            'message': '🎉 ACCESS GRANTED! Secret file unlocked!',
            'download_url': '/api/secret-file'
        })
    else:
        # Track failed attempts
        attempt = db.command_attempts.find_one_and_update(
            {'ip': ip},
            {
                '$inc': {'attempts': 1},
                '$set': {'last_attempt': now}
            },
            upsert=True,
            return_document=True
        )
        
        attempts = attempt.get('attempts', 1) if attempt else 1
        
        # Block IP after 5 failed attempts
        if attempts >= 5:
            db.blocked_ips.update_one(
                {'ip': ip},
                {
                    '$set': {
                        'blocked_until': now + timedelta(minutes=10),
                        'reason': 'Too many failed command attempts',
                        'blocked_at': now
                    }
                },
                upsert=True
            )
            db.command_attempts.delete_one({'ip': ip})
            return jsonify({
                'success': False,
                'message': '⛔ Too many attempts! IP blocked for 10 minutes.'
            }), 429
        
        return jsonify({
            'success': False,
            'message': f'Command "{command}" not recognized. Access denied. ({5 - attempts} attempts remaining)'
        })


@app.route('/api/secret-file')
@login_required
def api_secret_file():
    """Protected endpoint to download secret file from MongoDB GridFS"""
    # Check if user has unlocked the secret file
    if not session.get('can_download_secret'):
        return jsonify({'error': 'Access denied. Enter the correct command first.'}), 403
    
    # Find the file in GridFS
    try:
        file = fs.find_one({'filename': 'ooogabooga.wav'})
        if not file:
            return jsonify({'error': 'Secret file not found in database'}), 404
        
        # Return the file
        return Response(
            file.read(),
            mimetype='audio/wav',
            headers={
                'Content-Disposition': 'attachment; filename=ooogabooga.wav'
            }
        )
    except Exception as e:
        return jsonify({'error': 'Error retrieving file'}), 500


@app.route('/api/attacks')
def api_attacks():
    """API endpoint for dashboard to fetch attack logs"""
    attacks = attack_logger.get_recent_attacks(50)
    
    # Convert ObjectId and datetime for JSON serialization
    for attack in attacks:
        attack['_id'] = str(attack['_id'])
        attack['timestamp'] = attack['timestamp'].isoformat() if attack.get('timestamp') else None
    
    return jsonify(attacks)


@app.route('/api/attack-stats')
def api_attack_stats():
    """API endpoint for attack statistics"""
    stats = attack_logger.get_attack_stats()
    blocked_ips = attack_logger.get_blocked_ips()
    
    for ip_entry in blocked_ips:
        ip_entry['_id'] = str(ip_entry['_id'])
        ip_entry['timestamp'] = ip_entry['timestamp'].isoformat() if ip_entry.get('timestamp') else None
    
    return jsonify({
        'stats': stats,
        'blocked_ips': blocked_ips
    })


@app.route('/api/database/users')
def api_database_users():
    """API endpoint to view all users in database"""
    users = list(db.users.find())
    
    for user in users:
        user['_id'] = str(user['_id'])
        user['created_at'] = user['created_at'].isoformat() if user.get('created_at') else None
        # Remove password hash for security (show it exists but masked)
        if 'password_hash' in user:
            user['password_hash'] = '[HASHED - bcrypt]'
    
    return jsonify({
        'collection': 'users',
        'count': len(users),
        'documents': users
    })


@app.route('/api/database/attack_logs')
def api_database_attack_logs():
    """API endpoint to view all attack logs in database"""
    logs = list(db.attack_logs.find().sort('timestamp', -1).limit(100))
    
    for log in logs:
        log['_id'] = str(log['_id'])
        log['timestamp'] = log['timestamp'].isoformat() if log.get('timestamp') else None
    
    return jsonify({
        'collection': 'attack_logs',
        'count': len(logs),
        'documents': logs
    })


@app.route('/api/database/stats')
def api_database_stats():
    """API endpoint for database statistics"""
    return jsonify({
        'database': 'ctf_db',
        'collections': {
            'users': db.users.count_documents({}),
            'attack_logs': db.attack_logs.count_documents({})
        }
    })


# ==================== ERROR HANDLERS ====================

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    attack_logger.log_rate_limited()
    return render_template('signin.html', 
                          error='Too many login attempts. You have been temporarily blocked. Try again in 1 minute.'), 429


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ==================== STARTUP ====================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
