"""
Attack Logger Module - Detects and logs suspicious activity
"""
from datetime import datetime
from flask import request


class AttackLogger:
    def __init__(self, db):
        self.db = db
        self.attack_logs = db.attack_logs
        self.rate_limits = db.rate_limits
        
        # Patterns to detect attacks
        self.sqli_patterns = [
            "' or ", "' and ", "1=1", "1'='1", "' --", "'; --",
            "union select", "drop table", "insert into", "delete from",
            "$ne", "$gt", "$lt", "$regex", "$where"  # NoSQL injection
        ]
        self.xss_patterns = [
            "<script", "javascript:", "onerror=", "onload=",
            "onclick=", "onmouseover=", "alert(", "document.cookie"
        ]
    
    def get_client_ip(self):
        """Get the real client IP address"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr or '127.0.0.1'
    
    def detect_attack_type(self, payload):
        """Detect the type of attack from payload"""
        payload_lower = payload.lower()
        
        for pattern in self.sqli_patterns:
            if pattern in payload_lower:
                return 'SQL/NoSQL Injection'
        
        for pattern in self.xss_patterns:
            if pattern in payload_lower:
                return 'XSS'
        
        return None
    
    def log_request(self, endpoint, payload=None, attack_type=None, blocked=False):
        """Log a request/attack to the database"""
        ip = self.get_client_ip()
        
        # Auto-detect attack type if not provided
        if payload and not attack_type:
            attack_type = self.detect_attack_type(str(payload))
        
        log_entry = {
            'timestamp': datetime.utcnow(),
            'ip': ip,
            'endpoint': endpoint,
            'payload': str(payload) if payload else None,
            'attack_type': attack_type,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'method': request.method,
            'blocked': blocked
        }
        
        # Only log if it's an attack or blocked
        if attack_type or blocked:
            self.attack_logs.insert_one(log_entry)
        
        return log_entry
    
    def log_failed_login(self, username, ip=None):
        """Log a failed login attempt"""
        if ip is None:
            ip = self.get_client_ip()
            
        self.attack_logs.insert_one({
            'timestamp': datetime.utcnow(),
            'ip': ip,
            'endpoint': '/signin',
            'payload': f'Failed login for user: {username}',
            'attack_type': 'Brute Force Attempt',
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'method': 'POST',
            'blocked': False
        })
    
    def log_rate_limited(self, ip=None):
        """Log when an IP gets rate limited"""
        if ip is None:
            ip = self.get_client_ip()
            
        self.attack_logs.insert_one({
            'timestamp': datetime.utcnow(),
            'ip': ip,
            'endpoint': '/signin',
            'payload': 'Rate limit exceeded - possible brute force',
            'attack_type': 'Brute Force Blocked',
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'method': 'POST',
            'blocked': True
        })
    
    def get_recent_attacks(self, limit=50):
        """Get recent attack logs"""
        return list(self.attack_logs.find().sort('timestamp', -1).limit(limit))
    
    def get_blocked_ips(self):
        """Get list of IPs that have been rate limited recently"""
        return list(self.attack_logs.find({'blocked': True}).sort('timestamp', -1).limit(20))
    
    def get_attack_stats(self):
        """Get attack statistics"""
        pipeline = [
            {'$group': {'_id': '$attack_type', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        return list(self.attack_logs.aggregate(pipeline))
