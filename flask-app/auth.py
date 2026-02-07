"""
Authentication Module - User signup/signin with password hashing
"""
import bcrypt
from datetime import datetime


class Auth:
    def __init__(self, db, attack_logger):
        self.db = db
        self.users = db.users
        self.logger = attack_logger
    
    def hash_password(self, password):
        """Hash a password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    def verify_password(self, password, password_hash):
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash)
        except Exception:
            return False
    
    def signup(self, username, email, password, ip_address):
        """Register a new user"""
        # Check if username already exists
        if self.users.find_one({'username': username}):
            return {'success': False, 'message': 'Username already exists'}
        
        # Check if email already exists
        if self.users.find_one({'email': email}):
            return {'success': False, 'message': 'Email already registered'}
        
        # Create user
        user = {
            'username': username,
            'email': email,
            'password_hash': self.hash_password(password),
            'created_at': datetime.utcnow(),
            'ip_registered': ip_address,
            'role': 'user'
        }
        
        self.users.insert_one(user)
        return {'success': True, 'message': 'Account created successfully'}
    
    def signin(self, username, password, ip_address):
        """
        Authenticate a user.
        NOTE: This contains a deliberate NoSQL injection vulnerability for CTF purposes.
        The username is used directly in the query without sanitization.
        """
        # VULNERABLE: If username is a dict like {"$ne": ""}, it bypasses auth
        # This is intentional for CTF demonstration
        try:
            # Check for NoSQL injection patterns and log them
            if isinstance(username, dict) or (isinstance(username, str) and '$' in username):
                self.logger.log_request('/signin', username, 'NoSQL Injection')
            
            user = self.users.find_one({'username': username})
            
            if not user:
                self.logger.log_failed_login(str(username), ip_address)
                return {'success': False, 'message': 'Invalid username or password'}
            
            if not self.verify_password(password, user['password_hash']):
                self.logger.log_failed_login(username, ip_address)
                return {'success': False, 'message': 'Invalid username or password'}
            
            return {
                'success': True,
                'message': 'Login successful',
                'user': {
                    'username': user['username'],
                    'email': user['email'],
                    'role': user.get('role', 'user')
                }
            }
        except Exception as e:
            return {'success': False, 'message': 'Authentication error'}
    
    def get_user_by_username(self, username):
        """Get user by username"""
        user = self.users.find_one({'username': username})
        if user:
            user['_id'] = str(user['_id'])
            del user['password_hash']
        return user
