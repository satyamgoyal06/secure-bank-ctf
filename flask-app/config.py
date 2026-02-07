import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'ctf-super-secret-key-change-me')
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongodb:27017/ctf_db')
    
    # Rate limiting settings
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Login rate limit: 5 attempts per minute per IP
    LOGIN_RATE_LIMIT = "5 per minute"
    LOGIN_BLOCK_DURATION = 15 * 60  # 15 minutes in seconds
