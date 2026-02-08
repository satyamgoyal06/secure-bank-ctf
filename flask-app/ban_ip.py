import sys
import os
from datetime import datetime, timedelta
from pymongo import MongoClient

def ban_ip(ip, reason="Manual Ban", duration_hours=24):
    # Connect to MongoDB (same URI as app)
    mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/ctf_db')
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        db = client.ctf_db
        
        # Check connection
        client.server_info()
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        # Try docker internal hostname if localhost fails (unlikely if running from host with port mapping)
        # Actually user runs this from HOST. Host needs to connect to port 27017.
        # Docker maps 27017:27017. So localhost:27017 works.
        return

    now = datetime.utcnow()
    blocked_until = now + timedelta(hours=duration_hours)
    
    # Upsert the ban
    result = db.blocked_ips.update_one(
        {'ip': ip},
        {
            '$set': {
                'blocked_until': blocked_until,
                'reason': reason,
                'blocked_at': now,
                'manual': True
            }
        },
        upsert=True
    )
    
    if result.upserted_id:
        print(f"✅ IP {ip} globally BANNED until {blocked_until.isoformat()}")
    else:
        print(f"✅ IP {ip} ban UPDATED until {blocked_until.isoformat()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ban_ip.py <IP_ADDRESS> [REASON]")
        sys.exit(1)
    
    ip_addr = sys.argv[1]
    reason_str = sys.argv[2] if len(sys.argv) > 2 else "Manual Administrator Ban"
    
    ban_ip(ip_addr, reason_str)
