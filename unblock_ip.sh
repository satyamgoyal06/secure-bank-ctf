#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: ./unblock_ip.sh <IP_ADDRESS>"
    exit 1
fi

IP=$1
echo "[*] Unblocking IP: $IP in web container..."
# Try to delete the rule
docker exec ctf_web ufw delete deny from $IP
docker exec ctf_web ufw status verbose | grep $IP || echo "[+] IP $IP is not blocked"
echo "[+] Done"
