#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: ./block_ip.sh <IP_ADDRESS>"
    exit 1
fi

IP=$1
echo "[*] Blocking IP: $IP in web container..."
docker exec ctf_web ufw deny from $IP
docker exec ctf_web ufw status verbose | grep $IP
echo "[+] Blocked $IP"
