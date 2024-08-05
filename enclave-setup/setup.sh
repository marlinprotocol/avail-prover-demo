#!/bin/sh

# setting an address for loopback
ifconfig lo 127.0.0.1
ifconfig

# adding a default route
ip route add default dev lo src 127.0.0.1
route -n

# iptables rules to route traffic to transparent proxy
iptables -A OUTPUT -t nat -p tcp --dport 1:65535 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:1200
iptables -L -t nat

# generate identity key
#/app/keygen --secret /app/id.sec --public /app/id.pub
#/app/oyster-keygen --secret /app/secp.sec --public /app/secp.pub

ls /params

ls app
cat /app/id.sec
cat /app/secp.sec

# starting supervisord
/app/supervisord
