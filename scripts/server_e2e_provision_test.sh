#!/usr/bin/env bash
# E2E провижининга: adduser выдаёт ссылку → сервер с -peers → клиент по -url.
set -u
B=/root/mirage
WAN=$(ip route show default | awk '/default/{print $5; exit}')
PORT=5562
SUBNET=10.30.0.0/24
TUN=mirage5
NS=mpP
LINK=10.93.0

cleanup() {
  ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del $NS 2>/dev/null; rm -rf /etc/netns/$NS
  pkill -f "0.0.0.0:$PORT" 2>/dev/null
  ip link del vhP 2>/dev/null; ip link del $TUN 2>/dev/null
  iptables -t nat -D POSTROUTING -s $SUBNET -o "$WAN" -j MASQUERADE 2>/dev/null
  iptables -D INPUT -i vhP -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i $TUN -j ACCEPT 2>/dev/null; iptables -D FORWARD -o $TUN -j ACCEPT 2>/dev/null
  rm -f /root/prov_peers.txt /root/prov_srv.key
}
trap cleanup EXIT; cleanup; trap cleanup EXIT

S=$($B genkey); SPRIV=$(echo "$S"|awk '/private/{print $3}'); SPUB=$(echo "$S"|awk '/public/{print $3}')
umask 077; echo "$SPRIV" > /root/prov_srv.key

# Провижиним пользователя — получаем ссылку.
OUT=$($B adduser -peers /root/prov_peers.txt -server "$SPUB" -endpoint $LINK.1:$PORT \
      -addr 10.30.0.2/24 -peer 10.30.0.1 -name testuser)
URL=$(echo "$OUT" | grep '^mirage://')
echo "=== выданная ссылка ==="; echo "$URL"
echo "=== peers-файл ==="; cat /root/prov_peers.txt

iptables -I FORWARD -i $TUN -j ACCEPT
iptables -I FORWARD -o $TUN -j ACCEPT

$B server -listen 0.0.0.0:$PORT -key-file /root/prov_srv.key -tun -tun-name $TUN \
  -tun-addr 10.30.0.1/24 -nat -wan "$WAN" -peers /root/prov_peers.txt > /root/prov_srv.log 2>&1 &
sleep 1.5

ip netns add $NS
ip link add vhP type veth peer name vcP
ip link set vcP netns $NS
ip addr add $LINK.1/24 dev vhP; ip link set vhP up
ip netns exec $NS ip addr add $LINK.2/24 dev vcP
ip netns exec $NS ip link set vcP up; ip netns exec $NS ip link set lo up
mkdir -p /etc/netns/$NS; echo "nameserver 1.1.1.1" > /etc/netns/$NS/resolv.conf
iptables -I INPUT -i vhP -j ACCEPT

# Клиент подключается ТОЛЬКО по ссылке (-url), своё имя tun чтобы не конфликтовать.
ip netns exec $NS $B client -url "$URL" -tun-name $TUN > /root/prov_cli.log 2>&1 &
for i in $(seq 1 30); do ip netns exec $NS ip link show $TUN >/dev/null 2>&1 && break; sleep 0.3; done
ip netns exec $NS ip route add default via 10.30.0.1 dev $TUN 2>/dev/null \
  || ip netns exec $NS ip route add default dev $TUN
sleep 1.5

echo "=== server log ==="; cat /root/prov_srv.log
echo "=== client log ==="; cat /root/prov_cli.log
echo "=== ping через туннель (по ссылке) ==="; ip netns exec $NS ping -c2 -W3 1.1.1.1 | tail -2
SRV=$(curl -4 -s --max-time 12 https://ifconfig.me)
NS_IP=$(ip netns exec $NS curl -4 -s --max-time 15 https://ifconfig.me)
echo "srv=$SRV  через-туннель=$NS_IP"
if [ -n "$NS_IP" ] && [ "$NS_IP" = "$SRV" ]; then
  echo "✅ ПРОВИЖИНИНГ РАБОТАЕТ: adduser→ссылка→server -peers→client -url→интернет"
else
  echo "❌ srv=$SRV ns=$NS_IP"
fi
