#!/usr/bin/env bash
# E2E multi-peer: два клиента одновременно через один сервер (маршрутизация по IP).
# Отдельные подсеть/порт/tun, чтобы не задеть systemd-сервисы.
set -u
B=/root/mirage
WAN=$(ip route show default | awk '/default/{print $5; exit}')
PORT=5560
SUBNET=10.20.0.0/24
TUN=mirage3

cleanup() {
  for ns in mpA mpB; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $ns 2>/dev/null
    rm -rf /etc/netns/$ns
  done
  pkill -f "0.0.0.0:$PORT" 2>/dev/null
  ip link del vhA 2>/dev/null; ip link del vhB 2>/dev/null; ip link del $TUN 2>/dev/null
  iptables -t nat -D POSTROUTING -s $SUBNET -o "$WAN" -j MASQUERADE 2>/dev/null
  iptables -D INPUT -i vhA -j ACCEPT 2>/dev/null; iptables -D INPUT -i vhB -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i $TUN -j ACCEPT 2>/dev/null; iptables -D FORWARD -o $TUN -j ACCEPT 2>/dev/null
  rm -f /root/mp_peers.txt /root/mp_srv.key
}
trap cleanup EXIT; cleanup; trap cleanup EXIT

S=$($B genkey);  SPRIV=$(echo "$S"|awk '/private/{print $3}'); SPUB=$(echo "$S"|awk '/public/{print $3}')
A=$($B genkey);  APRIV=$(echo "$A"|awk '/private/{print $3}'); APUB=$(echo "$A"|awk '/public/{print $3}')
C=$($B genkey);  BPRIV=$(echo "$C"|awk '/private/{print $3}'); BPUB=$(echo "$C"|awk '/public/{print $3}')

printf '%s 10.20.0.2 clientA\n%s 10.20.0.3 clientB\n' "$APUB" "$BPUB" > /root/mp_peers.txt
umask 077; echo "$SPRIV" > /root/mp_srv.key

iptables -I FORWARD -i $TUN -j ACCEPT
iptables -I FORWARD -o $TUN -j ACCEPT

$B server -listen 0.0.0.0:$PORT -key-file /root/mp_srv.key -tun -tun-name $TUN \
  -tun-addr 10.20.0.1/24 -nat -wan "$WAN" -peers /root/mp_peers.txt > /root/mp_srv.log 2>&1 &
sleep 1.5

setup_client() { # ns vh vc link cpriv tunaddr
  local ns=$1 vh=$2 vc=$3 link=$4 cpriv=$5 tunaddr=$6
  ip netns add $ns
  ip link add $vh type veth peer name $vc
  ip link set $vc netns $ns
  ip addr add $link.1/24 dev $vh; ip link set $vh up
  ip netns exec $ns ip addr add $link.2/24 dev $vc
  ip netns exec $ns ip link set $vc up; ip netns exec $ns ip link set lo up
  mkdir -p /etc/netns/$ns; echo "nameserver 1.1.1.1" > /etc/netns/$ns/resolv.conf
  iptables -I INPUT -i $vh -j ACCEPT
  ip netns exec $ns $B client -connect $link.1:$PORT -server "$SPUB" -key "$cpriv" \
    -tun -tun-name $TUN -tun-addr $tunaddr -keepalive 5s > /root/mp_${ns}.log 2>&1 &
  for i in $(seq 1 30); do ip netns exec $ns ip link show $TUN >/dev/null 2>&1 && break; sleep 0.3; done
  ip netns exec $ns ip route add default via 10.20.0.1 dev $TUN 2>/dev/null \
    || ip netns exec $ns ip route add default dev $TUN
}

setup_client mpA vhA vcA 10.91.0 "$APRIV" 10.20.0.2/24
setup_client mpB vhB vcB 10.92.0 "$BPRIV" 10.20.0.3/24
sleep 1.5

echo "=== server log ==="; cat /root/mp_srv.log
echo "=== ping одновременно ==="
echo "clientA:"; ip netns exec mpA ping -c2 -W3 1.1.1.1 | tail -2
echo "clientB:"; ip netns exec mpB ping -c2 -W3 1.1.1.1 | tail -2
echo "=== egress IP ==="
SRV=$(curl -4 -s --max-time 12 https://ifconfig.me)
A_IP=$(ip netns exec mpA curl -4 -s --max-time 15 https://ifconfig.me)
B_IP=$(ip netns exec mpB curl -4 -s --max-time 15 https://ifconfig.me)
echo "srv=$SRV  A=$A_IP  B=$B_IP"
if [ -n "$A_IP" ] && [ "$A_IP" = "$SRV" ] && [ "$B_IP" = "$SRV" ]; then
  echo "✅ MULTI-PEER РАБОТАЕТ: два клиента одновременно выходят через сервер"
else
  echo "❌ srv=$SRV A=$A_IP B=$B_IP"
fi
