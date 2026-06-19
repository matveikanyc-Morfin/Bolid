#!/usr/bin/env bash
# E2E-тест туннеля MIRAGE через TLS-обфускацию (профиль tls-reality, шаг 3a).
# Использует отдельные имена/подсеть/порт (TCP 5556), чтобы НЕ конфликтовать с
# работающим systemd-сервисом mirage (UDP 5555, mirage0, 10.7.0.0/24).
#
# Снаружи трафик между namespace и сервером выглядит как HTTPS (TLS 1.3 к SNI).
set -u

B=/root/mirage
NS=mclitls
LOG_SRV=/root/mirage_tls_srv.log
LOG_CLI=/root/mirage_tls_cli.log
WAN=$(ip route show default | awk '/default/{print $5; exit}')
SUBNET=10.8.0.0/24
VHOST=vhost-tls
VCLI=vcli-tls
LINK=10.98.0

cleanup() {
  echo "=== cleanup ==="
  ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
  pkill -f "$B server -listen 0.0.0.0:5556" 2>/dev/null
  ip netns del $NS 2>/dev/null
  ip link del $VHOST 2>/dev/null
  ip link del mirage1 2>/dev/null
  iptables -t nat -D POSTROUTING -s $SUBNET -o "$WAN" -j MASQUERADE 2>/dev/null
  iptables -D INPUT -i $VHOST -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i mirage1 -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o mirage1 -j ACCEPT 2>/dev/null
  rm -rf /etc/netns/$NS
}
trap cleanup EXIT
cleanup
trap cleanup EXIT

echo "WAN: $WAN"
SRV=$($B genkey); SPRIV=$(echo "$SRV"|awk '/private/{print $3}'); SPUB=$(echo "$SRV"|awk '/public/{print $3}')
CLI=$($B genkey); CPRIV=$(echo "$CLI"|awk '/private/{print $3}')
echo "server pub: $SPUB"

ip netns add $NS
ip link add $VHOST type veth peer name $VCLI
ip link set $VCLI netns $NS
ip addr add $LINK.1/24 dev $VHOST
ip link set $VHOST up
ip netns exec $NS ip addr add $LINK.2/24 dev $VCLI
ip netns exec $NS ip link set $VCLI up
ip netns exec $NS ip link set lo up
mkdir -p /etc/netns/$NS
echo "nameserver 1.1.1.1" > /etc/netns/$NS/resolv.conf

iptables -I INPUT -i $VHOST -j ACCEPT
iptables -I FORWARD -i mirage1 -j ACCEPT
iptables -I FORWARD -o mirage1 -j ACCEPT

# сервер с TLS-профилем
$B server -listen 0.0.0.0:5556 -key "$SPRIV" -tls -cert-host www.microsoft.com \
   -tun -tun-name mirage1 -tun-addr 10.8.0.1/24 -nat -wan "$WAN" > $LOG_SRV 2>&1 &
sleep 1.5

# клиент в namespace, TLS, SNI=www.microsoft.com
ip netns exec $NS $B client -connect $LINK.1:5556 -server "$SPUB" -key "$CPRIV" \
   -tls -sni www.microsoft.com \
   -tun -tun-name mirage1 -tun-addr 10.8.0.2/24 -keepalive 15s > $LOG_CLI 2>&1 &

for i in $(seq 1 30); do
  ip netns exec $NS ip link show mirage1 >/dev/null 2>&1 && break
  sleep 0.3
done
ip netns exec $NS ip route add default via 10.8.0.1 dev mirage1 2>/dev/null \
  || ip netns exec $NS ip route add default dev mirage1
sleep 1

echo "=== server log ==="; cat $LOG_SRV
echo "=== client log ==="; cat $LOG_CLI
echo
echo "=== ТЕСТ: ping 1.1.1.1 через TLS-туннель ==="
ip netns exec $NS ping -c 3 -W 3 1.1.1.1
echo "=== egress IP через TLS-туннель (ожидаем IP сервера) ==="
SRV_IP=$(curl -4 -s --max-time 12 https://ifconfig.me); echo "сервер: $SRV_IP"
NS_IP=$(ip netns exec $NS curl -4 -s --max-time 15 https://ifconfig.me); echo "через туннель: $NS_IP"
echo
if [ -n "$NS_IP" ] && [ "$NS_IP" = "$SRV_IP" ]; then
  echo "РЕЗУЛЬТАТ: ✅ TLS-ТУННЕЛЬ РАБОТАЕТ — трафик внутри TLS 1.3 выходит через сервер ($NS_IP)"
else
  echo "РЕЗУЛЬТАТ: ❌ ns='$NS_IP' srv='$SRV_IP'"
fi
