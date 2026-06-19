#!/usr/bin/env bash
# E2E-тест профиля Reality (3b): свой клиент через TLS-туннель + проверка
# anti-active-probing (зонд видит настоящий www.microsoft.com).
# Использует отдельные имена/подсеть/порт, чтобы не задеть systemd-сервис.
set -u

B=/root/mirage
NS=mclireal
DEST=www.microsoft.com:443
SNI=www.microsoft.com
PORT=5557
WAN=$(ip route show default | awk '/default/{print $5; exit}')
SUBNET=10.9.0.0/24
VHOST=vh-real
VCLI=vc-real
LINK=10.97.0

cleanup() {
  echo "=== cleanup ==="
  ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
  pkill -f "$B server -listen 0.0.0.0:$PORT" 2>/dev/null
  ip netns del $NS 2>/dev/null
  ip link del $VHOST 2>/dev/null
  ip link del mirage2 2>/dev/null
  iptables -t nat -D POSTROUTING -s $SUBNET -o "$WAN" -j MASQUERADE 2>/dev/null
  iptables -D INPUT -i $VHOST -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i mirage2 -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o mirage2 -j ACCEPT 2>/dev/null
  rm -rf /etc/netns/$NS
}
trap cleanup EXIT
cleanup
trap cleanup EXIT

echo "WAN=$WAN  dest=$DEST"
echo "=== доступность dest с сервера ==="
curl -s --max-time 10 -o /dev/null -w "dest HTTP=%{http_code}\n" "https://$SNI/" || echo "dest недоступен!"

SRV=$($B genkey); SPRIV=$(echo "$SRV"|awk '/private/{print $3}'); SPUB=$(echo "$SRV"|awk '/public/{print $3}')
CLI=$($B genkey); CPRIV=$(echo "$CLI"|awk '/private/{print $3}')
PSK=$($B genkey | awk '/private/{print $3}')  # 32 байта как Reality-PSK
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
iptables -I FORWARD -i mirage2 -j ACCEPT
iptables -I FORWARD -o mirage2 -j ACCEPT

$B server -listen 0.0.0.0:$PORT -key "$SPRIV" -reality -dest "$DEST" -reality-psk "$PSK" \
   -tun -tun-name mirage2 -tun-addr 10.9.0.1/24 -nat -wan "$WAN" > /root/mirage_real_srv.log 2>&1 &
sleep 1.5

ip netns exec $NS $B client -connect $LINK.1:$PORT -server "$SPUB" -key "$CPRIV" \
   -reality -reality-psk "$PSK" -sni "$SNI" \
   -tun -tun-name mirage2 -tun-addr 10.9.0.2/24 -keepalive 15s > /root/mirage_real_cli.log 2>&1 &

for i in $(seq 1 30); do
  ip netns exec $NS ip link show mirage2 >/dev/null 2>&1 && break
  sleep 0.3
done
ip netns exec $NS ip route add default via 10.9.0.1 dev mirage2 2>/dev/null \
  || ip netns exec $NS ip route add default dev mirage2
sleep 1

echo "=== server log ==="; cat /root/mirage_real_srv.log
echo "=== client log ==="; cat /root/mirage_real_cli.log
echo
echo "=== ТЕСТ 1: туннель — egress IP через Reality (ожидаем IP сервера) ==="
SRV_IP=$(curl -4 -s --max-time 12 https://ifconfig.me); echo "сервер: $SRV_IP"
NS_IP=$(ip netns exec $NS curl -4 -s --max-time 15 https://ifconfig.me); echo "через туннель: $NS_IP"
echo
echo "=== ТЕСТ 2: ANTI-PROBE — зонд на порт $PORT должен увидеть НАСТОЯЩИЙ $SNI ==="
echo "(без -k: валидный сертификат = трафик реально ушёл на microsoft)"
curl -s --max-time 15 --resolve $SNI:$PORT:127.0.0.1 "https://$SNI:$PORT/" \
   -o /dev/null -w "зонд: HTTP=%{http_code}  tls_verify=%{ssl_verify_result} (0=валидный серт)\n" \
   || echo "зонд: ошибка"
echo
if [ -n "$NS_IP" ] && [ "$NS_IP" = "$SRV_IP" ]; then
  echo "ТУННЕЛЬ: ✅ трафик выходит через сервер ($NS_IP)"
else
  echo "ТУННЕЛЬ: ❌ ns='$NS_IP' srv='$SRV_IP'"
fi
