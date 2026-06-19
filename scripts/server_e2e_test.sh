#!/usr/bin/env bash
# E2E-тест туннеля MIRAGE на одной Linux-машине через сетевые namespace.
#
# Топология:
#   [namespace mcli] ── veth ── [root ns: mirage server + TUN + NAT] ── WAN ── интернет
#
# Клиент (в mcli) гонит весь трафик через TUN → сессия MIRAGE → UDP → сервер →
# NAT → интернет. Если curl из mcli показывает публичный IP сервера — туннель
# работает по-настоящему.
set -u

B=/root/mirage
NS=mcli
LOG_SRV=/root/mirage_srv.log
LOG_CLI=/root/mirage_cli.log
WAN=$(ip route show default | awk '/default/{print $5; exit}')

cleanup() {
  echo "=== cleanup ==="
  ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
  pkill -f "$B server" 2>/dev/null
  ip netns del $NS 2>/dev/null
  ip link del veth-host 2>/dev/null
  ip link del mirage0 2>/dev/null
  iptables -t nat -D POSTROUTING -s 10.7.0.0/24 -o "$WAN" -j MASQUERADE 2>/dev/null
  iptables -D FORWARD -i mirage0 -o "$WAN" -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i "$WAN" -o mirage0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i mirage0 -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o mirage0 -j ACCEPT 2>/dev/null
  iptables -D INPUT -i veth-host -j ACCEPT 2>/dev/null
  rm -rf /etc/netns/$NS
}
trap cleanup EXIT
cleanup  # на случай остатков от прошлого запуска
trap cleanup EXIT

echo "WAN-интерфейс: $WAN"

# --- ключи ---
SRV=$($B genkey); SPRIV=$(echo "$SRV" | awk '/private/{print $3}'); SPUB=$(echo "$SRV" | awk '/public/{print $3}')
CLI=$($B genkey); CPRIV=$(echo "$CLI" | awk '/private/{print $3}')
echo "server pub: $SPUB"

# --- namespace клиента + veth ---
ip netns add $NS
ip link add veth-host type veth peer name veth-cli
ip link set veth-cli netns $NS
ip addr add 10.99.0.1/24 dev veth-host
ip link set veth-host up
ip netns exec $NS ip addr add 10.99.0.2/24 dev veth-cli
ip netns exec $NS ip link set veth-cli up
ip netns exec $NS ip link set lo up

# DNS для namespace (резолвинг пойдёт через туннель)
mkdir -p /etc/netns/$NS
echo "nameserver 1.1.1.1" > /etc/netns/$NS/resolv.conf

# ufw на сервере имеет INPUT policy DROP — разрешаем трафик на внутреннем veth,
# иначе UDP клиента не дойдёт до mirage. И подстраховка по FORWARD для mirage0.
iptables -I INPUT -i veth-host -j ACCEPT
iptables -I FORWARD -i mirage0 -j ACCEPT
iptables -I FORWARD -o mirage0 -j ACCEPT

# --- сервер (root ns) с TUN + NAT ---
$B server -listen 0.0.0.0:5555 -key "$SPRIV" -tun -tun-addr 10.7.0.1/24 -nat -wan "$WAN" > $LOG_SRV 2>&1 &
sleep 1.5

# --- клиент (в namespace) с TUN ---
ip netns exec $NS $B client -connect 10.99.0.1:5555 -server "$SPUB" -key "$CPRIV" \
    -tun -tun-addr 10.7.0.2/24 -keepalive 15s > $LOG_CLI 2>&1 &

# ждём появления tun у клиента
for i in $(seq 1 30); do
  ip netns exec $NS ip link show mirage0 >/dev/null 2>&1 && break
  sleep 0.3
done
# весь трафик namespace — в туннель
ip netns exec $NS ip route add default via 10.7.0.1 dev mirage0 2>/dev/null \
  || ip netns exec $NS ip route add default dev mirage0
sleep 1

echo "=== server log ==="; cat $LOG_SRV
echo "=== client log ==="; cat $LOG_CLI
echo
echo "=== интерфейсы в namespace ==="
ip netns exec $NS ip -brief addr
echo "=== маршруты в namespace ==="
ip netns exec $NS ip route

echo
echo "=== ТЕСТ 1: ping 1.1.1.1 через туннель ==="
ip netns exec $NS ping -c 3 -W 3 1.1.1.1

echo
echo "=== ТЕСТ 2: публичный IPv4 сервера (напрямую) ==="
SRV_IP=$(curl -4 -s --max-time 12 https://ifconfig.me); echo "$SRV_IP"
echo "=== ТЕСТ 3: публичный IP из namespace ЧЕРЕЗ ТУННЕЛЬ ==="
NS_IP=$(ip netns exec $NS curl -s --max-time 15 https://ifconfig.me); echo "$NS_IP"

echo
if [ -n "$NS_IP" ] && [ "$NS_IP" = "$SRV_IP" ]; then
  echo "РЕЗУЛЬТАТ: ✅ ТУННЕЛЬ РАБОТАЕТ — трафик namespace выходит через сервер ($NS_IP)"
else
  echo "РЕЗУЛЬТАТ: ❌ что-то не так (ns='$NS_IP' srv='$SRV_IP')"
fi
