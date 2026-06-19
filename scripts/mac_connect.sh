#!/usr/bin/env bash
# Подключение macOS-клиента к серверу MIRAGE.
#
#   sudo ./mac_connect.sh test    # БЕЗОПАСНО: через туннель идёт только проверочный
#                                 # трафик; основной интернет Mac не затрагивается.
#   sudo ./mac_connect.sh full    # весь трафик Mac через VPN + kill-switch и защита
#                                 # от утечек (DNS→1.1.1.1, блок IPv6). При обрыве
#                                 # туннеля трафик блокируется (нет утечки в обход VPN).
#
# Требует root (utun, маршруты, pf, DNS). Параметры берутся из impl/keys.env.
# Аварийное восстановление сети (если процесс убили жёстко): scripts/vpn-recover.sh
set -u

MODE="${1:-test}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"   # .../impl
BIN="$DIR/bin/mirage"
ENVF="$DIR/keys.env"
LOG=/tmp/mirage_client.log
PFCONF=/tmp/mirage_pf.conf
DNS_STATE=/tmp/mirage_dns_state

[ "$(id -u)" = 0 ] || { echo "Запусти через sudo: sudo $0 $MODE"; exit 1; }
[ -x "$BIN" ] || { echo "Нет бинаря $BIN — собери: (cd $DIR && source env.sh && go build -o bin/mirage ./cmd/mirage)"; exit 1; }
[ -f "$ENVF" ] || { echo "Нет $ENVF"; exit 1; }
# shellcheck disable=SC1090
source "$ENVF"
# UDP-профиль (рабочий на этом хостере). Reality (3b) реализован, но некоторые
# VPS-хостеры перехватывают SNI'd TLS на нестандартных портах — см. 06/PROGRESS.
SERVER_IP="${ENDPOINT%%:*}"
SERVER_PORT="${ENDPOINT##*:}"

CLI_PID=""
UTUN=""
OLD_GW=""; OLD_IF=""
declare -a HOST_ROUTES=()
KILLSWITCH=0
PF_WAS_ENABLED=0
DNS_SAVED=0

# --- Защита от утечек: DNS через туннель ---

save_and_set_dns() {
  : > "$DNS_STATE"
  local svc cur
  while IFS= read -r svc; do
    case "$svc" in '*'*|'') continue;; esac   # пропускаем отключённые/пустые
    cur="$(networksetup -getdnsservers "$svc" 2>/dev/null)"
    if printf '%s' "$cur" | grep -qi "aren't any"; then
      cur="Empty"
    else
      cur="$(printf '%s' "$cur" | tr '\n' ' ' | sed 's/ *$//')"
    fi
    printf '%s\t%s\n' "$svc" "$cur" >> "$DNS_STATE"
    networksetup -setdnsservers "$svc" 1.1.1.1 1.0.0.1 2>/dev/null
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  DNS_SAVED=1
  dscacheutil -flushcache 2>/dev/null; killall -HUP mDNSResponder 2>/dev/null
}

restore_dns() {
  [ "$DNS_SAVED" = 1 ] || return 0
  local svc vals
  while IFS=$'\t' read -r svc vals; do
    [ -n "$svc" ] || continue
    if [ "$vals" = "Empty" ] || [ -z "$vals" ]; then
      networksetup -setdnsservers "$svc" Empty 2>/dev/null
    else
      # shellcheck disable=SC2086
      networksetup -setdnsservers "$svc" $vals 2>/dev/null
    fi
  done < "$DNS_STATE"
  dscacheutil -flushcache 2>/dev/null; killall -HUP mDNSResponder 2>/dev/null
  DNS_SAVED=0
}

# --- Kill-switch: pf пропускает только туннель и трафик к серверу ---

load_killswitch() {
  cat > "$PFCONF" <<EOF
# MIRAGE kill-switch (генерируется автоматически)
set block-policy drop
set skip on lo0
# DHCP — чтобы физический линк сохранял аренду адреса
pass quick proto udp from any to any port { 67, 68 }
# зашифрованный туннель к серверу MIRAGE (единственное, что уходит наружу)
pass out quick proto udp from any to $SERVER_IP port $SERVER_PORT
pass in  quick proto udp from $SERVER_IP port $SERVER_PORT to any
# весь трафик внутри VPN-туннеля
pass quick on $UTUN all
# kill-switch: IPv6 целиком и всё прочее — блок (нет утечки при обрыве VPN)
block drop quick inet6 all
block drop all
EOF
  # Проверяем правила ДО применения; при ошибке не трогаем сеть.
  if ! pfctl -nf "$PFCONF" >/dev/null 2>&1; then
    echo "⚠️ pf-правила не прошли проверку — kill-switch НЕ включён (маршруты всё равно работают)."
    return 1
  fi
  if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then PF_WAS_ENABLED=1; else PF_WAS_ENABLED=0; fi
  pfctl -Ef "$PFCONF" >/dev/null 2>&1
  KILLSWITCH=1
  return 0
}

restore_pf() {
  [ "$KILLSWITCH" = 1 ] || return 0
  pfctl -f /etc/pf.conf >/dev/null 2>&1
  [ "$PF_WAS_ENABLED" = 0 ] && pfctl -d >/dev/null 2>&1
  KILLSWITCH=0
}

cleanup() {
  echo; echo "=== отключение: восстановление сети ==="
  restore_pf                                   # сперва снимаем блокировку
  if [ "$MODE" = full ] && [ -n "$OLD_GW" ]; then
    route -n change default "$OLD_GW" >/dev/null 2>&1
  fi
  route -n delete -host "$SERVER_IP" >/dev/null 2>&1
  for r in "${HOST_ROUTES[@]}"; do route -n delete -host "$r" >/dev/null 2>&1; done
  restore_dns                                  # возвращаем системный DNS
  [ -n "$CLI_PID" ] && kill "$CLI_PID" >/dev/null 2>&1
  echo "готово, сеть восстановлена."
}
trap cleanup EXIT INT TERM

echo "=== запускаю клиент MIRAGE (UDP) → $ENDPOINT ==="
"$BIN" client -connect "$ENDPOINT" -server "$SERVER_PUB" -key "$CLIENT_PRIV" \
  -tun -tun-addr 10.7.0.2/24 -peer 10.7.0.1 -mtu 1380 -keepalive 10s > "$LOG" 2>&1 &
CLI_PID=$!

# ждём появления utun с адресом 10.7.0.2
for _ in $(seq 1 40); do
  for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
    if ifconfig "$i" 2>/dev/null | grep -q 'inet 10.7.0.2'; then UTUN="$i"; break; fi
  done
  [ -n "$UTUN" ] && break
  kill -0 "$CLI_PID" 2>/dev/null || { echo "клиент завершился, лог:"; cat "$LOG"; exit 1; }
  sleep 0.3
done
[ -n "$UTUN" ] || { echo "не удалось поднять utun за 12с, лог:"; cat "$LOG"; exit 1; }

echo "=== клиент поднял интерфейс $UTUN (10.7.0.2 ↔ 10.7.0.1) ==="
cat "$LOG"

if [ "$MODE" = test ]; then
  echo
  echo "=== РЕЖИМ TEST: через туннель только проверочные адреса ==="
  route -n add -host 1.1.1.1 -interface "$UTUN" >/dev/null 2>&1; HOST_ROUTES+=("1.1.1.1")
  IPME="$(dig +short ifconfig.me A 2>/dev/null | grep -E '^[0-9]' | head -1)"
  RESOLVE=""
  if [ -n "$IPME" ]; then
    route -n add -host "$IPME" -interface "$UTUN" >/dev/null 2>&1; HOST_ROUTES+=("$IPME")
    RESOLVE="--resolve ifconfig.me:443:$IPME"
  fi
  echo "--- ping 1.1.1.1 через туннель ---"
  ping -c 3 -t 3 1.1.1.1
  echo "--- egress IP через туннель (ожидаем IP сервера $SERVER_IP) ---"
  # shellcheck disable=SC2086
  OUT="$(curl -4 --max-time 12 $RESOLVE https://ifconfig.me 2>/dev/null)"; echo "$OUT"
  echo
  if [ "$OUT" = "$SERVER_IP" ]; then
    echo "✅ macOS-клиент РАБОТАЕТ: трафик выходит через сервер. Для полного VPN: sudo $0 full"
  else
    echo "⚠️ egress IP='$OUT' (ждали $SERVER_IP). ping выше показывает, идёт ли трафик вообще."
  fi
  echo "(нажми Enter для отключения)"; read -r _
  exit 0
fi

if [ "$MODE" = full ]; then
  OLD_GW="$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')"
  OLD_IF="$(route -n get default 2>/dev/null | awk '/interface/{print $2}')"
  echo "=== РЕЖИМ FULL: весь трафик через VPN (старый шлюз $OLD_GW dev $OLD_IF) ==="
  [ -n "$OLD_GW" ] || { echo "не нашёл текущий шлюз — отмена"; exit 1; }
  # трафик до сервера — мимо туннеля (иначе петля)
  route -n add -host "$SERVER_IP" "$OLD_GW" >/dev/null 2>&1
  # дефолт — в туннель
  route -n change default -interface "$UTUN" >/dev/null 2>&1 \
    || route -n add -net default -interface "$UTUN" >/dev/null 2>&1

  # Защита от утечек + kill-switch
  save_and_set_dns
  load_killswitch
  echo
  if [ "$KILLSWITCH" = 1 ]; then
    echo "✅ VPN активен. Весь трафик через сервер $SERVER_IP."
    echo "   🛡️  kill-switch ВКЛ: при обрыве туннеля трафик блокируется (нет утечки)."
    echo "   🔒 DNS → 1.1.1.1 через туннель; IPv6 заблокирован."
  else
    echo "✅ VPN активен (маршруты), но kill-switch не включился — см. предупреждение выше."
  fi
  echo "   Ctrl-C — отключить, вернуть маршруты/DNS/pf."
  echo "   Если интернет пропал после жёсткого завершения: sudo $DIR/scripts/vpn-recover.sh"
  wait "$CLI_PID"
  exit 0
fi

echo "неизвестный режим: $MODE (используй test|full)"; exit 2
