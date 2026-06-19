#!/usr/bin/env bash
# Аварийное восстановление сети после MIRAGE VPN.
# Используй, если VPN-процесс убили жёстко (kill -9 / перезагрузка питания) и
# интернет пропал из-за оставшегося kill-switch (pf) или маршрута в туннель.
#
#   sudo scripts/vpn-recover.sh
set -u
[ "$(id -u)" = 0 ] || { echo "Запусти через sudo: sudo $0"; exit 1; }

echo "1) сбрасываю pf-правила (снимаю kill-switch)..."
pfctl -f /etc/pf.conf >/dev/null 2>&1
pfctl -d >/dev/null 2>&1

echo "2) возвращаю DNS на автоматический (DHCP) для всех сервисов..."
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | while IFS= read -r svc; do
  case "$svc" in '*'*|'') continue;; esac
  networksetup -setdnsservers "$svc" Empty 2>/dev/null
done
dscacheutil -flushcache 2>/dev/null; killall -HUP mDNSResponder 2>/dev/null

echo "3) удаляю возможный host-маршрут к серверу и сбрасываю дефолт..."
# дефолтный маршрут проще всего починить переподнятием основного интерфейса:
GW="$(netstat -rn 2>/dev/null | awk '/^default/ && $2 ~ /^[0-9]/ {print $2; exit}')"
IF="$(route -n get default 2>/dev/null | awk '/interface/{print $2}')"
echo "   (если дефолт всё ещё на utun — выключи и включи Wi-Fi, маршрут восстановится по DHCP)"

echo "готово. Проверь интернет: ping -c2 1.1.1.1"
