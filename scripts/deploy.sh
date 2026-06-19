#!/usr/bin/env bash
# Деплой свежего бинаря MIRAGE на сервер NL и перезапуск сервиса — за один заход.
# Спросит ОДИН раз пароль сервера. Ключи на сервере не трогаем (меняем только код).
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"   # .../impl
# Параметры сервера переопредели через окружение:
#   export MIRAGE_SSH=root@1.2.3.4   export MIRAGE_SSH_KEY=~/.ssh/your_key
SERVER="${MIRAGE_SSH:-root@YOUR_SERVER_IP}"
BIN="$DIR/bin/mirage-linux-amd64"
KEY="${MIRAGE_SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH=(ssh -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=10)

[ -x "$BIN" ] || { echo "Нет linux-бинаря $BIN — собери: (cd $DIR && source env.sh && GOOS=linux GOARCH=amd64 go build -o bin/mirage-linux-amd64 ./cmd/mirage)"; exit 1; }

echo "=== заливаю MIRAGE на сервер и перезапускаю ==="
# Пишем во временный файл и подменяем через mv (безопасно для работающего бинаря),
# затем рестартим сервис и печатаем его статус. Всё одним SSH-подключением по ключу.
"${SSH[@]}" "$SERVER" 'cat > /root/mirage.new && chmod +x /root/mirage.new && mv /root/mirage.new /root/mirage && systemctl restart mirage && sleep 1.5 && echo -n "статус сервиса: " && systemctl is-active mirage && echo -n "слушает 5555: " && (ss -lunp | grep -q 5555 && echo да || echo нет)' < "$BIN"

echo
echo "✅ Сервер обновлён до 0.2. Теперь подключай VPN:  sudo scripts/mac_connect.sh test"
