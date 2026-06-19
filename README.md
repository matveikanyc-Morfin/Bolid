# bolid

![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-experimental-orange)

> **EN:** **bolid** is a from-scratch VPN protocol (codename **MIRAGE**) for
> DPI-resistant censorship circumvention with modern, vetted cryptography
> (WireGuard-grade). It features a Noise_IK handshake, Elligator2 key masking
> (the first packet looks like uniform random noise), a cheap MAC1 anti-probe
> guard, sliding-window anti-replay, multi-peer routing, reconnect/roaming, and
> a TLS/Reality profile. Written in Go. For lawful anti-censorship, privacy and
> educational use. No home-made crypto — only standard, reviewed primitives.

**bolid** — собственный VPN-протокол (кодовое имя **MIRAGE**), спроектированный
с нуля для устойчивого обхода DPI и блокировок при современной, проверенной
криптографии. Реализация на Go.

> ⚠️ Проект для **законного** обхода цензуры, приватности и инженерного обучения.
> Используются только стандартные вычитанные крипто-примитивы — никаких
> самодельных схем.

## Идея

Трафик MIRAGE должен быть **неотличим от случайного шума** (а в перспективе — от
обычного HTTPS), устойчив к пассивному DPI и к активному зондированию. При этом
данные защищены современной криптографией уровня WireGuard.

## Возможности

- **Рукопожатие Noise_IK** — X25519 / ChaCha20-Poly1305 / BLAKE2s (фреймворк
  [flynn/noise](https://github.com/flynn/noise)).
- **Elligator2-маскировка** эфемерных ключей — первый пакет не содержит узнаваемой
  точки кривой, выглядит равномерным шумом («look like nothing», как obfs4).
- **MAC1** — дешёвая защита от зондов и DoS: сервер отбрасывает чужой пакет одним
  хешем ещё до X25519 и не выдаёт себя (anti-probe).
- **Anti-replay** — скользящее окно по 64-битному счётчику (допускает
  переупорядочивание UDP, блокирует повторы).
- **L3-туннель** (TUN) с выходом в интернет через NAT.
- **Multi-peer сервер**, аутентификация по статическому ключу.
- **Реконнект и роуминг** — сессия переживает смену сети (Wi-Fi ↔ LTE, смена NAT).
- **Профиль TLS/Reality** — туннель внутри настоящего TLS 1.3, релей зондов на
  сайт-приманку (обход по 443, мимикрия под HTTPS).
- **`mirage://` share-ссылки** и провижининг пользователей одной командой.
- **gomobile-обёртка** — фундамент под мобильные клиенты (iOS/Android).

## Слоистая архитектура

```
┌─────────────────────────────────────────────────────────────┐
│ L4  Интеграция:  TUN-устройство (L3-профиль) | SOCKS5 (mux)   │
├─────────────────────────────────────────────────────────────┤
│ L3  Мультиплексор: stream_id, flow-control, control-stream    │
├─────────────────────────────────────────────────────────────┤
│ L2  Защищённая сессия: Noise_IK + AEAD-записи, anti-replay,   │
│     ротация ключей, роуминг                                   │
├─────────────────────────────────────────────────────────────┤
│ L1  Транспорт+обфускация: UDP|TCP × профиль мимикрии          │
│     (random / Elligator2 / TLS-Reality)                       │
└─────────────────────────────────────────────────────────────┘
```

## Сборка

Нужен **Go 1.25+**.

```sh
go build -o bin/mirage ./cmd/mirage
```

## Быстрая проверка (локально, без root)

```sh
./bin/mirage genkey                 # выполнить дважды: серверу и клиенту
# терминал 1 — эхо-сервер:
./bin/mirage server -listen 127.0.0.1:5555 -key <SERVER_PRIV>
# терминал 2 — клиент:
./bin/mirage client -connect 127.0.0.1:5555 -server <SERVER_PUB> -key <CLIENT_PRIV> -msg "привет"
```

Клиент покажет расшифрованное эхо — значит рукопожатие (Noise_IK + Elligator2 +
MAC1) и шифрованная сессия работают.

## VPN-туннель (Linux-сервер, root)

```sh
# сервер: туннель + NAT в интернет
sudo ./mirage server -listen 0.0.0.0:5555 -key-file server.key \
  -tun -tun-addr 10.7.0.1/24 -mtu 1380 -nat

# клиент
sudo ./mirage client -connect <SERVER_IP>:5555 -server <SERVER_PUB> \
  -key-file client.key -tun -tun-addr 10.7.0.2/24 -peer 10.7.0.1 -keepalive 10s
```

Multi-peer, `adduser` и `mirage://`-ссылки — см. `cmd/mirage` и `scripts/`.

## Криптография (без самодельных примитивов)

| Назначение | Что используется |
|---|---|
| Рукопожатие / AEAD | Noise_IK через [flynn/noise](https://github.com/flynn/noise) |
| DH / шифр / хеш | X25519 / ChaCha20-Poly1305 / BLAKE2s |
| Elligator2 (decode) | [edwards25519-extra](https://gitlab.com/yawning/edwards25519-extra) (BSD) |
| Elligator2 (encode) | алгоритм Monocypher (Loup Vaillant) поверх [filippo.io/edwards25519](https://filippo.io/edwards25519) (BSD) |
| MAC1 | Keyed-BLAKE2s-128 |

## Статус

Работает: туннель UDP (Noise_IK + ChaCha20 + anti-replay), Elligator2 + MAC1,
multi-peer, реконнект/роуминг, профиль TLS/Reality, провижининг, мобильная
библиотека.

В планах: ротация ключей (rekey), MAC2/cookie против флуда с подделкой IP,
timestamp-anti-replay рукопожатия, доводка развёртывания Reality на 443,
kill-switch / защита от утечек в клиентах.

## Лицензия

[MIT](LICENSE).

## Дисклеймер

Предназначено для законного обхода цензуры, защиты приватности и обучения.
Методы анти-зондирования и мимикрии — стандартные приёмы из академических
pluggable transports (obfs4, Tor), не вредоносные техники.
