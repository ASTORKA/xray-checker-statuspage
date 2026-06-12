#!/usr/bin/env bash
# Установщик probe-агента xray-checker-statuspage для Linux.
# Регистрирует пробник на сервере, кладёт agent.py + xray в ~/.xrs-probe/,
# создаёт systemd-user-сервис для авто-запуска (с авто-перезапуском).
#
# Использование:
#   bash install-linux.sh           # интерактивный режим
#   STATUSPAGE_URL=... ADMIN_TOKEN=... bash install-linux.sh
#   bash install-linux.sh --uninstall
#
# Подписку (URL прокси-конфигов) задаёт владелец сервера через env
# PROBE_SUBSCRIPTION_URL — на устройство пользователя она НЕ попадает.
set -euo pipefail

APP_DIR="${HOME}/.xrs-probe"
UNIT_NAME="xrs-probe.service"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT_FILE="${UNIT_DIR}/${UNIT_NAME}"
LOCAL_BIN="${HOME}/.local/bin"
REPO_RAW="https://raw.githubusercontent.com/ASTORKA/xray-checker-statuspage/main/probes"
AGENT_RAW_URL="${REPO_RAW}/agent.py"
MONITORVPN_RAW_URL="${REPO_RAW}/monitorvpn-linux"

c_g(){ printf "\033[32m%s\033[0m\n" "$*"; }
c_y(){ printf "\033[33m%s\033[0m\n" "$*"; }
c_r(){ printf "\033[31m%s\033[0m\n" "$*"; }
die(){ c_r "ОШИБКА: $*"; exit 1; }

uninstall(){
  c_y "Удаление…"
  systemctl --user disable --now "${UNIT_NAME}" 2>/dev/null || true
  rm -f "${UNIT_FILE}"
  systemctl --user daemon-reload 2>/dev/null || true
  rm -rf "${APP_DIR}"
  rm -f "${LOCAL_BIN}/monitorvpn"
  c_g "✓ удалено."
  exit 0
}

[ "${1:-}" = "--uninstall" ] && uninstall

[ "$(uname)" = "Linux" ] || die "этот установщик только для Linux."
command -v systemctl >/dev/null 2>&1 || die "не найден systemctl (нужен systemd)."
PYTHON="$(command -v python3 || true)"
[ -n "${PYTHON}" ] || die "не найден python3. Поставь: sudo apt install python3 (или аналог)."
command -v unzip >/dev/null 2>&1 || die "не найден unzip. Поставь: sudo apt install unzip."
command -v curl  >/dev/null 2>&1 || die "не найден curl. Поставь: sudo apt install curl."
# systemctl --user требует пользовательскую шину; в headless/ssh без сессии её может не быть.
if ! systemctl --user show-environment >/dev/null 2>&1; then
  die "недоступен systemd --user (нет пользовательской сессии). Зайди в графическую сессию или включи лингер: loginctl enable-linger ${USER}"
fi

ask(){ local p="$1" d="${2:-}" v=""; if [ -n "$d" ]; then read -rp "$p [$d]: " v; else read -rp "$p: " v; fi; echo "${v:-$d}"; }
asks(){ local p="$1" v=""; read -rsp "$p: " v; echo >&2; printf '%s' "$v"; }

c_g "== xray-checker-statuspage probe agent (Linux) =="
echo

[ -n "${STATUSPAGE_URL:-}" ] || STATUSPAGE_URL="$(ask 'URL статус-страницы (https://...)')"
[ -n "${ADMIN_TOKEN:-}" ] || ADMIN_TOKEN="$(asks 'ADMIN_TOKEN статус-страницы')"
DEFAULT_NAME="Linux-$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "$(whoami)")"
[ -n "${PROBE_NAME:-}" ] || PROBE_NAME="$(ask 'Имя пробника' "${DEFAULT_NAME}")"
INTERVAL="${INTERVAL:-60}"
EXPECT_COUNTRY="${EXPECT_COUNTRY:-RU}"

[ -n "${STATUSPAGE_URL}" ] && [ -n "${ADMIN_TOKEN}" ] \
  || die "URL статус-страницы и ADMIN_TOKEN обязательны."

STATUSPAGE_URL="${STATUSPAGE_URL%/}"

c_g "→ регистрируем пробник на сервере…"
RESP="$(curl -fsSL -X POST \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"${PROBE_NAME}\",\"mode\":\"merge\"}" \
  "${STATUSPAGE_URL}/api/admin/probes")" \
  || die "регистрация не удалась. Проверь URL и ADMIN_TOKEN."
PROBE_ID="$(echo "${RESP}" | "${PYTHON}" -c 'import sys,json;print(json.load(sys.stdin)["probe_id"])')" \
  || die "не удалось распарсить ответ сервера: ${RESP}"
PROBE_TOKEN="$(echo "${RESP}" | "${PYTHON}" -c 'import sys,json;print(json.load(sys.stdin)["probe_token"])')"
echo "  probe_id: ${PROBE_ID}"

c_g "→ устанавливаем агент в ${APP_DIR}…"
mkdir -p "${APP_DIR}" "${UNIT_DIR}" "${LOCAL_BIN}"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SELF_DIR}/agent.py" ]; then
  cp "${SELF_DIR}/agent.py" "${APP_DIR}/agent.py"
  echo "  agent.py скопирован из ${SELF_DIR}"
else
  curl -fsSL "${AGENT_RAW_URL}" -o "${APP_DIR}/agent.py" \
    || die "не удалось скачать agent.py с GitHub"
  echo "  agent.py скачан с GitHub"
fi
chmod 600 "${APP_DIR}/agent.py"

# monitorvpn CLI (Linux-вариант)
if [ -f "${SELF_DIR}/monitorvpn-linux" ]; then
  cp "${SELF_DIR}/monitorvpn-linux" "${APP_DIR}/monitorvpn"
else
  curl -fsSL "${MONITORVPN_RAW_URL}" -o "${APP_DIR}/monitorvpn" \
    || c_y "не удалось скачать monitorvpn-linux (необязательно)"
fi
chmod +x "${APP_DIR}/monitorvpn" 2>/dev/null || true
ln -sf "${APP_DIR}/monitorvpn" "${LOCAL_BIN}/monitorvpn"
case ":${PATH}:" in
  *":${LOCAL_BIN}:"*) : ;;
  *) c_y "  ${LOCAL_BIN} не в PATH — добавь в ~/.bashrc: export PATH=\"\$HOME/.local/bin:\$PATH\"";;
esac

# xray-core: качаем релиз под архитектуру (пин v25.12.8 — до 26.x, где REALITY
# требует password). Override: XRAY_VERSION=latest bash install-linux.sh.
if [ ! -x "${APP_DIR}/xray" ]; then
  c_g "→ ставим xray-core в ${APP_DIR}/xray…"
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64|amd64)   ZIP_NAME="Xray-linux-64.zip" ;;
    aarch64|arm64)  ZIP_NAME="Xray-linux-arm64-v8a.zip" ;;
    armv7l|armv7)   ZIP_NAME="Xray-linux-arm32-v7a.zip" ;;
    *) die "неизвестная архитектура: ${ARCH}. Поставь xray вручную в ${APP_DIR}/xray" ;;
  esac
  XRAY_VERSION="${XRAY_VERSION:-v25.12.8}"
  if [ "${XRAY_VERSION}" = "latest" ]; then
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/${ZIP_NAME}"
  else
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${ZIP_NAME}"
  fi
  TMP="$(mktemp -d)"
  if curl -fL --retry 2 "${XRAY_URL}" -o "${TMP}/xray.zip"; then
    if unzip -oq "${TMP}/xray.zip" xray -d "${APP_DIR}" 2>/dev/null; then
      chmod +x "${APP_DIR}/xray"
      echo "  ✓ xray установлен ($("${APP_DIR}/xray" version 2>/dev/null | head -1 || echo 'версия неизвестна'))"
    else
      c_y "не удалось распаковать ${ZIP_NAME}. Поставь xray вручную в ${APP_DIR}/xray"
    fi
  else
    c_y "не удалось скачать ${XRAY_URL}. Поставь xray вручную в ${APP_DIR}/xray"
  fi
  rm -rf "${TMP}"
fi

c_g "→ регистрируем systemd-user-сервис ${UNIT_NAME}…"
cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=xray-checker-statuspage probe agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=STATUSPAGE_URL=${STATUSPAGE_URL}
Environment=PROBE_TOKEN=${PROBE_TOKEN}
Environment=INTERVAL=${INTERVAL}
Environment=EXPECT_COUNTRY=${EXPECT_COUNTRY}
ExecStart=${PYTHON} ${APP_DIR}/agent.py
Restart=always
RestartSec=15

[Install]
WantedBy=default.target
EOF
chmod 600 "${UNIT_FILE}"

systemctl --user daemon-reload
systemctl --user enable --now "${UNIT_NAME}"

# Лингер: чтобы сервис работал даже без активного логина (на ноутбуке — после
# выхода из сессии). Требует прав — пробуем, при отказе подсказываем.
if ! loginctl show-user "${USER}" 2>/dev/null | grep -q 'Linger=yes'; then
  if loginctl enable-linger "${USER}" 2>/dev/null; then
    echo "  ✓ linger включён — агент работает и без активного логина"
  else
    c_y "  чтобы агент работал без входа в сессию, выполни один раз:"
    echo "    sudo loginctl enable-linger ${USER}"
  fi
fi

echo
c_g "✓ агент запущен. При загрузке системы будет стартовать сам."
echo "   Управление:  monitorvpn {start|stop|restart|status|logs|refresh|update|xray-update|delete}"
echo "   Логи:        journalctl --user -u xrs-probe -f"
echo "   Снести:      monitorvpn delete   (или: bash \"$0\" --uninstall)"
echo
c_y "Если 'monitorvpn: command not found' — перезайди в shell или добавь ~/.local/bin в PATH."
c_y "Подсказка: первая строка лога — «start: interval=...» через ~5 сек."
