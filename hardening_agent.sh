#!/usr/bin/env bash
# hardening_agent.sh — CCDC Linux hardening state collector + phone-home agent
#
# Recolecta servicios, procesos, tareas programadas, permisos, usuarios, red,
# firewall y puntos de persistencia; luego IMPRIME o ENVÍA un reporte JSON al
# servidor central para diagnóstico con LLM.
#
#   ./hardening_agent.sh text     # volcado legible a stdout
#   ./hardening_agent.sh local    # JSON a stdout (sin red)
#   ./hardening_agent.sh send      # POST JSON a $HARDEN_SERVER  (default)
#
# Config por variables de entorno:
#   HARDEN_SERVER=http://10.0.0.5:8000/report
#   HARDEN_TOKEN=secreto-compartido
#
# Correr como root para cobertura completa (estado de shadow, todos los
# crontabs, todas las authorized_keys). NO exporta hashes, solo su estado.

set -uo pipefail

SERVER_URL="${HARDEN_SERVER:-http://127.0.0.1:8000/report}"
AUTH_TOKEN="${HARDEN_TOKEN:-changeme-shared-secret}"
MODE="${1:-send}"
FIND_TIMEOUT="${HARDEN_FIND_TIMEOUT:-25}"
CAP=200

b64()  { printf '%s' "${1:-}" | base64 | tr -d '\n'; }
jesc() { printf '"%s"' "$(printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g')"; }
h()    { printf '\n## %s\n' "$1"; }              # sub-encabezado dentro de una sección
tmo()  { timeout "$FIND_TIMEOUT" "$@" 2>/dev/null || true; }

collect_system() {
  h "Kernel / arch";    uname -a 2>/dev/null
  h "OS release";       cat /etc/os-release 2>/dev/null
  h "Uptime / load";    uptime 2>/dev/null
  h "Last boot";        who -b 2>/dev/null
  h "Identidad actual"; id 2>/dev/null
}

collect_users() {
  h "Cuentas (name uid gid shell)"
  awk -F: '{print $1, "uid="$3, "gid="$4, "shell="$7}' /etc/passwd 2>/dev/null
  h "Cuentas UID 0 (deberia ser SOLO root)"
  awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
  h "Cuentas con shell interactiva"
  awk -F: '$7 ~ /(bash|sh|zsh|ksh|fish)$/{print $1" -> "$7}' /etc/passwd 2>/dev/null
  h "Estado de contrasena (EMPTY!/locked/set — NO se exportan hashes)"
  if [ -r /etc/shadow ]; then
    awk -F: '{s=$2; st=(s==""?"EMPTY!":(s ~ /^[!*]/?"locked":"set")); print $1": "st}' /etc/shadow 2>/dev/null
  else
    echo "(se necesita root para leer /etc/shadow)"
  fi
  h "Sudoers / grupos privilegiados"
  grep -Ev '^\s*#|^\s*$' /etc/sudoers 2>/dev/null
  cat /etc/sudoers.d/* 2>/dev/null | grep -Ev '^\s*#|^\s*$'
  getent group sudo wheel admin 2>/dev/null
  h "Logins exitosos recientes"; last -n 15 2>/dev/null
  h "Logins FALLIDOS recientes"; lastb -n 15 2>/dev/null
}

collect_processes() {
  h "Lista completa de procesos"
  ps auxww 2>/dev/null
  h "Procesos lanzados desde tmp/shm/var-tmp (sospechoso)"
  ps auxww 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/' | grep -v grep
  h "Binarios borrados aun corriendo (posible malware en memoria)"
  ls -l /proc/*/exe 2>/dev/null | grep -i '(deleted)'
  h "Herramientas de shell/tunel corriendo"
  ps auxww 2>/dev/null | grep -E '\b(nc|ncat|socat|/bin/bash -i|python.*socket|perl.*socket|msf|meterpreter)\b' | grep -v grep
}

collect_network() {
  h "Sockets en escucha (con proceso)"
  ss -tulpnw 2>/dev/null || netstat -tulpnw 2>/dev/null
  h "Conexiones establecidas"
  ss -tupnw state established 2>/dev/null || { netstat -tupnw 2>/dev/null | grep ESTAB; }
}

collect_services() {
  h "Servicios corriendo"
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    || service --status-all 2>/dev/null
  h "Servicios habilitados al arranque"
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null
  h "Unidades fallidas"
  systemctl --failed --no-pager --no-legend 2>/dev/null
}

collect_scheduled() {
  h "Crontab del sistema"; cat /etc/crontab 2>/dev/null
  h "cron.d / directorios periodicos"
  ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
  cat /etc/cron.d/* 2>/dev/null
  h "Crontabs por usuario"
  for u in $(cut -f1 -d: /etc/passwd 2>/dev/null); do
    out="$(crontab -u "$u" -l 2>/dev/null)"
    [ -n "$out" ] && { echo "### $u"; echo "$out"; }
  done
  h "systemd timers"; systemctl list-timers --all --no-pager --no-legend 2>/dev/null
  h "at jobs"; atq 2>/dev/null
  h "rc.local"; cat /etc/rc.local 2>/dev/null
}

collect_permissions() {
  h "Binarios SUID";  tmo find / -xdev -perm -4000 -type f | head -"$CAP"
  h "Binarios SGID";  tmo find / -xdev -perm -2000 -type f | head -"$CAP"
  h "Archivos world-writable"; tmo find / -xdev -type f -perm -0002 | head -"$CAP"
  h "Directorios world-writable sin sticky bit"; tmo find / -xdev -type d -perm -0002 ! -perm -1000 | head -50
  h "Archivos sin dueno (nouser/nogroup)"; tmo find / -xdev \( -nouser -o -nogroup \) | head -50
}

collect_ssh() {
  h "sshd_config (lineas efectivas)"
  grep -Ev '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null
  h "authorized_keys por usuario"
  for home in /root /home/*; do
    [ -f "$home/.ssh/authorized_keys" ] && { echo "### $home"; cat "$home/.ssh/authorized_keys" 2>/dev/null; }
  done
}

collect_firewall() {
  h "Reglas iptables"; iptables -S 2>/dev/null
  h "Ruleset nftables"; nft list ruleset 2>/dev/null
  h "ufw status"; ufw status verbose 2>/dev/null
  h "firewalld"; firewall-cmd --list-all 2>/dev/null
}

collect_persistence() {
  h "ld.so.preload (deberia estar vacio/ausente)"; cat /etc/ld.so.preload 2>/dev/null
  h "Scripts init.d"; ls -la /etc/init.d 2>/dev/null
  h "Scripts profile.d"; ls -la /etc/profile.d 2>/dev/null
  h "Unidades systemd del sistema"; ls -la /etc/systemd/system 2>/dev/null
  h "Archivos rc de shell (mtime)"
  for home in /root /home/*; do
    ls -la "$home/.bashrc" "$home/.bash_profile" "$home/.profile" 2>/dev/null
  done
  h "Binarios de sistema modificados (<7 dias)"
  tmo find /usr/bin /usr/sbin /bin /sbin -mtime -7 -type f | head -50
}

# ---- recolectar todo ----
declare -A CHECKS
CHECKS[system]="$(collect_system)"
CHECKS[users]="$(collect_users)"
CHECKS[processes]="$(collect_processes)"
CHECKS[network]="$(collect_network)"
CHECKS[services]="$(collect_services)"
CHECKS[scheduled]="$(collect_scheduled)"
CHECKS[permissions]="$(collect_permissions)"
CHECKS[ssh]="$(collect_ssh)"
CHECKS[firewall]="$(collect_firewall)"
CHECKS[persistence]="$(collect_persistence)"

ORDER=(system users processes network services scheduled permissions ssh firewall persistence)
HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
WHO="$(id -un 2>/dev/null || echo unknown)"

build_json() {
  printf '{'
  printf '"hostname":%s,' "$(jesc "$HOST")"
  printf '"timestamp":"%s",' "$TS"
  printf '"collected_as":%s,' "$(jesc "$WHO")"
  printf '"checks":{'
  local first=1
  for k in "${ORDER[@]}"; do
    [ $first -eq 0 ] && printf ','
    first=0
    printf '"%s":"%s"' "$k" "$(b64 "${CHECKS[$k]:-}")"
  done
  printf '}}'
}

case "$MODE" in
  text)
    for k in "${ORDER[@]}"; do
      printf '\n===== %s =====\n' "${k^^}"
      printf '%s\n' "${CHECKS[$k]}"
    done
    ;;
  local)
    build_json; echo
    ;;
  send)
    payload="$(build_json)"
    echo "[*] Host=$HOST as=$WHO bytes=${#payload} -> $SERVER_URL"
    if command -v curl >/dev/null 2>&1; then
      printf '%s' "$payload" | curl -sS -X POST "$SERVER_URL" \
        -H "Content-Type: application/json" -H "X-Auth-Token: $AUTH_TOKEN" \
        --data-binary @- && echo && echo "[+] enviado" || echo "[!] fallo el envio"
    elif command -v wget >/dev/null 2>&1; then
      printf '%s' "$payload" | wget -q -O- --header="Content-Type: application/json" \
        --header="X-Auth-Token: $AUTH_TOKEN" --post-data="$payload" "$SERVER_URL" \
        && echo "[+] enviado (wget)" || echo "[!] fallo el envio"
    else
      echo "[!] no hay curl ni wget; usa modo 'local' y canaliza el JSON tu mismo"
    fi
    ;;
  *)
    echo "uso: $0 {text|local|send}"; exit 1;;
esac
