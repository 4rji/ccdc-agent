#!/usr/bin/env bash
# hardening_agent.sh - CCDC Linux hardening state collector + phone-home agent
#
# Collects services, processes, scheduled tasks, permissions, users, network,
# firewall, and persistence points, then PRINTS or SENDS a JSON report to the
# central server for LLM diagnosis.
#
#   ./hardening_agent.sh text     # human-readable dump to stdout
#   ./hardening_agent.sh local    # JSON to stdout (no network)
#   ./hardening_agent.sh send      # POST JSON to $HARDEN_SERVER  (default)
#
# Config via environment variables:
#   HARDEN_SERVER=http://10.0.0.5:8000/report
#   HARDEN_TOKEN=ccdcagent2026
#
# Run as root for full coverage (shadow status, all crontabs, all
# authorized_keys). Password hashes are NOT exported, only their status.

set -uo pipefail

SERVER_URL="${HARDEN_SERVER:-http://127.0.0.1:8000/report}"
AUTH_TOKEN="${HARDEN_TOKEN:-ccdcagent2026}"
MODE="${1:-send}"
FIND_TIMEOUT="${HARDEN_FIND_TIMEOUT:-25}"
CAP=200

b64()  { printf '%s' "${1:-}" | base64 | tr -d '\n'; }
jesc() { printf '"%s"' "$(printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g')"; }
h()    { printf '\n## %s\n' "$1"; }              # sub-header inside a section
tmo()  { timeout "$FIND_TIMEOUT" "$@" 2>/dev/null || true; }

collect_system() {
  h "Kernel / arch";    uname -a 2>/dev/null
  h "OS release";       cat /etc/os-release 2>/dev/null
  h "Uptime / load";    uptime 2>/dev/null
  h "Last boot";        who -b 2>/dev/null
  h "Current identity"; id 2>/dev/null
}

collect_users() {
  h "Accounts (name uid gid shell)"
  awk -F: '{print $1, "uid="$3, "gid="$4, "shell="$7}' /etc/passwd 2>/dev/null
  h "UID 0 accounts (should be ONLY root)"
  awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
  h "Accounts with an interactive shell"
  awk -F: '$7 ~ /(bash|sh|zsh|ksh|fish)$/{print $1" -> "$7}' /etc/passwd 2>/dev/null
  h "Password status (EMPTY!/locked/set - hashes are NOT exported)"
  if [ -r /etc/shadow ]; then
    awk -F: '{s=$2; st=(s==""?"EMPTY!":(s ~ /^[!*]/?"locked":"set")); print $1": "st}' /etc/shadow 2>/dev/null
  else
    echo "(root is required to read /etc/shadow)"
  fi
  h "Sudoers / privileged groups"
  grep -Ev '^\s*#|^\s*$' /etc/sudoers 2>/dev/null
  cat /etc/sudoers.d/* 2>/dev/null | grep -Ev '^\s*#|^\s*$'
  getent group sudo wheel admin 2>/dev/null
  h "Recent successful logins"; last -n 15 2>/dev/null
  h "Recent FAILED logins"; lastb -n 15 2>/dev/null
}

collect_processes() {
  h "Full process list"
  ps auxww 2>/dev/null
  h "Processes launched from tmp/shm/var-tmp (suspicious)"
  ps auxww 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/' | grep -v grep
  h "Running deleted binaries (possible in-memory malware)"
  ls -l /proc/*/exe 2>/dev/null | grep -i '(deleted)'
  h "Shell/tunnel tools currently running"
  ps auxww 2>/dev/null | grep -E '\b(nc|ncat|socat|/bin/bash -i|python.*socket|perl.*socket|msf|meterpreter)\b' | grep -v grep
}

collect_network() {
  h "Listening sockets (with process)"
  ss -tulpnw 2>/dev/null || netstat -tulpnw 2>/dev/null
  h "Established connections"
  ss -tupnw state established 2>/dev/null || { netstat -tupnw 2>/dev/null | grep ESTAB; }
}

collect_services() {
  h "Running services"
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    || service --status-all 2>/dev/null
  h "Enabled-at-boot services"
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null
  h "Failed units"
  systemctl --failed --no-pager --no-legend 2>/dev/null
}

collect_scheduled() {
  h "System crontab"; cat /etc/crontab 2>/dev/null
  h "cron.d / periodic directories"
  ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
  cat /etc/cron.d/* 2>/dev/null
  h "Per-user crontabs"
  for u in $(cut -f1 -d: /etc/passwd 2>/dev/null); do
    out="$(crontab -u "$u" -l 2>/dev/null)"
    [ -n "$out" ] && { echo "### $u"; echo "$out"; }
  done
  h "systemd timers"; systemctl list-timers --all --no-pager --no-legend 2>/dev/null
  h "at jobs"; atq 2>/dev/null
  h "rc.local"; cat /etc/rc.local 2>/dev/null
}

collect_permissions() {
  h "SUID binaries";  tmo find / -xdev -perm -4000 -type f | head -"$CAP"
  h "SGID binaries";  tmo find / -xdev -perm -2000 -type f | head -"$CAP"
  h "World-writable files"; tmo find / -xdev -type f -perm -0002 | head -"$CAP"
  h "World-writable directories without sticky bit"; tmo find / -xdev -type d -perm -0002 ! -perm -1000 | head -50
  h "Files with no owner (nouser/nogroup)"; tmo find / -xdev \( -nouser -o -nogroup \) | head -50
}

collect_ssh() {
  h "sshd_config (effective lines)"
  grep -Ev '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null
  h "authorized_keys per user"
  for home in /root /home/*; do
    [ -f "$home/.ssh/authorized_keys" ] && { echo "### $home"; cat "$home/.ssh/authorized_keys" 2>/dev/null; }
  done
}

collect_firewall() {
  h "iptables rules"; iptables -S 2>/dev/null
  h "Ruleset nftables"; nft list ruleset 2>/dev/null
  h "ufw status"; ufw status verbose 2>/dev/null
  h "firewalld"; firewall-cmd --list-all 2>/dev/null
}

collect_persistence() {
  h "ld.so.preload (should be empty or absent)"; cat /etc/ld.so.preload 2>/dev/null
  h "Scripts init.d"; ls -la /etc/init.d 2>/dev/null
  h "Scripts profile.d"; ls -la /etc/profile.d 2>/dev/null
  h "System systemd units"; ls -la /etc/systemd/system 2>/dev/null
  h "Shell rc files (mtime)"
  for home in /root /home/*; do
    ls -la "$home/.bashrc" "$home/.bash_profile" "$home/.profile" 2>/dev/null
  done
  h "System binaries modified (<7 days)"
  tmo find /usr/bin /usr/sbin /bin /sbin -mtime -7 -type f | head -50
}

# ---- collect everything ----
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
        --data-binary @- && echo && echo "[+] sent" || echo "[!] send failed"
    elif command -v wget >/dev/null 2>&1; then
      printf '%s' "$payload" | wget -q -O- --header="Content-Type: application/json" \
        --header="X-Auth-Token: $AUTH_TOKEN" --post-data="$payload" "$SERVER_URL" \
        && echo "[+] sent (wget)" || echo "[!] send failed"
    else
      echo "[!] curl or wget is required; use 'local' mode and send the JSON manually"
    fi
    ;;
  *)
    echo "usage: $0 {text|local|send}"; exit 1;;
esac
