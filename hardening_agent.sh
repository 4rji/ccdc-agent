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
#   HARDEN_FIND_TIMEOUT=25         # per-find timeout (seconds)
#   HARDEN_DEEP=1                  # also run package integrity verification (slow)
#   HARDEN_DEEP_TIMEOUT=120        # timeout for the deep integrity pass
#
# Run as root for full coverage (shadow status, all crontabs, all
# authorized_keys, other users' /proc). Password hashes are NOT exported,
# only their status and algorithm family.

set -uo pipefail

SERVER_URL="${HARDEN_SERVER:-http://127.0.0.1:8000/report}"
AUTH_TOKEN="${HARDEN_TOKEN:-ccdcagent2026}"
MODE="${1:-send}"
FIND_TIMEOUT="${HARDEN_FIND_TIMEOUT:-25}"
DEEP="${HARDEN_DEEP:-0}"
DEEP_TIMEOUT="${HARDEN_DEEP_TIMEOUT:-120}"
AGENT_VERSION="1.1"
CAP=200

b64()      { printf '%s' "${1:-}" | base64 | tr -d '\n'; }
jesc()     { printf '"%s"' "$(printf '%s' "${1:-}" | tr '\n\t' '  ' | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
h()        { printf '\n## %s\n' "$1"; }                 # sub-header inside a section
tmo()      { timeout "$FIND_TIMEOUT" "$@" 2>/dev/null || true; }
tmo_deep() { timeout "$DEEP_TIMEOUT" "$@" 2>/dev/null || true; }

# Print up to $CAP lines from stdin, then note how many were dropped. Truncation
# used to be silent (head -N), which hid the fact that data was cut.
capped() {
  local n=0 line
  while IFS= read -r line; do
    n=$((n+1))
    [ "$n" -le "$CAP" ] && printf '%s\n' "$line"
  done
  [ "$n" -gt "$CAP" ] && printf '... [truncated: %s total, showing first %s]\n' "$n" "$CAP"
}

# Real, local block-backed filesystems only. The old code used `find / -xdev`,
# which silently skipped anything on a separate mount (e.g. a split /home, /usr,
# /var) and so missed SUID/world-writable files living there.
local_mounts() {
  if command -v findmnt >/dev/null 2>&1; then
    findmnt -rno TARGET,FSTYPE 2>/dev/null | awk '
      $2 !~ /^(proc|sysfs|tmpfs|devtmpfs|devpts|cgroup2?|nfs4?|cifs|smb3|fuse\..*|autofs|squashfs|ramfs|mqueue|debugfs|tracefs|securityfs|pstore|bpf|configfs|hugetlbfs|binfmt_misc|rpc_pipefs|efivarfs)$/ {print $1}'
  else
    echo /
  fi
}

# Run `find <local mounts> -xdev <args>`, deduplicated. Covers every local
# filesystem without descending into network mounts.
scan_find() {
  local_mounts | while IFS= read -r m; do
    [ -n "$m" ] && tmo find "$m" -xdev "$@"
  done | sort -u
}

collect_system() {
  h "Kernel / arch";     uname -a 2>/dev/null
  h "OS release";        cat /etc/os-release 2>/dev/null
  h "Virtualization";    systemd-detect-virt 2>/dev/null; systemd-detect-virt --container 2>/dev/null
  h "Uptime / load";     uptime 2>/dev/null
  h "Last boot";         who -b 2>/dev/null
  h "Current identity";  id 2>/dev/null
  h "Security-relevant sysctl (expected hardened values noted)"
  for kv in kernel.randomize_va_space net.ipv4.ip_forward \
            net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects \
            net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route \
            net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_redirects \
            kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope; do
    v="$(sysctl -n "$kv" 2>/dev/null)"; [ -n "$v" ] && printf '%s = %s\n' "$kv" "$v"
  done
  h "Loaded kernel modules"; lsmod 2>/dev/null | head -"$CAP"
}

collect_users() {
  h "Accounts (name uid gid shell)"
  awk -F: '{print $1, "uid="$3, "gid="$4, "shell="$7}' /etc/passwd 2>/dev/null
  h "UID 0 accounts (should be ONLY root)"
  awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
  h "Login-capable accounts (real shell, not nologin/false)"
  awk -F: '
    $7=="" { print $1" -> (empty shell field = defaults to /bin/sh)"; next }
    $7 !~ /(nologin|false|true|sync|halt|shutdown)$/ { print $1" -> "$7 }
  ' /etc/passwd 2>/dev/null
  h "Password status (hashes NOT exported; algorithm family shown)"
  if [ -r /etc/shadow ]; then
    awk -F: '{
      s=$2
      if (s=="")                       st="EMPTY! (login with NO password)"
      else if (s=="*")                 st="no-password (cannot auth via password)"
      else if (s=="!" || s=="!!")      st="locked (no hash)"
      else if (s ~ /^[!*]/)            st="locked (hash present but disabled)"
      else                             st="password set"
      alg=""
      if (s ~ /\$1\$/)       alg=" [MD5 - WEAK]"
      else if (s ~ /\$2/)    alg=" [bcrypt]"
      else if (s ~ /\$5\$/)  alg=" [SHA-256]"
      else if (s ~ /\$6\$/)  alg=" [SHA-512]"
      else if (s ~ /\$y\$/)  alg=" [yescrypt]"
      else if (s ~ /\$gy\$/) alg=" [gost-yescrypt]"
      print $1": "st alg
    }' /etc/shadow 2>/dev/null
  else
    echo "(root is required to read /etc/shadow)"
  fi
  h "Sudoers (effective lines, with source file)"
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] && grep -Ev '^\s*#|^\s*$' "$f" 2>/dev/null | sed "s|^|$f: |"
  done
  h "Privileged group members"
  # sudo/wheel/admin = admin rights; docker/lxd/lxc = trivial root escape on host;
  # adm = log read; kvm/libvirt = VM control. All worth auditing.
  getent group sudo wheel admin adm 2>/dev/null
  getent group docker lxd lxc kvm libvirt 2>/dev/null
  h "Recent successful logins"; last -Faiw -n 15 2>/dev/null || last -n 15 2>/dev/null
  h "Recent FAILED logins";     lastb -Faiw -n 15 2>/dev/null || lastb -n 15 2>/dev/null
}

collect_processes() {
  h "Full process list"
  ps auxww 2>/dev/null
  h "Suspicious executables (running from writable paths, or deleted on disk)"
  # Resolve the REAL executable per PID via /proc/PID/exe instead of grepping the
  # argv line. Grepping argv gave false positives (any process merely mentioning
  # /tmp/ matched) and missed the actual on-disk location.
  for e in /proc/[0-9]*/exe; do
    tgt="$(readlink "$e" 2>/dev/null)" || continue
    flag=""
    case "$tgt" in
      /tmp/*|/dev/shm/*|/var/tmp/*|/run/user/*|/home/*) flag="WRITABLE-PATH" ;;
    esac
    case "$tgt" in
      *"(deleted)") flag="${flag:+$flag,}DELETED" ;;
    esac
    [ -n "$flag" ] || continue
    pid="${e#/proc/}"; pid="${pid%/exe}"
    printf '[%s] pid=%s exe=%s cmd=%s\n' "$flag" "$pid" "$tgt" \
      "$(tr '\0' ' ' </proc/"$pid"/cmdline 2>/dev/null)"
  done
  h "Shell / tunnel / reverse-shell tooling currently running"
  ps auxww 2>/dev/null | grep -v -E 'grep|hardening_agent' \
    | grep -E '\b(nc|ncat|socat|telnet)\b|/dev/tcp/|bash -i|sh -i|(python|perl|ruby|php)[0-9.]* .*(socket|pty|fsockopen|TCPSocket)|meterpreter|msfconsole|\b(chisel|ligolo|frpc|frps|gost)\b'
}

collect_network() {
  h "Listening sockets (tcp/udp/raw, with process)"
  ss -tulpnw 2>/dev/null || netstat -tulpnw 2>/dev/null
  h "Established connections (with process)"
  ss -tupnw state established 2>/dev/null || { netstat -tupnw 2>/dev/null | grep ESTAB; }
  h "Unix domain sockets (listening) - can hide local backdoors"
  ss -xlp 2>/dev/null | head -"$CAP"
  h "Routing table"; ip route 2>/dev/null || route -n 2>/dev/null
  h "ARP / neighbor cache"; ip neigh 2>/dev/null || arp -an 2>/dev/null
  h "DNS resolvers"; cat /etc/resolv.conf 2>/dev/null
  h "/etc/hosts (watch for hijacked update/mirror hosts)"
  grep -Ev '^\s*#|^\s*$' /etc/hosts 2>/dev/null
}

collect_services() {
  h "Running services"
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    || service --status-all 2>/dev/null
  h "Enabled-at-boot services"
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null
  h "Masked services"
  systemctl list-unit-files --type=service --state=masked --no-pager --no-legend 2>/dev/null
  h "Socket-activated units (spawn services on demand - persistence vector)"
  systemctl list-units --type=socket --state=running --no-pager --no-legend 2>/dev/null
  h "Failed units"
  systemctl --failed --no-pager --no-legend 2>/dev/null
}

collect_scheduled() {
  h "System crontab"; cat /etc/crontab 2>/dev/null
  h "cron.d entries (contents)"
  for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f" 2>/dev/null; }; done
  h "Periodic cron directories (listing + mtimes)"
  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    echo "### $d"; ls -la "$d" 2>/dev/null
  done
  h "Per-user crontabs (crontab -l; root needed for other users)"
  while IFS=: read -r u _; do
    out="$(crontab -u "$u" -l 2>/dev/null)"
    [ -n "$out" ] && { echo "### $u"; echo "$out"; }
  done < /etc/passwd
  h "Raw cron spool (cross-check vs a tampered crontab binary)"
  for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] && { echo "### $f"; cat "$f" 2>/dev/null; }
  done
  h "cron / at allow-deny lists"
  for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [ -f "$f" ] && { echo "### $f"; cat "$f" 2>/dev/null; }
  done
  h "systemd timers"; systemctl list-timers --all --no-pager --no-legend 2>/dev/null
  h "at jobs"; atq 2>/dev/null
  h "rc.local"; cat /etc/rc.local 2>/dev/null
}

collect_permissions() {
  h "Local filesystems scanned"; local_mounts
  h "SUID binaries"
  scan_find -perm -4000 -type f | capped
  h "SGID binaries"
  scan_find -perm -2000 -type f | capped
  h "File capabilities (getcap) - cap_setuid/cap_dac_* etc. == privilege risk"
  # SUID bits are only half the story: a binary with cap_setuid+ep is as
  # dangerous as SUID-root but never appears in a -perm -4000 scan. The old
  # collector missed this entirely.
  if command -v getcap >/dev/null 2>&1; then
    local_mounts | while IFS= read -r m; do
      [ -n "$m" ] && tmo getcap -r "$m" 2>/dev/null
    done | sort -u | capped
  else
    echo "(getcap not available)"
  fi
  h "World-writable files"
  scan_find -type f -perm -0002 | capped
  h "World-writable directories WITHOUT sticky bit (dangerous)"
  scan_find -type d -perm -0002 ! -perm -1000 | capped
  h "Files with no valid owner (nouser/nogroup)"
  scan_find \( -nouser -o -nogroup \) | capped
}

collect_ssh() {
  h "Effective sshd configuration (sshd -T resolves Include drop-ins + defaults)"
  # sshd -T reports the ACTUAL running config (drop-ins from sshd_config.d and
  # built-in defaults merged in). Grepping only /etc/ssh/sshd_config missed both.
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -Ei \
      '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|challengeresponseauthentication|kbdinteractiveauthentication|usepam|x11forwarding|allowtcpforwarding|permittunnel|maxauthtries|logingracetime|allowusers|allowgroups|denyusers|denygroups|port|ciphers|macs|kexalgorithms) '
  else
    echo "(sshd binary not found; see raw config below)"
  fi
  h "Raw sshd_config + drop-ins (as written, with source file)"
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$f" ] && grep -Ev '^\s*#|^\s*$' "$f" 2>/dev/null | sed "s|^|$f: |"
  done
  h "authorized_keys per user (all home dirs from passwd, incl. legacy _keys2)"
  # Enumerate homes from passwd so service accounts with homes outside /home are
  # covered, and report file perms (a world-writable authorized_keys = backdoor).
  awk -F: '{print $1":"$6}' /etc/passwd 2>/dev/null | sort -u | while IFS=: read -r u home; do
    [ -n "$home" ] || continue
    for kf in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -f "$kf" ] || continue
      echo "### $u ($kf)  perms=$(stat -c '%a %U:%G' "$kf" 2>/dev/null)"
      cat "$kf" 2>/dev/null
    done
  done
  h "SSH host public keys present"
  ls -la /etc/ssh/ssh_host_*_key.pub 2>/dev/null
}

collect_firewall() {
  h "iptables (IPv4) rules + policies"; iptables -S 2>/dev/null; iptables -L -n -v 2>/dev/null | head -"$CAP"
  h "ip6tables (IPv6) rules - often forgotten, leaves v6 wide open"; ip6tables -S 2>/dev/null
  h "nftables ruleset"; nft list ruleset 2>/dev/null
  h "ufw status"; ufw status verbose 2>/dev/null
  h "firewalld"; firewall-cmd --state 2>/dev/null; firewall-cmd --list-all-zones 2>/dev/null | head -"$CAP"
}

collect_persistence() {
  h "ld.so.preload (should be empty/absent)"; cat /etc/ld.so.preload 2>/dev/null
  h "ld.so.conf.d entries"; ls -la /etc/ld.so.conf.d 2>/dev/null; cat /etc/ld.so.conf 2>/dev/null
  h "init.d scripts"; ls -la /etc/init.d 2>/dev/null
  h "profile.d scripts"; ls -la /etc/profile.d 2>/dev/null
  h "systemd unit dirs (/etc overrides /lib and /usr)"
  ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null | head -"$CAP"
  h "User systemd units (~/.config/systemd/user)"
  awk -F: '{print $6}' /etc/passwd 2>/dev/null | sort -u | while IFS= read -r home; do
    [ -d "$home/.config/systemd/user" ] && { echo "### $home"; ls -la "$home/.config/systemd/user" 2>/dev/null; }
  done
  h "Shell rc / profile files (mtime + perms)"
  awk -F: '{print $6}' /etc/passwd 2>/dev/null | sort -u | while IFS= read -r home; do
    [ -n "$home" ] && ls -la "$home/.bashrc" "$home/.bash_profile" "$home/.bash_login" \
                             "$home/.bash_logout" "$home/.profile" "$home/.zshrc" "$home/.zshenv" 2>/dev/null
  done
  h "Global shell init + /etc/environment (LD_PRELOAD injection vector)"
  ls -la /etc/profile /etc/bash.bashrc /etc/environment 2>/dev/null
  grep -Ev '^\s*#|^\s*$' /etc/environment 2>/dev/null
  h "PAM configuration (auth-stack edits are a classic backdoor)"; ls -la /etc/pam.d 2>/dev/null
  h "MOTD scripts (executed at login)"; ls -la /etc/update-motd.d 2>/dev/null
  h "System binaries modified in last 7 days (possible tampering)"
  tmo find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -mtime -7 -type f 2>/dev/null | sort -u | capped
}

collect_integrity() {
  h "Package manager file verification"
  if [ "$DEEP" != "1" ]; then
    echo "(skipped; set HARDEN_DEEP=1 to run rpm -Va / dpkg -V - slow, but detects tampered package files)"
    return
  fi
  if command -v rpm >/dev/null 2>&1; then
    echo "### rpm -Va (columns: S=size 5=md5 T=mtime U/G=owner M=mode c=config)"
    tmo_deep rpm -Va | capped
  elif command -v dpkg >/dev/null 2>&1; then
    echo "### dpkg -V (files whose checksum differs from package metadata)"
    tmo_deep dpkg -V | capped
  else
    echo "(no rpm/dpkg available)"
  fi
  if command -v debsums >/dev/null 2>&1; then
    echo "### debsums -c (changed files)"
    tmo_deep debsums -c | capped
  fi
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
CHECKS[integrity]="$(collect_integrity)"

ORDER=(system users processes network services scheduled permissions ssh firewall persistence integrity)
HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
WHO="$(id -un 2>/dev/null || echo unknown)"
EUID_NUM="$(id -u 2>/dev/null || echo -1)"
IS_ROOT=$([ "$EUID_NUM" = "0" ] && echo true || echo false)

build_json() {
  printf '{'
  printf '"agent_version":"%s",' "$AGENT_VERSION"
  printf '"hostname":%s,' "$(jesc "$HOST")"
  printf '"timestamp":"%s",' "$TS"
  printf '"collected_as":%s,' "$(jesc "$WHO")"
  printf '"is_root":%s,' "$IS_ROOT"
  printf '"checks":{'
  local first=1
  for k in "${ORDER[@]}"; do
    [ $first -eq 0 ] && printf ','
    first=0
    printf '"%s":"%s"' "$k" "$(b64 "${CHECKS[$k]:-}")"
  done
  printf '}}'
}

# Tell the operator when coverage is partial (many checks need root).
[ "$IS_ROOT" = "false" ] && \
  echo "[!] not root: /etc/shadow, other users' crontabs/keys, and some /proc data will be incomplete" >&2

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
    echo "[*] Host=$HOST as=$WHO root=$IS_ROOT bytes=${#payload} -> $SERVER_URL"
    if command -v curl >/dev/null 2>&1; then
      printf '%s' "$payload" | curl -sS --max-time 30 -X POST "$SERVER_URL" \
        -H "Content-Type: application/json" -H "X-Auth-Token: $AUTH_TOKEN" \
        --data-binary @- && echo && echo "[+] sent" || echo "[!] send failed"
    elif command -v wget >/dev/null 2>&1; then
      printf '%s' "$payload" | wget -q -O- --timeout=30 \
        --header="Content-Type: application/json" \
        --header="X-Auth-Token: $AUTH_TOKEN" --post-file=- "$SERVER_URL" \
        && echo "[+] sent (wget)" || echo "[!] send failed"
    else
      echo "[!] curl or wget is required; use 'local' mode and send the JSON manually"
    fi
    ;;
  *)
    echo "usage: $0 {text|local|send}"; exit 1;;
esac