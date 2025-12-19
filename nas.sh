#!/usr/bin/env bash
set -euo pipefail

### ===============================
### Globals
### ===============================
BASE="/srv/samba"
CONF="/etc/samba/smb.conf"
RECYCLE="$BASE/.recycle"
DAYS_FILE="/etc/samba/nas-recycle-days"

GROUP_ADMIN="nas_admin"
GROUP_USER="nas_user"
GROUP_PUBLIC="nas_public"

die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "${EUID:-0}" -eq 0 ] || die "Run as root"; }

ask(){ local v; read -r -p "$1 [$2]: " v || true; echo "${v:-$2}"; }
ask_yn(){
  local v
  while true; do
    read -r -p "$1 (y/n) [$2]: " v || true
    v="${v:-$2}"
    case "$v" in y|Y) echo y; return;; n|N) echo n; return;; esac
  done
}

valid_name(){ [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
valid_share(){ [[ "${1:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }

mark_s(){ echo "### START SHARE $1 ###"; }
mark_e(){ echo "### END SHARE $1 ###"; }

# Writes a share block to stdout. If disabled, comments every line inside.
write_share_block(){
  local name="$1" enabled="$2"
  mark_s "$name"
  if [ "$enabled" = y ]; then
    cat
  else
    sed 's/^/; /'
  fi
  mark_e "$name"
}

need_root
umask 022

### ===============================
### Packages Install
### ===============================
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y samba

### ===============================
### User Groups
### ===============================
for g in "$GROUP_ADMIN" "$GROUP_USER" "$GROUP_PUBLIC"; do
  getent group "$g" >/dev/null || groupadd "$g"
done

### ===============================
### Install Questions
### ===============================
WORKGROUP="$(ask "Workgroup" "WORKGROUP")"
SERVERSTR="$(ask "Server description" "Mini NAS")"
ALLOWED_SUBNETS="$(ask "Allowed subnets (space-separated CIDRs)" "127.0.0.1/32 192.168.0.0/16")"

ENABLE_GUEST="$(ask_yn "Enable Guest share" n)"
ENABLE_SHARED="$(ask_yn "Enable Shared share" y)"
ENABLE_PUBLIC="$(ask_yn "Enable Public share" y)"
ENABLE_HOMES="$(ask_yn "Enable Homes" y)"

ENABLE_RECYCLE="$(ask_yn "Enable Recycle bin" y)"
ENABLE_RECYCLE_SHARE=n
[ "$ENABLE_RECYCLE" = y ] && ENABLE_RECYCLE_SHARE="$(ask_yn "Expose Recycle share" y)"
ENABLE_NETBIOS="$(ask_yn "Enable NetBIOS (nmbd, ports 137-139)" n)"
CONFIGURE_UFW="$(ask_yn "Configure UFW firewall rules now" y)"
if [ "$CONFIGURE_UFW" = y ]; then
  UFW_ENABLE_IF_DISABLED="$(ask_yn "Enable UFW if currently disabled" n)"
fi

ADMIN_USER="$(ask "Initial admin username" nasadmin)"
valid_name "$ADMIN_USER" || die "Invalid admin username"

### ===============================
### Permissioned directories
### ===============================
install -d -m 0755 "$BASE"
install -d -m 2770 -o root -g "$GROUP_USER"   "$BASE/shared"
install -d -m 2770 -o root -g "$GROUP_PUBLIC" "$BASE/public"
install -d -m 2775 -o root -g "$GROUP_PUBLIC" "$BASE/guest"
install -d -m 0711 "$BASE/homes"

[ "$ENABLE_RECYCLE" = y ] && install -d -m 0700 -o root -g root "$RECYCLE"

### ===============================
### Initial admin user
### ===============================
if ! id "$ADMIN_USER" &>/dev/null; then
  useradd -m -d "$BASE/homes/$ADMIN_USER" -s /usr/sbin/nologin "$ADMIN_USER"
fi
usermod -aG "$GROUP_ADMIN,$GROUP_USER" "$ADMIN_USER"

mkdir -p "$BASE/homes/$ADMIN_USER"
chown "$ADMIN_USER:$ADMIN_USER" "$BASE/homes/$ADMIN_USER" || true
chmod 0700 "$BASE/homes/$ADMIN_USER" || true

echo "Set Samba password for $ADMIN_USER:"
smbpasswd -a "$ADMIN_USER"
smbpasswd -e "$ADMIN_USER"

### ===============================
### Samba Config (/etc/samba/smb.conf)
### ===============================
tmp_conf="$(mktemp)"
trap 'rm -f "$tmp_conf"' EXIT

{
# unquoted heredoc: expand variables here (intended)
cat <<EOF
[global]
  workgroup = $WORKGROUP
  server string = $SERVERSTR
  server role = standalone server

  security = user
  passdb backend = tdbsam
  map to guest = $([ "$ENABLE_GUEST" = y ] && echo "Bad User" || echo "never")

  access based share enum = yes
  hide unreadable = yes
  hide dot files = yes

  # Modern protocol/auth defaults
  server min protocol = SMB2
  client min protocol = SMB2
  ntlm auth = ntlmv2-only
  server signing = default
  smb encrypt = desired
EOF

# Only when guest disabled
[ "$ENABLE_GUEST" = n ] && echo "  restrict anonymous = 2"

cat <<EOF

  # Network scoping
  hosts allow = $ALLOWED_SUBNETS
  hosts deny  = 0.0.0.0/0 ::/0
  bind interfaces only = no

  # NetBIOS toggle (nmbd service managed below)
  disable netbios = $([ "$ENABLE_NETBIOS" = y ] && echo no || echo yes)

  # Admins
  admin users = @$GROUP_ADMIN

  # Logging
  log file = /var/log/samba/log.%m
  max log size = 1000
  log level = 1

  # Printing off
  load printers = no
  disable spoolss = yes

### START GLOBAL VFS ###
EOF

if [ "$ENABLE_RECYCLE" = y ]; then
cat <<EOF
  vfs objects = acl_xattr recycle
  map acl inherit = yes
  store dos attributes = yes

  recycle:repository = $RECYCLE/%U
  recycle:directory_mode = 0700
  recycle:subdir_mode = 0700
  recycle:keeptree = yes
  recycle:versions = yes
  recycle:touch = yes
  recycle:exclude = *.tmp *.temp ~$*
EOF
else
cat <<EOF
  vfs objects = acl_xattr
  map acl inherit = yes
  store dos attributes = yes
EOF
fi

# quoted heredoc: keep literal text inside
cat <<'EOF'
### END GLOBAL VFS ###
EOF

write_share_block Guest "$ENABLE_GUEST" <<EOF
[Guest]
  path = $BASE/guest
  browseable = yes
  guest ok = yes
  read only = yes
  write list = @$GROUP_PUBLIC @$GROUP_ADMIN
  create mask = 0664
  directory mask = 2775
EOF

write_share_block Shared "$ENABLE_SHARED" <<EOF
[Shared]
  path = $BASE/shared
  browseable = yes
  guest ok = no
  read only = no
  valid users = @$GROUP_USER @$GROUP_ADMIN
  force group = $GROUP_USER
  inherit permissions = yes
  create mask = 0660
  directory mask = 2770
EOF

write_share_block Public "$ENABLE_PUBLIC" <<EOF
[Public]
  path = $BASE/public
  browseable = yes
  read only = yes
  valid users = @$GROUP_USER @$GROUP_PUBLIC @$GROUP_ADMIN
  write list  = @$GROUP_PUBLIC @$GROUP_ADMIN
  force group = $GROUP_PUBLIC
  inherit permissions = yes
  create mask = 0660
  directory mask = 2770
EOF

# quoted heredoc so %H and %S remain literals for Samba
write_share_block homes "$ENABLE_HOMES" <<'EOF'
[homes]
  path = %H
  browseable = no
  read only = no
  guest ok = no
  valid users = %S
  create mask = 0600
  directory mask = 0700
EOF

write_share_block Recycle "$ENABLE_RECYCLE_SHARE" <<EOF
[Recycle]
  path = $RECYCLE/%U
  browseable = yes
  read only = no
  valid users = @$GROUP_USER @$GROUP_PUBLIC @$GROUP_ADMIN
  hide unreadable = yes
  vfs objects = acl_xattr
  create mask = 0600
  directory mask = 0700
EOF

} > "$tmp_conf"

testparm -s "$tmp_conf" >/dev/null

# Backup existing config if present, then replace atomically
if [ -f "$CONF" ]; then
  install -d -m 0755 /var/backups/samba
  cp -a "$CONF" "/var/backups/samba/smb.conf.$(date +%F_%H%M%S)"
fi
install -m 0644 "$tmp_conf" "$CONF"

### ===============================
### Recycle cleanup
### ===============================
if [ "$ENABLE_RECYCLE" = y ]; then
  echo 30 > "$DAYS_FILE"

  # quoted heredoc: keep variables literal inside the script body
  cat > /usr/local/sbin/nas-recycle-cleanup <<'EOF_CLEAN'
#!/usr/bin/env bash
set -euo pipefail
DAYS="$(cat /etc/samba/nas-recycle-days 2>/dev/null || echo 30)"
RECYCLE_BASE="/srv/samba/.recycle"
[ -d "$RECYCLE_BASE" ] || exit 0

find "$RECYCLE_BASE" -type f -mtime "+$DAYS" -print -delete 2>/dev/null || true
find "$RECYCLE_BASE" -mindepth 2 -type d -empty -mtime "+$DAYS" -delete
EOF_CLEAN
  chmod 0755 /usr/local/sbin/nas-recycle-cleanup

  cat > /etc/systemd/system/nas-recycle-cleanup.service <<'EOF_SVC'
[Unit]
Description=Cleanup Samba Recycle Bin

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nas-recycle-cleanup
EOF_SVC

  cat > /etc/systemd/system/nas-recycle-cleanup.timer <<'EOF_TIMER'
[Unit]
Description=Daily cleanup of Samba Recycle Bin

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF_TIMER

  systemctl daemon-reload
  systemctl enable --now nas-recycle-cleanup.timer
fi

### ===============================
### Firewall (UFW) — optional
### ===============================
if [ "$CONFIGURE_UFW" = y ]; then
  if ! command -v ufw >/dev/null 2>&1; then
    apt-get install -y ufw
  fi

  ufw allow in on lo >/dev/null 2>&1 || true

  for net in $ALLOWED_SUBNETS; do
    if [ "$ENABLE_NETBIOS" = y ]; then
      ufw allow from "$net" to any app Samba >/dev/null 2>&1 || {
        ufw allow from "$net" to any port 137,138 proto udp || true
        ufw allow from "$net" to any port 139,445 proto tcp || true
      }
    else
      ufw allow from "$net" to any port 445 proto tcp || true
    fi
  done

  status="$(ufw status | head -n1 || true)"
  if [[ "$status" =~ "inactive" ]] && [ "$UFW_ENABLE_IF_DISABLED" = y ]; then
    ufw --force enable
  fi
fi

### ===============================
### Samba start (smbd/nmbd based on NetBIOS question)
### ===============================
systemctl enable --now smbd
if systemctl list-unit-files | grep -q '^nmbd.service'; then
  if [ "$ENABLE_NETBIOS" = y ]; then
    systemctl enable --now nmbd
  else
    systemctl disable --now nmbd || true
  fi
fi
systemctl restart smbd

### ===============================
### nasctl - Mini-NAS Management CLI
### ===============================
cat > /usr/local/sbin/nasctl <<'EOF_NASCTL'
#!/usr/bin/env bash
set -euo pipefail

# ---- Consts ----
CONF="/etc/samba/smb.conf"
BKDIR="/var/backups/samba"
RECYCLE="/srv/samba/.recycle"
DAYS="/etc/samba/nas-recycle-days"
BASE="/srv/samba"
GROUP_ADMIN="nas_admin"
GROUP_USER="nas_user"
GROUP_PUBLIC="nas_public"

# ---- Utils ----
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "${EUID:-0}" -eq 0 ] || die "Run as root"; }
valid_name(){ [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
valid_share(){ [[ "${1:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }

reload(){
  testparm -s >/dev/null
  systemctl restart smbd || die "failed to restart smbd"
  systemctl is-active --quiet nmbd 2>/dev/null && systemctl restart nmbd || true
}

start_line(){ echo "### START SHARE $1 ###"; }
end_line(){ echo "### END SHARE $1 ###"; }

share_exists(){
  grep -Fxq "$(start_line "$1")" "$CONF" && grep -Fxq "$(end_line "$1")" "$CONF"
}

share_list(){
  awk '
    /^### START SHARE / { name=$4; sub(/ ###$/, "", name); inside=1; state="disabled"; next }
    /^### END SHARE /   { printf "%-16s %s\n", name, state; inside=0; next }
    inside==1 && /^\[/ { state="enabled" }
  ' "$CONF"
}

toggle_block(){ # enable|disable by commenting inner lines
  local name="$1" mode="$2" s e
  s="$(start_line "$name")"; e="$(end_line "$name")"
  awk -v s="$s" -v e="$e" -v m="$mode" '
    $0==s {print; inside=1; next}
    $0==e {inside=0; print; next}
    inside==1 {
      if(m=="disable"){ if($0 ~ /^;/) print; else print "; " $0; next }
      if(m=="enable"){ sub(/^;[ ]?/,"",$0); print; next }
    }
    {print}
  ' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
}

remove_block(){ # delete marked block
  local name="$1" s e
  s="$(start_line "$name")"; e="$(end_line "$name")"
  grep -Fxq "$s" "$CONF" && grep -Fxq "$e" "$CONF" || die "Share not found: $name"
  awk -v s="$s" -v e="$e" '
    $0==s {inside=1; next}
    $0==e {inside=0; next}
    inside!=1 {print}
  ' "$CONF" > "$CONF.tmp"
  testparm -s "$CONF.tmp" >/dev/null || { rm -f "$CONF.tmp"; die "Resulting config invalid"; }
  mv "$CONF.tmp" "$CONF"
}

get_share_path(){ # extract "path = ..." inside block
  local name="$1" s e
  s="$(start_line "$name")"; e="$(end_line "$name")"
  awk -v s="$s" -v e="$e" '
    $0==s {inside=1; next}
    $0==e {inside=0; next}
    inside==1 && $0 ~ /^[[:space:]]*path[[:space:]]*=/ {
      gsub(/^[[:space:]]*path[[:space:]]*=[[:space:]]*/,"")
      gsub(/[[:space:]]+$/,"")
      print; exit
    }
  ' "$CONF"
}

safe_purge_dir(){ # only under $BASE, never $BASE or /
  local dir="$1"
  [ -n "$dir" ] || die "Empty directory path"
  [ -d "$dir" ] || { echo "Note: not found, nothing to purge: $dir"; return 0; }
  local real; real="$(readlink -f -- "$dir" 2>/dev/null || true)"
  [ -n "$real" ] || die "Cannot resolve: $dir"
  [[ "$real" == "$BASE"* ]] || die "Refusing to purge outside $BASE: $real"
  [ "$real" != "$BASE" ] || die "Refusing to purge BASE itself"
  [ "$real" != "/" ] || die "Refusing to purge /"
  rm -rf -- "$real"
}

append_share_block(){ # tmp file build + validate
  local name="$1" path="$2" valid_users="$3" write_list="$4"
  local tmp; tmp="$(mktemp)"; cp "$CONF" "$tmp"
  {
    echo ""
    echo "### START SHARE $name ###"
    echo "[$name]"
    echo "  path = $path"
    echo "  browseable = yes"
    echo "  read only = no"
    echo "  valid users = $valid_users"
    echo "  write list  = $write_list"
    echo "  inherit permissions = yes"
    echo "  create mask = 0660"
    echo "  directory mask = 2770"
    echo "### END SHARE $name ###"
  } >> "$tmp"
  testparm -s "$tmp" >/dev/null || { rm -f "$tmp"; die "Generated config invalid"; }
  mv "$tmp" "$CONF"
}

validate_acl_tokens(){ # allow @group or user; groups must exist
  local list="$1" t
  for t in $list; do
    if [[ "$t" =~ ^@(.+)$ ]]; then getent group "${BASH_REMATCH[1]}" >/dev/null || die "No such group: $t"
    else id "$t" >/dev/null 2>&1 || true
    fi
  done
}

usage(){
  cat <<'EOF'
nasctl

Users:
  nasctl user add <name>
  nasctl user del <name> [--purge-home]
  nasctl user passwd <name>

Groups:
  nasctl group create <group>
  nasctl group adduser <group> <user>
  nasctl group deluser <group> <user>
  nasctl group list <user>

Config:
  nasctl conf backup
  nasctl conf list
  nasctl conf restore <file.tgz>

Shares:
  nasctl share list
  nasctl share enable  <name>
  nasctl share disable <name>
  nasctl share create  <name> <path> <valid_users> <write_list>
  nasctl share delete  <name> [--purge-share]

Recycle:
  nasctl recycle flush
  nasctl recycle days <N>
  nasctl recycle timer on|off
EOF
}

# ---- CLI ----
need_root
cmd="${1:-}"; shift || true

case "$cmd" in
  user)
    sub="${1:-}"; shift || true
    case "$sub" in
      add)
        u="${1:-}"; [ -n "$u" ] || die "user add <name>"; valid_name "$u" || die "Invalid username"
        id "$u" >/dev/null 2>&1 || useradd -m -d "$BASE/homes/$u" -s /usr/sbin/nologin "$u"
        usermod -aG "$GROUP_USER" "$u"
        mkdir -p "$BASE/homes/$u"; chown "$u:$u" "$BASE/homes/$u" || true; chmod 0700 "$BASE/homes/$u" || true
        echo "Set Samba password for $u:"; smbpasswd -a "$u"; smbpasswd -e "$u"
        ;;
      del)
        u="${1:-}"; [ -n "$u" ] || die "user del <name>"; valid_name "$u" || die "Invalid username"
        purge=n; [ "${2:-}" = "--purge-home" ] && purge=y
        smbpasswd -x "$u" 2>/dev/null || true
        [ "$purge" = y ] && userdel -r "$u" 2>/dev/null || userdel "$u" 2>/dev/null || true
        ;;
      passwd)
        u="${1:-}"; [ -n "$u" ] || die "user passwd <name>"; valid_name "$u" || die "Invalid username"
        smbpasswd "$u"
        ;;
      *) usage; exit 1;;
    esac
    ;;
  group)
    sub="${1:-}"; shift || true
    case "$sub" in
      create) g="${1:-}"; [ -n "$g" ] || die "group create <group>"; valid_name "$g" || die "Invalid group"; getent group "$g" >/dev/null && die "Exists"; groupadd "$g" ;;
      adduser) g="${1:-}"; u="${2:-}"; [ -n "$g" ] && [ -n "$u" ] || die "group adduser <group> <user>"; valid_name "$g" && valid_name "$u" || die "Invalid"; getent group "$g" >/dev/null || die "No such group"; usermod -aG "$g" "$u" ;;
      deluser) g="${1:-}"; u="${2:-}"; [ -n "$g" ] && [ -n "$u" ] || die "group deluser <group> <user>"; gpasswd -d "$u" "$g" ;;
      list) u="${1:-}"; [ -n "$u" ] || die "group list <user>"; id "$u" ;;
      *) usage; exit 1;;
    esac
    ;;
  conf)
    sub="${1:-}"; shift || true; mkdir -p "$BKDIR"
    case "$sub" in
      backup) ts="$(date +%F_%H%M%S)"; tar -czf "$BKDIR/samba-$ts.tgz" "$CONF" "$DAYS" /etc/systemd/system/nas-recycle-cleanup.* /usr/local/sbin/nas-recycle-cleanup 2>/dev/null || true; echo "Saved: $BKDIR/samba-$ts.tgz" ;;
      list)   ls -1 "$BKDIR" 2>/dev/null || true ;;
      restore) f="${1:-}"; [ -n "$f" ] || die "conf restore <file.tgz>"; tar -xzf "$f" -C /; systemctl daemon-reload 2>/dev/null || true; reload ;;
      *) usage; exit 1;;
    esac
    ;;
  share)
    sub="${1:-}"; shift || true
    case "$sub" in
      list) share_list ;;
      enable)  n="${1:-}"; [ -n "$n" ] || die "share enable <name>"; share_exists "$n" || die "Not found"; toggle_block "$n" enable;  reload ;;
      disable) n="${1:-}"; [ -n "$n" ] || die "share disable <name>"; share_exists "$n" || die "Not found"; toggle_block "$n" disable; reload ;;
      create)
        name="${1:-}"; path="${2:-}"; valid_users="${3:-}"; write_list="${4:-}"
        [ -n "$name" ] && [ -n "$path" ] && [ -n "$valid_users" ] && [ -n "$write_list" ] || die "share create <name> <path> <valid_users> <write_list>"
        valid_share "$name" || die "Invalid share name"
        grep -Fxq "### START SHARE $name ###" "$CONF" && die "Share exists: $name"

        owner_tok="$(awk '{print $1}' <<<"$write_list")"
        [[ "$owner_tok" =~ ^@([A-Za-z0-9._-]+)$ ]] || die "write_list must start with @group (owner)"
        owner_grp="${BASH_REMATCH[1]}"; getent group "$owner_grp" >/dev/null || die "No such group: $owner_grp"

        validate_acl_tokens "$valid_users"; validate_acl_tokens "$write_list"

        mkdir -p "$path"; chown root:"$owner_grp" "$path"; chmod 2770 "$path"
        append_share_block "$name" "$path" "$valid_users" "$write_list"
        reload
        ;;
      delete)
        n="${1:-}"; [ -n "$n" ] || die "share delete <name> [--purge-share]"
        purge="${2:-}"
        share_exists "$n" || die "Not found: $n"
        share_path="$(get_share_path "$n")"; [ -n "$share_path" ] || die "Cannot detect path for $n"
        remove_block "$n"; reload
        [ "$purge" = "--purge-share" ] && { echo "Purging $share_path"; safe_purge_dir "$share_path"; }
        ;;
      *) usage; exit 1;;
    esac
    ;;
  recycle)
    sub="${1:-}"; shift || true
    case "$sub" in
      flush) [ -d "$RECYCLE" ] || exit 0; find "$RECYCLE" -type f -delete 2>/dev/null || true; find "$RECYCLE" -mindepth 2 -type d -empty -delete 2>/dev/null || true ;;
      days)  n="${1:-}"; [[ "$n" =~ ^[0-9]+$ ]] || die "recycle days <N>"; echo "$n" > "$DAYS" ;;
      timer) v="${1:-}"; [ -n "$v" ] || die "recycle timer on|off"; if [ "$v" = "on" ]; then systemctl enable --now nas-recycle-cleanup.timer; else systemctl disable --now nas-recycle-cleanup.timer; fi ;;
      *) usage; exit 1;;
    esac
    ;;
  *) usage; exit 1;;
esac
EOF_NASCTL

chmod +x /usr/local/sbin/nasctl

echo "== DONE =="
echo "Config: $CONF"
echo "Base path: $BASE"
echo "CLI: nasctl"
echo "NetBIOS: $([ "$ENABLE_NETBIOS" = y ] && echo enabled || echo disabled)"
if [ "$CONFIGURE_UFW" = y ]; then
  echo "UFW configured for: $ALLOWED_SUBNETS (ports: $([ "$ENABLE_NETBIOS" = y ] && echo '137/udp,138/udp,139/tcp,445/tcp' || echo '445/tcp'))"
fi
