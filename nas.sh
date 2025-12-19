#!/usr/bin/env bash
# file: tools/install-samba.sh
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

ENABLE_GUEST="$(ask_yn "Enable guest share" n)"
ENABLE_SHARED="$(ask_yn "Enable shared share" y)"
ENABLE_PUBLIC="$(ask_yn "Enable public share" y)"
ENABLE_HOMES="$(ask_yn "Enable homes" y)"

ENABLE_RECYCLE="$(ask_yn "Enable recycle bin" y)"
ENABLE_RECYCLE_SHARE=n
[ "$ENABLE_RECYCLE" = y ] && ENABLE_RECYCLE_SHARE="$(ask_yn "Expose recycle share" y)"

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
cat <<EOF
[global]
  workgroup = $WORKGROUP
  server string = $SERVERSTR
  server role = standalone server

  security = user
  passdb backend = tdbsam
  map to guest = Bad User

  access based share enum = yes
  hide unreadable = yes
  hide dot files = yes

  # Modern protocol/auth defaults
  server min protocol = SMB2
  client min protocol = SMB2
  ntlm auth = ntlmv2-only
  server signing = default
  smb encrypt = desired

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
[ "$ENABLE_GUEST" = n ] && echo "  restrict anonymous = 2"

cat <<'EOF'
### END GLOBAL VFS ###
EOF

write_share_block guest "$ENABLE_GUEST" <<EOF
[Guest]
  path = $BASE/guest
  browseable = yes
  guest ok = yes
  read only = yes
  write list = @$GROUP_PUBLIC @$GROUP_ADMIN
  create mask = 0664
  directory mask = 2775
EOF

# Traditional shared: all authenticated users in nas_user
write_share_block shared "$ENABLE_SHARED" <<EOF
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

write_share_block public "$ENABLE_PUBLIC" <<EOF
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

# Override vfs objects to prevent recycle recursion
write_share_block recycle "$ENABLE_RECYCLE_SHARE" <<EOF
[Recycle Bin]
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

  cat > /usr/local/sbin/nas-recycle-cleanup <<'EOF_CLEAN'
#!/usr/bin/env bash
set -euo pipefail
DAYS="$(cat /etc/samba/nas-recycle-days 2>/dev/null || echo 30)"
RECYCLE_BASE="/srv/samba/.recycle"
[ -d "$RECYCLE_BASE" ] || exit 0

# Remove old files
find "$RECYCLE_BASE" -type f -mtime "+$DAYS" -print -delete 2>/dev/null || true
# Remove empty dirs (depth-first) — fixed var; avoid undefined $RECYCLE
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

  # Allow loopback
  ufw allow in on lo >/dev/null 2>&1 || true

  # Add rules for each allowed subnet
  for net in $ALLOWED_SUBNETS; do
    if [ "$ENABLE_NETBIOS" = y ]; then
      # Full Samba when NetBIOS is enabled
      ufw allow from "$net" to any app Samba >/dev/null 2>&1 || {
        ufw allow from "$net" to any port 137,138 proto udp || true
        ufw allow from "$net" to any port 139,445 proto tcp || true
      }
    else
      # SMB over TCP only (445)
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
### nasctl - Mini-NAS Management CLI (preserved)
### ===============================
cat > /usr/local/sbin/nasctl <<'EOF_NASCTL'
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/samba/smb.conf"
BKDIR="/var/backups/samba"
RECYCLE="/srv/samba/.recycle"
DAYS="/etc/samba/nas-recycle-days"
GROUP_ADMIN="nas_admin"
GROUP_USER="nas_user"
GROUP_PUBLIC="nas_public"

die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "${EUID:-0}" -eq 0 ] || die "Run as root"; }

valid_name(){ [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
valid_share(){ [[ "${1:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }

reload(){ testparm -s >/dev/null; systemctl restart smbd 2>/dev/null || systemctl restart smbd; }

start_line(){ echo "### START SHARE $1 ###"; }
end_line(){ echo "### END SHARE $1 ###"; }

toggle_block(){
  local name="$1" mode="$2" s e
  s="$(start_line "$name")"
  e="$(end_line "$name")"

  awk -v s="$s" -v e="$e" -v m="$mode" '
    $0==s {print; inside=1; next}
    $0==e {inside=0; print; next}
    inside==1 {
      if(m=="disable"){
        if($0 ~ /^;/) print
        else print "; " $0
        next
      }
      if(m=="enable"){
        sub(/^;[ ]?/, "", $0)
        print
        next
      }
    }
    {print}
  ' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
}

share_exists(){
  grep -Fxq "$(start_line "$1")" "$CONF" && grep -Fxq "$(end_line "$1")" "$CONF"
}

share_list(){
  awk '
    /^### START SHARE / {
      name=$4
      sub(/ ###$/, "", name)
      inside=1
      state="disabled"
      next
    }
    /^### END SHARE / {
      printf "%-16s %s\n", name, state
      inside=0
      next
    }
    inside==1 && /^\[/ {
      state="enabled"
    }
  ' "$CONF"
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
  nasctl share create <name> <path> <valid_users> <write_list>

Recycle:
  nasctl recycle flush
  nasctl recycle days <N>
  nasctl recycle timer on|off
EOF
}

need_root
cmd="${1:-}"; shift || true

case "$cmd" in
  user)
    sub="${1:-}"; shift || true
    case "$sub" in
      add)
        u="${1:-}"; [ -n "$u" ] || die "user add <name>"
        valid_name "$u" || die "Invalid username"
        id "$u" >/dev/null 2>&1 || useradd -m -d "/srv/samba/homes/$u" -s /usr/sbin/nologin "$u"
        usermod -aG "$GROUP_USER" "$u"
        mkdir -p "/srv/samba/homes/$u"
        chown "$u:$u" "/srv/samba/homes/$u" || true
        chmod 0700 "/srv/samba/homes/$u" || true
        echo "Set Samba password for $u:"
        smbpasswd -a "$u"; smbpasswd -e "$u"
        ;;
      del)
        u="${1:-}"; [ -n "$u" ] || die "user del <name>"
        valid_name "$u" || die "Invalid username"
        purge=n; [ "${2:-}" = "--purge-home" ] && purge=y
        smbpasswd -x "$u" 2>/dev/null || true
        [ "$purge" = y ] && userdel -r "$u" 2>/dev/null || userdel "$u" 2>/dev/null || true
        ;;
      passwd)
        u="${1:-}"; [ -n "$u" ] || die "user passwd <name>"
        valid_name "$u" || die "Invalid username"
        smbpasswd "$u"
        ;;
      *) usage; exit 1;;
    esac
    ;;

  group)
    sub="${1:-}"; shift || true
    case "$sub" in
      create)
        g="${1:-}"; [ -n "$g" ] || die "group create <group>"
        valid_name "$g" || die "Invalid group name"
        getent group "$g" >/dev/null && die "Group already exists: $g"
        groupadd "$g"
        ;;
      adduser)
        g="${1:-}"; u="${2:-}"
        [ -n "$g" ] && [ -n "$u" ] || die "group adduser <group> <user>"
        valid_name "$g" && valid_name "$u" || die "Invalid name"
        getent group "$g" >/dev/null || die "Group does not exist: $g"
        usermod -aG "$g" "$u"
        ;;
      deluser)
        g="${1:-}"; u="${2:-}"
        [ -n "$g" ] && [ -n "$u" ] || die "group deluser <group> <user>"
        gpasswd -d "$u" "$g"
        ;;
      list)
        u="${1:-}"; [ -n "$u" ] || die "group list <user>"
        id "$u"
        ;;
      *) usage; exit 1;;
    esac
    ;;

  conf)
    sub="${1:-}"; shift || true
    mkdir -p "$BKDIR"
    case "$sub" in
      backup)
        ts="$(date +%F_%H%M%S)"
        tar -czf "$BKDIR/samba-$ts.tgz" /etc/samba/smb.conf /etc/samba/nas-recycle-days \
          /etc/systemd/system/nas-recycle-cleanup.* /usr/local/sbin/nas-recycle-cleanup 2>/dev/null || true
        echo "Saved: $BKDIR/samba-$ts.tgz"
        ;;
      list) ls -1 "$BKDIR" 2>/dev/null || true ;;
      restore)
        f="${1:-}"; [ -n "$f" ] || die "conf restore <file.tgz>"
        tar -xzf "$f" -C /
        systemctl daemon-reload 2>/dev/null || true
        reload
        ;;
      *) usage; exit 1;;
    esac
    ;;

  share)
    sub="${1:-}"; shift || true
    case "$sub" in
      list) share_list ;;
      enable)
        n="${1:-}"; [ -n "$n" ] || die "share enable <name>"
        share_exists "$n" || die "Share not found: $n"
        toggle_block "$n" enable
        reload
        ;;
      disable)
        n="${1:-}"; [ -n "$n" ] || die "share disable <name>"
        share_exists "$n" || die "Share not found: $n"
        toggle_block "$n" disable
        reload
        ;;
      create)
        name="${1:-}"
        path="${2:-}"
        valid_users="${3:-}"
        write_list="${4:-}"

        [ -n "$name" ] && [ -n "$path" ] && [ -n "$valid_users" ] \
          || die "share create <name> <path> <valid_users> <write_list>"

        valid_share "$name" || die "Invalid share name"

        grp="$(echo "$write_list" | awk '{print $1}' | sed 's/^@//')"
        [ -n "$grp" ] || die "write_list must include at least one @group"
        getent group "$grp" >/dev/null || die "Group does not exist: $grp"

        mkdir -p "$path"
        chown root:"$grp" "$path"
        chmod 2770 "$path"

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
        } >> "$CONF"

        reload
        ;;
      *) usage; exit 1;;
    esac
    ;;

  recycle)
    sub="${1:-}"; shift || true
    case "$sub" in
      flush)
        [ -d "$RECYCLE" ] || exit 0
        find "$RECYCLE" -type f -delete 2>/dev/null || true
        find "$RECYCLE" -mindepth 2 -type d -empty -delete 2>/dev/null || true
        ;;
      days)
        n="${1:-}"; [[ "$n" =~ ^[0-9]+$ ]] || die "recycle days <N>"
        echo "$n" > "$DAYS"
        ;;
      timer)
        v="${1:-}"; [ -n "$v" ] || die "recycle timer on|off"
        if [ "$v" = "on" ]; then systemctl enable --now nas-recycle-cleanup.timer
        else systemctl disable --now nas-recycle-cleanup.timer
        fi
        ;;
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
