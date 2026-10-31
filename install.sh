#!/usr/bin/env bash
# =============================================================================
# Mini-NAS: turn a plain Linux VM into a simple Samba NAS.
#
# Works on: Debian 12/13, Ubuntu 22.04+, Rocky / Alma / RHEL 9+ (and Fedora).
# Made for Proxmox VMs/LXCs, but works on any VM or VPS.
#
# What you get:
#   - One shared folder  \\nas\shared  (everyone in group "nas" can read/write)
#   - A private folder per user  \\nas\<username>
#   - Optional: put the data on a second (blank) disk, formatted ext4
#   - Optional: a tiny read-only web page showing disk space (port 8080)
#   - The "nas" command to add/remove users and check status
#
# SECURITY: this is built for a trusted LOCAL network (home / homelab).
#   By default Samba only accepts private LAN addresses (10.x, 172.16-31.x,
#   192.168.x). Do NOT expose SMB (port 445) or the status page to the
#   internet. If you need remote access, use a VPN (WireGuard, Tailscale)
#   and keep this NAS on the private side of it.
#
# Usage:  sudo bash install.sh
#
# Unattended install: set any of these before running, plus NAS_YES=1
#   NAS_DIR=/srv/nas            where data lives (mount point if NAS_DISK set)
#   NAS_DISK=/dev/sdb           blank disk to format + mount (optional)
#   NAS_FORMAT=yes              required to actually format NAS_DISK unattended
#   NAS_USER=alice              first user (password asked, or NAS_PASS)
#   NAS_ALLOW="192.168.1.0/24"  who may connect (space separated)
#   NAS_IFACE="ens19"           only listen on these NICs (blank = all)
#   NAS_WEB=yes|no              disk-space web page on port 8080
# =============================================================================
set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"

# Ask a question unless NAS_YES=1 or there is no terminal; then use default.
ask() {
  local q="$1" def="$2" ans=""
  if [ "${NAS_YES:-0}" != 1 ] && [ -t 0 ]; then
    read -r -p "$q [$def]: " ans || true
  fi
  echo "${ans:-$def}"
}

# ---------------------------------------------------------------- distro ----
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) FAMILY=debian; SMB_SVC=smbd; NMB_SVC=nmbd ;;
  *" rhel "*|*" fedora "*|*" centos "*) FAMILY=rhel; SMB_SVC=smb; NMB_SVC=nmb ;;
  *) die "unsupported distro: ${PRETTY_NAME:-unknown} (need Debian/Ubuntu or RHEL-like)" ;;
esac
info "Detected ${PRETTY_NAME:-$ID} ($FAMILY)"

# --------------------------------------------------------------- answers ----
DIR="${NAS_DIR:-$(ask "Data folder" /srv/nas)}"
DIR="${DIR%/}"
[[ "$DIR" == /* && "$DIR" != / ]] || die "data folder must be an absolute path, not /"

# Offer blank disks (no partitions, no filesystem, not mounted).
if [ -z "${NAS_DISK+x}" ]; then
  blank=$(lsblk -dpno NAME,TYPE | awk '$2=="disk"{print $1}' | while read -r d; do
    [ "$(lsblk -no NAME "$d" | wc -l)" -eq 1 ] && [ -z "$(blkid -o value -s TYPE "$d")" ] && echo "$d"
  done || true)
  if [ -n "$blank" ]; then
    echo "Blank disks found (add one in Proxmox: VM > Hardware > Add > Hard Disk):"
    for d in $blank; do echo "   $d  $(lsblk -dno SIZE "$d")"; done
  fi
  NAS_DISK="$(ask "Disk to use for data (blank = keep data on system disk)" "")"
fi
USER1="${NAS_USER:-$(ask "First NAS user" nas)}"
ALLOW="${NAS_ALLOW:-$(ask "Allowed networks" "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16")}"
IFACE="${NAS_IFACE-$(ask "Listen only on NIC(s), e.g. ens19 (blank = all)" "")}"
WEB="${NAS_WEB:-$(ask "Show disk space on a web page, port 8080 (yes/no)" yes)}"

[[ "$USER1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "bad username: $USER1"

# -------------------------------------------------------------- packages ----
info "Installing packages"
if [ "$FAMILY" = debian ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq samba python3 >/dev/null
  # Lets Windows 10/11 see the NAS under "Network" (optional, best effort)
  apt-get install -y -qq wsdd-server >/dev/null 2>&1 || apt-get install -y -qq wsdd >/dev/null 2>&1 || true
else
  dnf install -y -q samba python3 policycoreutils-python-utils
fi

# ------------------------------------------------------------ data disk -----
if [ -n "${NAS_DISK:-}" ]; then
  [ -b "$NAS_DISK" ] || die "$NAS_DISK is not a block device"
  fstype="$(blkid -o value -s TYPE "$NAS_DISK" || true)"
  if [ -z "$fstype" ]; then
    [ "$(lsblk -no NAME "$NAS_DISK" | wc -l)" -eq 1 ] || die "$NAS_DISK has partitions, refusing to touch it"
    [ "${NAS_FORMAT:-}" = yes ] || NAS_FORMAT="$(ask "ERASE $NAS_DISK and format ext4? type yes" no)"
    [ "$NAS_FORMAT" = yes ] || die "not formatting $NAS_DISK"
    info "Formatting $NAS_DISK as ext4"
    # Whole disk, no partition table: growing the disk in Proxmox later only
    # needs "resize2fs $NAS_DISK". -m 0: no reserved root blocks on a data disk.
    mkfs.ext4 -q -m 0 -L nasdata "$NAS_DISK"
    fstype=ext4
  else
    case "$fstype" in ext4|xfs|btrfs) ;; *) die "$NAS_DISK contains $fstype, refusing to touch it" ;; esac
    info "$NAS_DISK already has $fstype, reusing it (no format)"
  fi
  uuid="$(blkid -s UUID -o value "$NAS_DISK")"
  mkdir -p "$DIR"
  if ! grep -q "UUID=$uuid" /etc/fstab; then
    # nofail: the VM still boots if the disk is missing
    echo "UUID=$uuid $DIR $fstype defaults,noatime,nofail 0 2" >> /etc/fstab
  fi
  systemctl daemon-reload
  mountpoint -q "$DIR" || mount "$DIR"
fi

# Free unused blocks back to thin storage (Proxmox ZFS / LVM-thin). Enable
# "Discard" on the VM disk in Proxmox for this to have an effect.
systemctl enable --now fstrim.timer >/dev/null 2>&1 || true

# ------------------------------------------------------- folders + users ----
info "Creating folders in $DIR"
getent group nas >/dev/null || groupadd nas
install -d -m 0755 "$DIR"
install -d -m 2770 -o root -g nas "$DIR/shared"   # setgid: new files stay group nas
install -d -m 0751 "$DIR/homes"

# Shared settings for the "nas" helper command installed below.
cat > /etc/mini-nas.conf <<EOF
NAS_DIR="$DIR"
SMB_SVC="$SMB_SVC"
EOF

# SELinux (Rocky/Alma): allow Samba to serve the data folder.
if command -v selinuxenabled >/dev/null && selinuxenabled; then
  info "Setting SELinux labels"
  semanage fcontext -a -t samba_share_t "$DIR(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t samba_share_t "$DIR(/.*)?"
  restorecon -R "$DIR"
fi

# --------------------------------------------------------------- smb.conf ---
info "Writing /etc/samba/smb.conf"
[ -f /etc/samba/smb.conf ] && cp -a /etc/samba/smb.conf "/etc/samba/smb.conf.bak.$(date +%s)"

if [ -n "$IFACE" ]; then
  LISTEN="  interfaces = lo $IFACE
  bind interfaces only = yes"
else
  LISTEN="  # listening on all NICs; set 'interfaces = lo ens19' + 'bind interfaces only = yes' to restrict"
fi

cat > /etc/samba/smb.conf <<EOF
# Mini-NAS Samba config. Edit freely, then: testparm && systemctl restart $SMB_SVC
#
# LAN ONLY. Do not port-forward 445 to the internet; use a VPN instead.

[global]
  server string = Mini NAS
  workgroup = WORKGROUP
  server role = standalone server
  passdb backend = tdbsam

  # Who may connect. Keep this to your LAN / VPN ranges.
  hosts allow = 127.0.0.1 ::1 $ALLOW
  hosts deny = ALL
$LISTEN

  # Security: no guests, no anonymous, SMB2+ only, encryption when client supports it.
  map to guest = never
  restrict anonymous = 2
  server min protocol = SMB2_10
  smb encrypt = desired
  disable netbios = yes
  smb ports = 445

  # Speed / macOS friendliness
  use sendfile = yes
  vfs objects = catia fruit streams_xattr
  fruit:metadata = stream
  fruit:posix_rename = yes
  fruit:veto_appledouble = no
  fruit:wipe_intentionally_left_blank_rfork = yes
  fruit:delete_empty_adfiles = yes

  load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes

  log file = /var/log/samba/log.%m
  max log size = 1000
  log level = 1

# Everyone in group "nas" can read and write.
[shared]
  path = $DIR/shared
  valid users = @nas
  read only = no
  force group = nas
  create mask = 0660
  directory mask = 2770

# Private folder per user, shows up as \\\\nas\\<username>
[homes]
  path = $DIR/homes/%S
  valid users = %S
  read only = no
  browseable = no
  create mask = 0600
  directory mask = 0700

# Add your own share like this (and create the folder with group nas, mode 2770):
# [media]
#   path = $DIR/media
#   valid users = @nas
#   read only = no
#   force group = nas
#   create mask = 0660
#   directory mask = 2770
EOF
testparm -s /etc/samba/smb.conf >/dev/null 2>&1 || die "smb.conf invalid, run: testparm"

# ------------------------------------------------------------- "nas" CLI ----
info "Installing the 'nas' command"
cat > /usr/local/sbin/nas <<'EOF'
#!/usr/bin/env bash
# Mini-NAS helper. Run "nas" for help.
set -euo pipefail
. /etc/mini-nas.conf
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

valid() { [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "bad username: ${1:-}" >&2; exit 1; }; }

case "${1:-} ${2:-}" in
  "user add")
    u="${3:-}"; valid "$u"
    # System account without shell or SSH login; it only exists for file ownership.
    id "$u" >/dev/null 2>&1 || useradd -M -d "$NAS_DIR/homes/$u" -s /usr/sbin/nologin -G nas "$u"
    usermod -aG nas "$u"
    install -d -m 0700 -o "$u" -g "$u" "$NAS_DIR/homes/$u"
    command -v restorecon >/dev/null && restorecon -R "$NAS_DIR/homes/$u" 2>/dev/null || true
    if [ -n "${NAS_PASS:-}" ]; then
      printf '%s\n%s\n' "$NAS_PASS" "$NAS_PASS" | smbpasswd -s -a "$u" >/dev/null
    else
      echo "Set password for $u:"; smbpasswd -a "$u" >/dev/null
    fi
    smbpasswd -e "$u" >/dev/null
    echo "User $u ready. Files: \\\\$(hostname)\\shared and \\\\$(hostname)\\$u"
    ;;
  "user del")
    u="${3:-}"; valid "$u"
    smbpasswd -x "$u" >/dev/null 2>&1 || true
    userdel "$u" 2>/dev/null || true
    echo "Removed $u. Their files are kept in $NAS_DIR/homes/$u (delete by hand if wanted)."
    ;;
  "user passwd") valid "${3:-}"; smbpasswd "$3" ;;
  "user list")   pdbedit -L | cut -d: -f1 ;;
  "status "*)
    echo "== Disk"; df -h "$NAS_DIR" | sed 1d | awk '{print "  "$6": "$4" free of "$2" ("$5" used)"}'
    echo "== Service"; echo "  $SMB_SVC: $(systemctl is-active "$SMB_SVC")"
    echo "== Addresses"; hostname -I | tr ' ' '\n' | sed '/^$/d; s/^/  /'
    echo "== Connected"; smbstatus -b 2>/dev/null | sed -n '5,$p' | sed 's/^/  /'
    ;;
  *)
    cat <<USAGE
nas user add <name>      add a user (asks for password)
nas user del <name>      remove a user (keeps their files)
nas user passwd <name>   change a password
nas user list            list users
nas status               free space, service, IPs, who is connected
USAGE
    ;;
esac
EOF
chmod 0755 /usr/local/sbin/nas

# ------------------------------------------------- disk space web page ------
if [ "$WEB" = yes ]; then
  info "Installing disk space page on port 8080"
  cat > /usr/local/lib/nas-web.py <<'EOF'
#!/usr/bin/env python3
# Read-only disk space page for Mini-NAS. No login, no writes, LAN clients only.
# Do NOT expose this to the internet.
import html, ipaddress, os, shutil, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIR = os.environ.get("NAS_DIR", "/srv/nas")

def gb(n): return f"{n / 1024**3:,.1f} GB"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        ip = ipaddress.ip_address(self.client_address[0])
        if not (ip.is_private or ip.is_loopback):
            self.send_error(403); return
        if self.path != "/":
            self.send_error(404); return
        u = shutil.disk_usage(DIR)
        pct = round(u.used * 100 / u.total) if u.total else 0
        color = "#c0392b" if pct >= 90 else "#e67e22" if pct >= 75 else "#27ae60"
        body = f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=60>
<meta name=viewport content="width=device-width">
<title>{html.escape(socket.gethostname())} NAS</title>
<body style="font:16px system-ui;max-width:32em;margin:3em auto;padding:0 1em">
<h2>{html.escape(socket.gethostname())}</h2>
<p><b>{gb(u.free)}</b> free of {gb(u.total)}</p>
<div style="background:#ddd;border-radius:6px"><div style="background:{color};width:{pct}%;
height:22px;border-radius:6px"></div></div>
<p style="color:#666">{pct}% used &middot; {html.escape(DIR)}<br>
Connect: <code>\\\\{html.escape(socket.gethostname())}\\shared</code> or <code>smb://{html.escape(socket.gethostname())}/shared</code></p>"""
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a): pass

ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("NAS_WEB_PORT", "8080"))), H).serve_forever()
EOF
  cat > /etc/systemd/system/nas-web.service <<EOF
[Unit]
Description=Mini-NAS disk space page
After=network.target

[Service]
Environment=NAS_DIR=$DIR
ExecStart=/usr/bin/python3 /usr/local/lib/nas-web.py
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now nas-web >/dev/null 2>&1
  systemctl restart nas-web
else
  systemctl disable --now nas-web >/dev/null 2>&1 || true
fi

# -------------------------------------------------------------- firewall ----
# Only touched if a firewall is already active. We never turn one on for you
# (that could lock you out of SSH).
ports="445"; [ "$WEB" = yes ] && ports="445 8080"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  info "Opening $ports in ufw for $ALLOW"
  for net in $ALLOW; do for p in $ports; do ufw allow from "$net" to any port "$p" proto tcp >/dev/null; done; done
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  info "Opening $ports in firewalld for $ALLOW"
  for net in $ALLOW; do
    fam=ipv4; [[ "$net" == *:* ]] && fam=ipv6
    for p in $ports; do
      firewall-cmd -q --permanent --add-rich-rule="rule family=$fam source address=$net port port=$p protocol=tcp accept" || true
    done
  done
  firewall-cmd -q --reload
fi

# --------------------------------------------------------------- services ---
systemctl disable --now "$NMB_SVC" >/dev/null 2>&1 || true   # NetBIOS not needed
systemctl enable "$SMB_SVC" >/dev/null 2>&1
systemctl restart "$SMB_SVC"
for w in wsdd-server wsdd; do systemctl enable --now "$w" >/dev/null 2>&1 || true; done

# ----------------------------------------------------------- first user -----
if pdbedit -L 2>/dev/null | cut -d: -f1 | grep -qx "$USER1"; then
  info "User $USER1 already exists, skipping"
else
  /usr/local/sbin/nas user add "$USER1"
fi

IP="$(hostname -I | awk '{print $1}')"
cat <<EOF

Done! Your NAS is ready.

  Windows:  \\\\$IP\\shared        (log in as $USER1)
  macOS:    smb://$IP/shared
  Linux:    smb://$IP/shared
$([ "$WEB" = yes ] && echo "  Space:    http://$IP:8080")

  Add users:  nas user add bob
  Status:     nas status
  Config:     /etc/samba/smb.conf

Reminder: LAN use only. Don't forward port 445 or 8080 to the internet.
EOF
