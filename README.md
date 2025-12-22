# Mini Samba NAS Setup
A miniature NAS system tested on unprivileged `Debian 12` container using `Proxmox VE 9.1.2`. Designed for homelabs and small trusted environments.

---
<img width="1919" height="355" alt="image" src="https://github.com/user-attachments/assets/170fdb8a-8a81-48a6-80e2-6870dc579210" />

> ⚠️ Disclaimer  
> Built as a personal project and learning exercise, I'm no expert!
> Worked well for my use case, has been tested enough to be useful, but not enough for me to claim it won't cause a headache.
> Use at your own risk.

## TODO
- ~~Management Script~~
- ~~Recycle bin clean-up service~~
- Basic Web Panel
- Quota Management

## Table of Contents
- [How Access Works](#how-access-works)
  - [Default Share Permissions](#default-share-permissions)
  - [Roles](#roles)
  - [Features](#features)
  - [Limitations](#limitations)
- [Installation](#installation)
  - [Follow Steps](#Follow-Steps)
  - [Manage](#Manage)

## How Access Works

### Default Share Permissions
- **Homes**: private to each user.
- **Shared** (Optional): `nas_user` can read/write/delete.
- **Public** (Optional): `nas_user` read; only `nas_public` + `nas_admin` can write.
- **Guest** (Optional): read-only for guests, writable by `nas_public` + `nas_admin`.

### Roles
- `nas_user` = Standard users; read access to all enabled shares, write access limited to their own home directory.
- `nas_admin` = Full administrative access; read, write, and modify all shares and user directories.
- `nas_public` = Users granted write permissions specifically for the Public share.

### Features
- Works within Proxmox containers.
- Creates a complete mini NAS structure with Homes, optional Shared, Public, and Guest shares.
- Create custom groups & shares easily.
- Per-user recycle bins if enabled.
- Automated user, group, and Samba account management.
- Automated UFW firewall if enabled.
- Optional NetBios support if enabled.

### Limitations
- Samba authentication is local-only (no AD/LDAP).
- Windows ACLs not fully supported.
- No brute force mitigation, must install fail2ban.
- Changes are made via `nasctl` commands.
- The backup only saves `/etc/samba/smb.conf` contents.

## Installation
```bash
# Setup Script
wget -O nas https://raw.githubusercontent.com/cfunkz/Mini-NAS/main/nas.sh
chmod +x nas

# Run setup script
./nas
```

### Follow Steps
> NOTE: Install by following the steps
<img width="800" height="630" alt="image" src="https://github.com/user-attachments/assets/4ded3c86-fb0a-4d9f-9c84-d15dc559c112" />

### Manage
> NOTE: Post-install management
```py
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
  nasctl share delete <name> [--purge-share]

Recycle:
  nasctl recycle flush
  nasctl recycle days <N>
  nasctl recycle timer on|off
```

To create a new `"Media"` share follow the steps:

**1. Create a custom user group if needed (Optional)**
```bash
 nasctl group create nas_media
```

**2. Add wanted users to the group**
```bash
nasctl group adduser nas_media nasuser
```

**3. Create the share**
```bash
# If for "nas_media" only
nasctl share create Media /srv/samba/media "@nas_media" "@nas_media"

# If for all users
nasctl share create Media /srv/samba/media "@nas_user @nas_admin" "@nas_user @nas_admin"
```

**Auto-appends to:** `/etc/samba/smb.conf`

<img width="387" height="270" alt="image" src="https://github.com/user-attachments/assets/3889dd10-bb76-403e-9199-72f7583df638" />
