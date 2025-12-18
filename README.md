# Mini NAS Setup
A miniature LXC NAS system tested on unprivileged `Debian 12` container using `Proxmox VE 9.1.2`. Designed for homelabs and small trusted environments.

---
<img width="1919" height="307" alt="image" src="https://github.com/user-attachments/assets/95f93d0d-91ec-4144-8862-d63758c14d38" />
<p align="center">
  <img src="https://github.com/user-attachments/assets/f9d7c14b-e48b-49ce-9024-c1915a918824" width="400"/>
  <img src="https://github.com/user-attachments/assets/0c0f6b88-25d2-4e50-a471-7bbe57957e05" width="400" />
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/296e72bd-10f3-4bf8-b346-81a39451b7a1" width="800" />
</p>

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
  - [Permissions](#permissions)
  - [Roles](#roles)
  - [Features](#features)
  - [Limitations](#limitations)
- [Installation](#installation)
  - [Follow Steps](#Follow-Steps)
  - [Manage](#Manage)

## How Access Works

### Permissions
- **Homes**: private.
- **Shared** (Optional): everyone can read/write/delete.
- **Public** (Optional): everyone read; only `nas_public` + `nas_admin` can write.
- **Guest** (optional): read-only for guests, writable by `nas_admin`.

### Roles
- `nas_user` = Standard users; read access to all public shares, write access limited to their own home directory.
- `nas_admin` = Full administrative access; read, write, and modify all shares and user directories.
- `nas_public` = Users granted write permissions specifically for the Public share.

### Features
- Works with privileged and unprivileged LXC containers.
- Creates a complete mini NAS structure with Homes, optional Shared, Public, and Guest shares.
- Create custom groups & shares easily.
- Per-user recycle bins.
- Automated user, group, and Samba account management.

### Limitations
- Samba authentication is local-only (no AD/LDAP).
- Samba admins are effectively trusted users.
- No brute force mitigation, must install fail2ban.
- Must configure your firewalls manually.
- Changes are script-driven.

## Installation
> NOTE: **AS ROOT ON THE HOST NODE, NOT IN CONTAINER**
```bash
# Setup Script
wget -O nas https://raw.githubusercontent.com/cfunkz/Proxmox-LXC-SMB/main/nas.sh
chmod +x nas

# Run setup script
./nas
```

### Follow Steps
> NOTE: Install by following the steps
<img width="931" height="633" alt="image" src="https://github.com/user-attachments/assets/a3dc9289-4621-4952-a36d-ae8d36f9987f" />

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
nasctl group adduser nas_media test2
```

**3. Create the share**
```bash
# If for "nas_media" only
nasctl share create Media /srv/samba/media "@nas_media @nas_admin" "@nas_media @nas_admin"

# If for all users
nasctl share create Media /srv/samba/media "@nas_user @nas_admin" "@nas_user @nas_admin"
```
