# Mini-NAS

Turn any Linux VM into a simple file server (Samba / SMB) in one command.
Made for Proxmox, works on any VM or VPS.

Supported: **Debian 12/13, Ubuntu 22.04+, Rocky / Alma / RHEL 9+** (VM or LXC).

What you get:

- `\\nas\shared`: one folder everyone on the NAS can read and write
- `\\nas\<username>`: a private folder per user
- Optional: data on its own disk (e.g. a disk on your Proxmox ZFS pool)
- Optional: a small web page that shows how much space is left (`http://nas:8080`)
- The `nas` command to add users and check status

That's it. No web admin panel, no database, nothing to keep updated except your OS.

> **LAN only.** This is meant for a trusted home / homelab network. Samba only
> accepts private addresses (10.x, 172.16-31.x, 192.168.x) by default.
> **Do not port-forward 445 or 8080 to the internet**, and don't run this on a
> public VPS without a firewall. For remote access use a VPN
> (WireGuard, Tailscale, ...) and reach the NAS through it.

## Install

```bash
wget https://raw.githubusercontent.com/cfunkz/Mini-NAS/main/install.sh
sudo bash install.sh
```

It asks a few questions (just press Enter for the defaults):

| Question | Default | Notes |
|---|---|---|
| Data folder | `/srv/nas` | Where files are stored |
| Disk to use for data | none | A blank disk is formatted ext4 and mounted on the data folder. A disk that already has ext4/xfs/btrfs is reused, never formatted. |
| First NAS user | `nas` | You'll be asked for its password |
| Allowed networks | all private ranges | e.g. `192.168.1.0/24` to lock it to one LAN |
| Listen only on NIC(s) | all | e.g. `ens19` if the VM has a separate storage NIC |
| Disk space web page | yes | Read-only, no login, port 8080 |

Then connect from:

- **Windows:** `\\<ip>\shared` in Explorer, or *Map network drive* (free space shows in Explorer)
- **macOS:** Finder > Go > Connect to Server > `smb://<ip>/shared`
- **Linux:** `smb://<ip>/shared` in your file manager

Running the installer again is safe: it keeps your files, users and disk.

### Unattended

```bash
sudo NAS_YES=1 NAS_USER=alice NAS_PASS='change-me' \
     NAS_DISK=/dev/sdb NAS_FORMAT=yes NAS_ALLOW=192.168.1.0/24 bash install.sh
```

Variables: `NAS_DIR`, `NAS_DISK`, `NAS_FORMAT`, `NAS_USER`, `NAS_PASS`, `NAS_ALLOW`, `NAS_IFACE`, `NAS_WEB` (yes/no).

## Manage

```
nas user add <name>      add a user (asks for password)
nas user del <name>      remove a user (keeps their files)
nas user passwd <name>   change a password
nas user list            list users
nas status               free space, service, IPs, who is connected
```

NAS users can't log in over SSH, they only exist for file access.

**Want another share?** Edit `/etc/samba/smb.conf`, copy the commented `[media]`
example at the bottom, then:

```bash
sudo install -d -m 2770 -g nas /srv/nas/media
sudo testparm && sudo systemctl restart smbd   # "smb" on Rocky/Alma
```

## Proxmox tips

**Storage (VM).** Keep the OS disk small and add a second disk for data:
*VM > Hardware > Add > Hard Disk*, pick your ZFS (or LVM-thin) storage, tick
**Discard**. Then choose that disk (usually `/dev/sdb`) in the installer.

- The installer puts plain ext4 on it. Don't run ZFS inside the VM on top of
  host ZFS; let Proxmox do ZFS (snapshots, compression, scrubs).
- With Discard on, the weekly `fstrim` the installer enables gives deleted
  space back to the ZFS pool.
- Need more space? Resize the disk in Proxmox, then in the VM:
  `sudo resize2fs /dev/sdb`. No partitions to fiddle with.
- Free space shown by the NAS is the size of that virtual disk. If the ZFS pool
  is thin-provisioned and overcommitted, also watch the pool on the host
  (`zfs list`).

**Storage (LXC).** You can't format disks inside an unprivileged container. Add a
mount point instead (*CT > Resources > Add > Mount Point*, path `/srv/nas`) and
leave "Disk to use" blank in the installer.

**Multiple NICs.** If the VM has a second NIC on a storage bridge/VLAN, answer
e.g. `ens19` to "Listen only on NIC(s)" so Samba isn't reachable from the other
network. Check names with `ip -br a`.

## Security defaults

- Only private LAN ranges may connect (`hosts allow`), everything else is denied
- No guest or anonymous access
- SMB1 and NetBIOS off; SMB2.1+ only; encryption used when the client supports it
- Per-user folders are private (`0700`); shared folder is group `nas` only
- Web page is read-only, shows only free space, answers private IPs only,
  and runs as an unprivileged sandboxed systemd service
- If `ufw` or `firewalld` is already active, ports 445 (and 8080) are opened
  only for your allowed networks. The installer never switches a firewall on for
  you, so you can't get locked out of SSH.
- SELinux (Rocky/Alma) stays enforcing; the data folder gets the right label.

Turn off the web page any time: `sudo systemctl disable --now nas-web`.

## Files

| Path | What |
|---|---|
| `/etc/samba/smb.conf` | Samba config (old one backed up next to it) |
| `/etc/mini-nas.conf` | Data folder location for the `nas` command |
| `/usr/local/sbin/nas` | The `nas` command |
| `/usr/local/lib/nas-web.py` | Disk space page |

## License

See [LICENSE](LICENSE).
