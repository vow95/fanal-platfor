# Lab environment

The only place CybrX may scan during development (SECURITY.md, SBD-07).

## Network

| Item | Value |
|---|---|
| Hypervisor | VirtualBox |
| Lab network | Host-only, `192.168.56.0/24`, no route to the internet |
| Host machine (VirtualBox adapter) | `192.168.56.1` — **excluded from scans** |
| VirtualBox DHCP server | `192.168.56.100` — **excluded from scans** |

## Machines

| Machine | IP | Role | Notes |
|---|---|---|---|
| Kali | `192.168.56.103` | Scanner + Docker host | Adapter 1 NAT (updates), Adapter 2 host-only. `net.ipv4.ip_forward = 0` |
| Metasploitable 2 | `192.168.56.104` | Network target | Host-only only. Login `msfadmin` / `msfadmin` (lab only) |
| OWASP Juice Shop | `192.168.56.103:3000` | Web target (Docker on Kali) | `bkimminich/juice-shop`, bound to the host-only IP |
| DVWA | `192.168.56.103:8080` | Web target (Docker on Kali) | `vulnerables/web-dvwa`; run `/setup.php` once; login `admin` / `password` (lab only) |

Web targets are bound to the host-only IP, not `localhost`, because the scope guard always blocks loopback (SBD-02).

## Lab scope (used by tests and `cybrx scan`)

```
allow: 192.168.56.0/24
deny:  192.168.56.1, 192.168.56.100
```

## Baseline (Phase 0 gate, 2026-11-16)

`nmap -sV 192.168.56.104` (nmap 7.99) found 23 open TCP ports, including:
21 vsftpd 2.3.4 · 22 OpenSSH 4.7p1 · 23 telnetd · 80 Apache 2.2.8 · 139/445 Samba 3.x–4.x ·
1524 bindshell · 3306 MySQL 5.0.51a · 5432 PostgreSQL 8.3 · 5900 VNC · 6667 UnrealIRCd · 8180 Tomcat.
Phase 1 scans should find at least these.

## Snapshots

Take a snapshot of Kali and Metasploitable after Phase 0 passes (e.g. `clean-lab-2026-11-16`) and restore it if a scan breaks a target.
