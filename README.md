# IKB21403 Vulnerability Analysis — Chapter 5: Enumeration

**Target Machine:** Metasploitable 2  
**Target IP:** `192.168.56.104`  
**Attacker Machine:** Kali Linux  
**Date:** 10 June 2026  

---

## Table of Contents

1. [Challenge 2 — Fast Nmap Scan](#challenge-2--fast-nmap-scan)
2. [Challenge 16 — Version Detection](#challenge-16--version-detection)
3. [Challenge 1 — NetBIOS Enumeration](#challenge-1--netbios-enumeration)
4. [Challenge 9 — FTP Banner](#challenge-9--ftp-banner)
5. [Challenge 10 — Anonymous FTP Login](#challenge-10--anonymous-ftp-login)
6. [Challenge 5 — TTL OS Fingerprinting](#challenge-5--ttl-os-fingerprinting)
7. [Challenge 7 — SMTP VRFY / EXPN](#challenge-7--smtp-vrfy--expn)
8. [Challenge 11 — SMB NSE Enumeration](#challenge-11--smb-nse-enumeration)
9. [Challenge 12 — Enum4linux](#challenge-12--enum4linux)
10. [Challenge 13 — NFS Exports](#challenge-13--nfs-exports)
11. [Summary](#summary)

---

## Challenge 2 — Fast Nmap Scan

**Objective:** Quickly identify open ports on the target using a fast scan of the 100 most common ports.

**Command Used:**
```bash
nmap -F 192.168.56.104
```

**Screenshot:**

<img width="748" height="523" alt="1" src="https://github.com/user-attachments/assets/9a981f4a-bb61-4392-9978-01ba8ff6bcd0" />


**Output Analysis:**

| Port | State | Service |
|------|-------|---------|
| 21/tcp | open | ftp |
| 22/tcp | open | ssh |
| 23/tcp | open | telnet |
| 25/tcp | open | smtp |
| 53/tcp | open | domain |
| 80/tcp | open | http |
| 111/tcp | open | rpcbind |
| 139/tcp | open | netbios-ssn |
| 445/tcp | open | microsoft-ds |
| 513/tcp | open | login |
| 514/tcp | open | shell |
| 2049/tcp | open | nfs |
| 2121/tcp | open | ccproxy-ftp |
| 3306/tcp | open | mysql |
| 5432/tcp | open | postgresql |
| 5900/tcp | open | vnc |
| 6000/tcp | open | X11 |
| 8009/tcp | open | ajp13 |

**Findings:** 18 open ports were discovered out of the 100 most common ports scanned. The presence of services such as Telnet (port 23), FTP (port 21), and VNC (port 5900) indicates a highly insecure target with numerous potential attack vectors.

---

## Challenge 16 — Version Detection

**Objective:** Identify specific version numbers of services running on the target.

**Command Used:**
```bash
nmap -sV 192.168.56.104
```

**Screenshot:**

<img width="735" height="642" alt="2" src="https://github.com/user-attachments/assets/c8a5b1e3-2781-4585-ba00-29eb775703b0" />


**Output Analysis:**

| Port | Service | Version |
|------|---------|---------|
| 21/tcp | ftp | vsFTPd 2.3.4 |
| 22/tcp | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 |
| 23/tcp | telnet | Linux telnetd |
| 25/tcp | smtp | Postfix smtpd |
| 53/tcp | domain | ISC BIND 9.4.2 |
| 80/tcp | http | Apache httpd 2.2.8 (Ubuntu) DAV/2 |
| 111/tcp | rpcbind | 2 (RPC #100000) |
| 139/tcp | netbios-ssn | Samba smbd 3.X – 4.X |
| 445/tcp | netbios-ssn | Samba smbd 3.X – 4.X |
| 512/tcp | exec | netkit-rsh rexecd |
| 513/tcp | login | — |
| 514/tcp | shell | Netkit rshd |
| 1099/tcp | java-rmi | GNU Classpath grmiregistry |
| 1524/tcp | bindshell | Metasploitable root shell |
| 2049/tcp | nfs | 2–4 (RPC #100003) |
| 2121/tcp | ftp | ProFTPD 1.3.1 |
| 3306/tcp | mysql | MySQL 5.0.51a-3ubuntu5 |
| 5432/tcp | postgresql | PostgreSQL DB 8.3.0 – 8.3.7 |
| 5900/tcp | vnc | VNC (protocol 3.3) |
| 6000/tcp | X11 | (access denied) |
| 6667/tcp | irc | UnrealIRCd |
| 8009/tcp | ajp13 | Apache Jserv Protocol v1.3 |
| 8180/tcp | http | Apache Tomcat/Coyote JSP engine 1.1 |

**Findings:** Multiple outdated and vulnerable service versions were identified. Notable findings include:
- **vsFTPd 2.3.4** — known backdoor vulnerability (CVE-2011-2523)
- **UnrealIRCd** — known backdoor vulnerability (CVE-2010-2075)
- **Metasploitable root shell on port 1524** — a direct backdoor with root access
- **Telnet (port 23)** — transmits credentials in plaintext

---

## Challenge 1 — NetBIOS Enumeration

**Objective:** Enumerate NetBIOS information including machine name, workgroup, and MAC address.

**Command Used:**
```bash
nbtscan 192.168.56.104
```

**Screenshot:**

<img width="652" height="137" alt="3" src="https://github.com/user-attachments/assets/7d1b4044-73bf-4865-a23b-7f8da374b785" />


**Output Analysis:**

| IP Address | NetBIOS Name | Server | User | MAC Address |
|------------|-------------|--------|------|-------------|
| 192.168.56.104 | METASPLOITABLE | `<server>` | METASPLOITABLE | 00:00:00:00:00:00 |

**Findings:** NetBIOS enumeration successfully revealed the machine hostname as `METASPLOITABLE` and confirmed it is acting as a file server. The MAC address `00:00:00:00:00:00` is typical for a VirtualBox virtual machine. This information can be used by an attacker to identify targets by hostname on the local network.

---

## Challenge 9 — FTP Banner

**Objective:** Retrieve the FTP service banner to identify the software and version running on port 21.

**Command Used:**
```bash
nc 192.168.56.104 21
```

**Screenshot:**

<img width="247" height="57" alt="4" src="https://github.com/user-attachments/assets/87bec7c3-2159-4bce-9673-002784d4b476" />


**Output:**
```
220 (vsFTPd 2.3.4)
```

**Findings:** The FTP service is running **vsFTPd version 2.3.4**. This version is publicly known to contain a backdoor vulnerability (**CVE-2011-2523**), which allows an attacker to gain a root shell by sending a specially crafted username containing `:)`. Exposing the version number through the banner is itself a security misconfiguration, as it gives attackers precise information to select exploits.

---

## Challenge 10 — Anonymous FTP Login

**Objective:** Test whether anonymous authentication is enabled on the FTP service.

**Command Used:**
```bash
ftp 192.168.56.104
```
- Username: `anonymous`
- Password: *(blank)*

**Screenshot:**

<img width="318" height="192" alt="5" src="https://github.com/user-attachments/assets/fecd9781-aec9-4bea-a60d-aa241e6d1865" />


**Output:**
```
Connected to 192.168.56.104.
220 (vsFTPd 2.3.4)
Name: anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

**Findings:** Anonymous FTP login is **enabled**. An unauthenticated user can log in and browse accessible directories without any credentials. Combined with the known vsFTPd 2.3.4 backdoor, this service presents a critical attack surface. Anonymous FTP should be disabled unless explicitly required.

---

## Challenge 5 — TTL OS Fingerprinting

**Objective:** Determine the operating system of the target by analyzing the TTL value in ICMP ping responses.

**Command Used:**
```bash
ping 192.168.56.104
```

**Screenshot:**
<img width="538" height="193" alt="6" src="https://github.com/user-attachments/assets/eb27ddeb-22bb-4d76-8c68-92e6b04da8ac" />


**TTL Reference Table:**

| TTL Value | OS Guess |
|-----------|----------|
| 64 | Linux / Unix |
| 128 | Windows |
| 255 | Cisco / BSD |

**Output:**
```
PING 192.168.56.104 (192.168.56.104) 56(84) bytes of data.
64 bytes from 192.168.56.104: icmp_seq=1 ttl=64 time=11.6 ms
64 bytes from 192.168.56.104: icmp_seq=2 ttl=64 time=22.6 ms
...
```

**Findings:** The TTL value returned is **64**, which indicates the target is running a **Linux/Unix** operating system. The host is responsive with low latency (sub-23ms), confirming it is on the same local network segment. This passive fingerprinting technique requires no special tools and can be performed without triggering intrusion detection systems.

---

## Challenge 7 — SMTP VRFY / EXPN

**Objective:** Enumerate valid user accounts on the target by exploiting the SMTP VRFY command.

**Command Used:**
```bash
nc 192.168.56.104 25
VRFY root
VRFY msfadmin
```

**Screenshot:**

<img width="453" height="113" alt="7" src="https://github.com/user-attachments/assets/65dd3e37-be7c-45c6-85e9-42afde903049" />


**Output:**
```
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY msfadmin
252 2.0.0 msfadmin
```

**Findings:**
- The SMTP banner reveals the server is running **Postfix on Ubuntu**, disclosing OS and software information.
- The `VRFY` command returned `252` responses for both `root` and `msfadmin`, indicating these users **likely exist** on the system.
- A `252` response (vs `250`) means the server won't fully confirm but implies the user is valid — still sufficient for user enumeration.
- A hardened server should return `550 User unknown` or disable VRFY entirely.

---

## Challenge 11 — SMB NSE Enumeration

**Objective:** Use Nmap NSE scripts to enumerate OS information and user accounts via the SMB protocol.

**Commands Used:**
```bash
nmap --script smb-os-discovery -p445 192.168.56.104
nmap --script smb-enum-users -p445 192.168.56.104
```

**Screenshots:**

<img width="592" height="331" alt="8a" src="https://github.com/user-attachments/assets/b3e85e1c-cf9b-491d-88f7-b66d9e0ee90f" />

<img width="578" height="617" alt="8b1" src="https://github.com/user-attachments/assets/fa6fbb32-9dbd-420c-a9ef-fdf1dee45273" />


**Output Analysis:**

*smb-os-discovery:*
```
OS: Unix (Samba 3.0.20-Debian)
Computer name: metasploitable
Domain name: localdomain
FQDN: metasploitable.localdomain
System time: 2026-06-10T07:21:15
```

*smb-enum-users (partial):*
```
METASPLOITABLE\backup (RID: 1068)
METASPLOITABLE\bin (RID: 1004)
METASPLOITABLE\daemon (RID: 1002)
METASPLOITABLE\ftp (RID: 1214)
METASPLOITABLE\games (RID: 1010)
...
```

**Findings:**
- OS identified as **Unix running Samba 3.0.20-Debian** — an outdated Samba version vulnerable to multiple CVEs.
- Numerous user accounts were enumerated without authentication, including service accounts (`ftp`, `daemon`, `backup`) and the system clock was revealed.
- Full domain structure (hostname, FQDN, domain name) disclosed, aiding further targeted attacks.

---

## Challenge 12 — Enum4linux

**Objective:** Perform comprehensive SMB enumeration using enum4linux to extract users, shares, and OS information.

**Command Used:**
```bash
enum4linux -a 192.168.56.104
```

**Screenshots:**

*Users enumerated:*

<img width="323" height="580" alt="9a" src="https://github.com/user-attachments/assets/a96c90a2-8bd6-4c13-83a8-75c8d46cc7ce" />


*Shares enumerated:*

<img width="555" height="96" alt="9b" src="https://github.com/user-attachments/assets/a95d3277-5f48-4ac2-90a9-486483baeba2" />


*OS Info via srvinfo:*

<img width="712" height="103" alt="9c" src="https://github.com/user-attachments/assets/056ae402-43c2-4628-91ad-adbe807fd166" />


**Output Analysis:**

*Users (33 accounts found, notable ones):*

| User | Notes |
|------|-------|
| root | Superuser |
| msfadmin | Primary admin account |
| postgres | PostgreSQL service account |
| mysql | MySQL service account |
| tomcat55 | Apache Tomcat service account |
| ftp | FTP service account |
| telnetd | Telnet service (insecure) |

*Shares:*

| Share | Access |
|-------|--------|
| //192.168.56.104/print$ | Mapping: DENIED |
| //192.168.56.104/tmp | Mapping: OK, Listing: OK |
| //192.168.56.104/opt | Mapping: DENIED |

*OS Info (srvinfo):*
```
METASPLOITABLE    Wk Sv PrQ Unx NT SNT metasploitable server (Samba 3.0.20-Debian)
platform_id     : 500
os version      : 4.9
server type     : 0x9a03
```

**Findings:** 33 user accounts were enumerated with no authentication — a critical information disclosure. The `tmp` share is publicly accessible (Mapping: OK, Listing: OK), allowing any network user to browse its contents. OS and Samba version confirmed as Samba 3.0.20-Debian, which is known to be vulnerable to the `username map script` command injection exploit (CVE-2007-2447).

---

## Challenge 13 — NFS Exports

**Objective:** Identify NFS shared directories that are exported to the network.

**Command Used:**
```bash
showmount -e 192.168.56.104
```

**Screenshot:**

<img width="290" height="80" alt="10" src="https://github.com/user-attachments/assets/1017444e-532c-4d21-8dab-425fc7faefde" />


**Output:**
```
Export list for 192.168.56.104:
/ *
```

**Findings:** The entire **root filesystem (`/`)** is exported to **all hosts (`*`)** with no IP restriction. This is far more severe than a typical misconfiguration — it means any machine on the network can mount the root filesystem of the target with a simple command:

```bash
mount -t nfs 192.168.56.104:/ /mnt/target
```

This could expose sensitive files including `/etc/passwd`, `/etc/shadow`, SSH keys, and configuration files. NFS exports should always be restricted to specific trusted IP addresses and should never expose the root directory.

---

## Summary

| # | Challenge | Status | Key Finding |
|---|-----------|--------|-------------|
| 2 | Fast Nmap Scan | ✅ Complete | 18 open ports discovered |
| 16 | Version Detection | ✅ Complete | vsFTPd 2.3.4, UnrealIRCd backdoors identified |
| 1 | NetBIOS Enumeration | ✅ Complete | Hostname: METASPLOITABLE |
| 9 | FTP Banner | ✅ Complete | vsFTPd 2.3.4 (CVE-2011-2523) |
| 10 | Anonymous FTP Login | ✅ Complete | Anonymous login enabled |
| 5 | TTL OS Fingerprinting | ✅ Complete | TTL=64 → Linux confirmed |
| 7 | SMTP VRFY / EXPN | ✅ Complete | root and msfadmin accounts confirmed |
| 11 | SMB NSE Enumeration | ✅ Complete | Samba 3.0.20, users enumerated |
| 12 | Enum4linux | ✅ Complete | 33 users, tmp share publicly accessible |
| 13 | NFS Exports | ✅ Complete | Root `/` exported to all hosts |

### Overall Assessment

Metasploitable 2 demonstrates numerous critical misconfigurations across multiple services. Key vulnerabilities identified through enumeration include unauthenticated access to NFS root exports, anonymous FTP login, SMTP user enumeration, SMB share access without credentials, and multiple services running with known CVEs. These findings highlight the importance of proper service hardening, version management, and network access controls.

---

*Report prepared for IKB21403 Vulnerability Analysis — Chapter 5 Enumeration*  
*Attacker: Kali Linux | Victim: Metasploitable 2 (192.168.56.104)*
