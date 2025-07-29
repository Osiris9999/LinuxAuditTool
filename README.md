# Linux Security Audit Script

Quick and dirty security audit for Linux servers. Checks the usual suspects - firewall, SSH config, file permissions, sketchy services, and other stuff that should probably be locked down.

## What it does

- Firewall status (UFW/iptables)
- SSH hardening checks  
- Critical file permissions (/etc/passwd, /etc/shadow, etc.)
- Unnecessary/risky services
- Basic rootkit indicators
- User account issues
- Available system updates

Spits out a score and tells you what's broken.

## Usage

```bash
# Basic run (some checks will be limited)
python3 security_audit.py

# Full audit (recommended)
sudo python3 security_audit.py
```

## Sample Output

```
Linux security audit
----------------------------------------

[firewall]
  ok   UFW: active
  FAIL iptables: no custom rules
  FAIL open ports: check these: 80, 443, 3306

[ssh]
  ok   ssh root login: disable root ssh
  FAIL ssh password auth: fix: keys only
  ok   ssh empty passwords: no empty passwords

[files]
  ok   perms passwd: /etc/passwd ok
  FAIL perms shadow: /etc/shadow: mode 644 (want 640)

==================================================
AUDIT RESULTS
==================================================
Host: webserver01
Date: 2024-03-15 14:32
Score: 67.3% (15/23)
Status: NEEDS WORK

CRITICAL ISSUES:
  ! no password: mysql

WARNINGS:
  - ports 80, 443, 3306 are open

TODO:
  1. sudo ufw enable
  2. SSH: keys only
  3. chmod 640 /etc/shadow && chown root:shadow /etc/shadow
  4. systemctl disable postfix
  ... and 3 more

Full report saved: audit_20240315_1432.json
```

## Requirements

- Python 3.6+
- Linux (obviously)
- Root access for complete results

Most commands should work on any modern distro. Tested on Ubuntu, CentOS, and Debian.

## What gets checked

### Firewall
- UFW status
- Basic iptables rules
- Open listening ports

### SSH Configuration
- Root login disabled
- Password authentication disabled  
- Empty passwords blocked
- Max auth attempts limited

### File Permissions
Standard system files that attackers love to mess with:
- /etc/passwd (644)
- /etc/shadow (640) 
- /etc/group (644)
- /etc/gshadow (640)
- /etc/sudoers (440)
- /etc/crontab (600)

### Services
Looks for commonly enabled services that you probably don't need:
- telnet, rsh, rlogin
- FTP daemons
- Mail servers (sendmail, postfix, dovecot)
- Print services (cups)

### Rootkit Detection
Basic checks for common hiding spots:
- Suspicious paths in /tmp, /dev, /usr/src
- Process count anomalies
- /etc/ld.so.preload modifications

### User Accounts
- Users with empty passwords
- Multiple UID 0 accounts (should only be root)

### Updates
Checks for available security updates using apt or yum.

## Output Files

Creates a JSON report with full details:
```json
{
  "timestamp": "2024-03-15T14:32:15",
  "hostname": "webserver01", 
  "score": 67.3,
  "checks_run": 23,
  "checks_passed": 15,
  "critical": ["no password: mysql"],
  "warnings": ["ports 80, 443, 3306 are open"],
  "todo": ["sudo ufw enable", "SSH: keys only", ...]
}
```

## Limitations

This isn't a replacement for proper security tools. It's meant for:
- Quick server checkups
- Basic hardening verification
- Spotting obvious misconfigurations

For serious security auditing, use proper tools like:
- Lynis
- OpenSCAP
- Nessus
- chkrootkit/rkhunter

## Contributing

PRs welcome. Keep it simple and practical - this isn't meant to be comprehensive, just useful for common scenarios.
