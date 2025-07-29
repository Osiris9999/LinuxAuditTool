#!/usr/bin/env python3

import os
import subprocess
import json
import re
import stat
import pwd
import grp
from datetime import datetime
from pathlib import Path
import hashlib

class LinuxSecurityAuditor:
    def __init__(self):
        self.results = {}
        self.checks_run = 0
        self.checks_passed = 0
        self.critical = []
        self.warnings = []
        self.todo = []
        
    def cmd(self, command, shell=True):
        try:
            proc = subprocess.run(command, shell=shell, capture_output=True, text=True, timeout=30)
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as e:
            return -1, "", str(e)
    
    def check_perms(self, path, mode, owner="root", group="root"):
        if not os.path.exists(path):
            return False, f"{path} missing"
        
        try:
            st = os.stat(path)
            actual_mode = oct(st.st_mode)[-3:]
            
            try:
                actual_owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                actual_owner = str(st.st_uid)
            
            try:
                actual_group = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                actual_group = str(st.st_gid)
            
            problems = []
            if actual_mode != mode:
                problems.append(f"mode {actual_mode} (want {mode})")
            if actual_owner != owner:
                problems.append(f"owner {actual_owner} (want {owner})")
            if actual_group != group:
                problems.append(f"group {actual_group} (want {group})")
            
            if problems:
                return False, f"{path}: {', '.join(problems)}"
            return True, f"{path} ok"
            
        except Exception as e:
            return False, f"{path}: {str(e)}"
    
    def check_firewall(self):
        checks = []
        
        rc, out, _ = self.cmd("ufw status")
        if rc == 0:
            if "Status: active" in out:
                checks.append(("UFW", True, "active"))
            else:
                checks.append(("UFW", False, "inactive"))
                self.todo.append("sudo ufw enable")
        
        rc, out, _ = self.cmd("iptables -L | wc -l")
        if rc == 0:
            lines = int(out.strip())
            if lines > 8:
                checks.append(("iptables", True, f"{lines} lines of rules"))
            else:
                checks.append(("iptables", False, "no custom rules"))
        
        rc, out, _ = self.cmd("ss -tuln")
        if rc == 0:
            ports = []
            for line in out.split('\n'):
                if ':' in line and 'LISTEN' in line:
                    m = re.search(r':(\d+)\s', line)
                    if m:
                        port = m.group(1)
                        if port not in ['22', '53']:
                            ports.append(port)
            
            if ports:
                checks.append(("open ports", False, f"check these: {', '.join(ports)}"))
                self.warnings.append(f"ports {', '.join(ports)} are open")
            else:
                checks.append(("open ports", True, "only ssh/dns"))
        
        return checks
    
    def check_ssh(self):
        checks = []
        config_file = "/etc/ssh/sshd_config"
        
        if not os.path.exists(config_file):
            checks.append(("ssh config", False, "file missing"))
            return checks
        
        try:
            with open(config_file, 'r') as f:
                config = f.read()
            
            ssh_checks = {
                "root login": (r'^\s*PermitRootLogin\s+no', "disable root ssh"),
                "password auth": (r'^\s*PasswordAuthentication\s+no', "keys only"),
                "empty passwords": (r'^\s*PermitEmptyPasswords\s+no', "no empty passwords"),
                "max attempts": (r'^\s*MaxAuthTries\s+[1-4]', "limit auth tries"),
            }
            
            for name, (pattern, desc) in ssh_checks.items():
                if re.search(pattern, config, re.MULTILINE):
                    checks.append((f"ssh {name}", True, desc))
                else:
                    checks.append((f"ssh {name}", False, f"fix: {desc}"))
                    self.todo.append(f"SSH: {desc}")
            
        except Exception as e:
            checks.append(("ssh config", False, f"read error: {e}"))
        
        return checks
    
    def check_files(self):
        checks = []
        
        files = {
            "/etc/passwd": ("644", "root", "root"),
            "/etc/shadow": ("640", "root", "shadow"),
            "/etc/group": ("644", "root", "root"),
            "/etc/gshadow": ("640", "root", "shadow"),
            "/etc/sudoers": ("440", "root", "root"),
            "/etc/crontab": ("600", "root", "root"),
        }
        
        for path, (mode, owner, group) in files.items():
            ok, msg = self.check_perms(path, mode, owner, group)
            checks.append((f"perms {os.path.basename(path)}", ok, msg))
            if not ok:
                self.todo.append(f"chmod {mode} {path} && chown {owner}:{group} {path}")
        
        return checks
    
    def check_services(self):
        checks = []
        
        rc, out, _ = self.cmd("systemctl list-unit-files --type=service --state=enabled")
        if rc != 0:
            checks.append(("services", False, "systemctl failed"))
            return checks
        
        bad_services = [
            'telnet', 'rsh', 'rlogin', 'vsftpd', 'ftpd', 
            'finger', 'talk', 'sendmail', 'postfix', 'dovecot'
        ]
        
        enabled = []
        for line in out.split('\n'):
            if 'enabled' in line:
                svc = line.split()[0].replace('.service', '')
                enabled.append(svc)
        
        found_bad = [s for s in bad_services if s in enabled]
        
        if found_bad:
            checks.append(("risky services", False, f"enabled: {', '.join(found_bad)}"))
            for svc in found_bad:
                self.todo.append(f"systemctl disable {svc}")
        else:
            checks.append(("risky services", True, "none found"))
        
        return checks
    
    def check_rootkits(self):
        checks = []
        
        sus_paths = [
            '/tmp/.ICE-unix/.font-unix',
            '/dev/rd/cdb',
            '/dev/.static/tty',
            '/usr/src/.puta',
            '/etc/ld.so.preload'
        ]
        
        found = [p for p in sus_paths if os.path.exists(p)]
        
        if found:
            checks.append(("rootkit paths", False, f"suspicious: {', '.join(found)}"))
            self.critical.append(f"possible rootkit files: {', '.join(found)}")
        else:
            checks.append(("rootkit paths", True, "clean"))
        
        rc, out, _ = self.cmd("ps aux --no-headers | wc -l")
        if rc == 0:
            procs = int(out.strip())
            if procs > 200:
                checks.append(("process count", False, f"{procs} processes"))
                self.warnings.append(f"lots of processes ({procs})")
            else:
                checks.append(("process count", True, f"{procs} processes"))
        
        return checks
    
    def check_users(self):
        checks = []
        
        rc, out, _ = self.cmd("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
        if rc == 0 and out:
            users = out.split('\n')
            checks.append(("empty passwords", False, f"users: {', '.join(users)}"))
            self.critical.append(f"no password: {', '.join(users)}")
        else:
            checks.append(("empty passwords", True, "none"))
        
        rc, out, _ = self.cmd("awk -F: '($3 == 0) {print $1}' /etc/passwd")
        if rc == 0:
            uid0_users = [u for u in out.split('\n') if u]
            if len(uid0_users) > 1 or (uid0_users and uid0_users[0] != 'root'):
                checks.append(("uid 0 accounts", False, f"found: {', '.join(uid0_users)}"))
                self.critical.append("multiple uid 0 accounts")
            else:
                checks.append(("uid 0 accounts", True, "only root"))
        
        return checks
    
    def check_updates(self):
        checks = []
        
        rc, out, _ = self.cmd("apt list --upgradable 2>/dev/null | wc -l")
        if rc == 0:
            count = int(out.strip()) - 1
            if count > 0:
                checks.append(("updates", False, f"{count} available"))
                self.todo.append(f"apt upgrade ({count} packages)")
            else:
                checks.append(("updates", True, "up to date"))
        else:
            rc, out, _ = self.cmd("yum check-update 2>/dev/null | grep -v '^$' | wc -l")
            if rc == 100:
                checks.append(("updates", False, "available (yum)"))
                self.todo.append("yum update")
            elif rc == 0:
                checks.append(("updates", True, "up to date"))
            else:
                checks.append(("updates", False, "check failed"))
        
        return checks
    
    def score(self):
        if self.checks_run == 0:
            return 0
        return round((self.checks_passed / self.checks_run) * 100, 1)
    
    def run(self):
        print("Linux security audit")
        print("-" * 40)
        
        sections = [
            ("firewall", self.check_firewall),
            ("ssh", self.check_ssh),
            ("files", self.check_files),
            ("services", self.check_services),
            ("rootkits", self.check_rootkits),
            ("users", self.check_users),
            ("updates", self.check_updates),
        ]
        
        for name, func in sections:
            print(f"\n[{name}]")
            try:
                results = func()
                self.results[name] = results
                
                for check, passed, msg in results:
                    self.checks_run += 1
                    if passed:
                        self.checks_passed += 1
                        print(f"  ok   {check}: {msg}")
                    else:
                        print(f"  FAIL {check}: {msg}")
                        
            except Exception as e:
                print(f"  ERROR: {e}")
        
        self.report()
    
    def report(self):
        score = self.score()
        
        print(f"\n{'='*50}")
        print("AUDIT RESULTS")
        print(f"{'='*50}")
        print(f"Host: {os.uname().nodename}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"Score: {score}% ({self.checks_passed}/{self.checks_run})")
        
        if score >= 80:
            print("Status: GOOD")
        elif score >= 60:
            print("Status: NEEDS WORK")
        else:
            print("Status: BAD")
        
        if self.critical:
            print(f"\nCRITICAL ISSUES:")
            for issue in self.critical:
                print(f"  ! {issue}")
        
        if self.warnings:
            print(f"\nWARNINGS:")
            for warn in self.warnings:
                print(f"  - {warn}")
        
        if self.todo:
            print(f"\nTODO:")
            for i, item in enumerate(self.todo[:10], 1):
                print(f"  {i}. {item}")
            if len(self.todo) > 10:
                print(f"  ... and {len(self.todo)-10} more")
        
        report_file = f"audit_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "score": score,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "results": self.results,
            "critical": self.critical,
            "warnings": self.warnings,
            "todo": self.todo
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\nFull report saved: {report_file}")

def main():
    if os.geteuid() != 0:
        print("Warning: not running as root, some checks limited")
        print("Run with sudo for full audit\n")
    
    auditor = LinuxSecurityAuditor()
    auditor.run()

if __name__ == "__main__":
    main()
