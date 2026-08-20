#!/bin/bash
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
NAME="${WAZUH_AGENT_NAME:-victim01}"

for user in backup appsvc natali; do
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
done
echo 'backup:Summer2026!' | chpasswd
echo 'natali:Correct-Horse-9' | chpasswd
usermod -aG sudo natali

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
ssh-keygen -A >/dev/null 2>&1
touch /var/log/auth.log /var/log/syslog /var/log/lab/access.log

echo "configuring and starting rsyslog"
cat > /etc/rsyslog.conf <<'CONF'
module(load="imuxsock")
$FileCreateMode 0644
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
auth,authpriv.*                 /var/log/lab/auth.log
*.*;auth,authpriv.none          /var/log/lab/syslog
CONF
rm -f /etc/rsyslog.d/*.conf 2>/dev/null || true
rsyslogd
sleep 2

echo "starting sshd"
# No -E: sshd logs via syslog/authpriv, so rsyslog frames each line with the
# timestamp and hostname that Wazuh's sshd decoder expects.
/usr/sbin/sshd

echo "enrolling with $MANAGER as $NAME"
until /var/ossec/bin/agent-auth -m "$MANAGER" -A "$NAME" >/dev/null 2>&1; do
    echo "manager not accepting enrolment yet, retrying"
    sleep 10
done

/var/ossec/bin/wazuh-control start
sleep 5
/var/ossec/bin/wazuh-control status | head -3

echo "agent up, starting scenes"
exec python3 /opt/attacks.py --loop
