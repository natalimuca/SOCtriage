FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg2 lsb-release \
        openssh-server sshpass sudo cron procps python3 rsyslog \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent \
    && rm -rf /var/lib/apt/lists/*

COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
COPY attacks.py /opt/attacks.py

RUN chmod +x /entrypoint.sh && mkdir -p /var/run/sshd /var/www/html /var/log/lab

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/entrypoint.sh"]
