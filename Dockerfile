FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV SCAN_DB_PATH=/data/scans.db
ENV RESULTS_PATH=/data/results

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    dirb \
    exploitdb \
    metasploit-framework \
    hydra \
    john \
    wordlists \
    git \
    curl \
    wget \
    net-tools \
    iputils-ping \
    dnsutils \
    libcap2-bin \
    sudo \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/results

RUN pip3 install --no-cache-dir --break-system-packages \
    fastmcp \
    mcp

COPY mcp_security_server.py /root/mcp_security_server.py
RUN chmod +x /root/mcp_security_server.py

RUN msfdb init || true
RUN searchsploit -u || true

WORKDIR /root

VOLUME ["/data"]

EXPOSE 8000

RUN echo '#!/bin/bash\npython3 /root/mcp_security_server.py &\ntail -f /dev/null' > /root/start.sh && \
    chmod +x /root/start.sh

CMD ["/root/start.sh"]