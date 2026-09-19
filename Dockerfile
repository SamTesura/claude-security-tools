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

# Kali ships /usr/lib/nmap/nmap with file capabilities (setcap net_raw,net_admin,
# net_bind_service) so non-root users can SYN-scan. This server runs as root with
# cap_add: NET_RAW, so those file caps are redundant — and they make execve fail
# with EPERM under `security_opt: no-new-privileges:true` (the kernel refuses an
# execve that would grant new file caps). Strip them so nmap runs cleanly as
# root+NET_RAW while we keep the no-new-privileges hardening.
RUN setcap -r /usr/lib/nmap/nmap || true

# Pin mcp to the v1 line. The server imports mcp.server.fastmcp.FastMCP, which
# was removed in mcp 2.x — an unpinned install now pulls 2.x and the import
# fails at startup ("No module named 'mcp.server.fastmcp'"). The standalone
# fastmcp package was unused by this code, so it is dropped.
RUN pip3 install --no-cache-dir --break-system-packages \
    "mcp<2"

COPY mcp_security_server.py /root/mcp_security_server.py
RUN chmod +x /root/mcp_security_server.py

# Bake a valid default scope allowlist into the image. A single-file bind mount
# of scope.json is unreliable on Docker Desktop + WSL2 (it can surface as an
# empty file and trip the fail-closed scope loader at startup), so ship a valid
# default in the image. Override by mounting a DIRECTORY that contains a
# scope.json onto /etc/mcp (see docker-compose.yml).
RUN mkdir -p /etc/mcp
COPY scope.example.json /etc/mcp/scope.json

# NOTE: msfdb init and `searchsploit -u` are intentionally NOT run at build time.
# They introduce non-deterministic network fetches and DB state that does not
# belong in an image layer. The auxiliary/* and post/* modules this server allows
# run without a Metasploit DB, and searchsploit uses the packaged Exploit-DB.
# Refresh the exploit DB deliberately at runtime with `searchsploit -u`.

WORKDIR /root

VOLUME ["/data"]

# Generate the launch script with printf so real newlines are guaranteed
# regardless of which /bin/sh echo implements backslash escapes.
RUN printf '%s\n' \
    '#!/bin/bash' \
    'python3 /root/mcp_security_server.py &' \
    'tail -f /dev/null' \
    > /root/start.sh && \
    chmod +x /root/start.sh

CMD ["/root/start.sh"]