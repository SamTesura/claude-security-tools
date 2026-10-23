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
    ca-certificates \
    net-tools \
    iputils-ping \
    dnsutils \
    libcap2-bin \
    sudo \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# The private keys of several eMudhra (emSign) intermediate CAs turned out to be
# trivially weak and are compromised (Oct 2026). Debian's fixed ca-certificates
# (20260816+nmu1 in testing/sid) distrusts the two roots that vouch for them,
# emSign ECC Root CA - G3 and Comodo AAA Services root, but Kali's import of
# that fix is not confirmed. ca-certificates is named in the install above so
# apt upgrades it to Kali's newest build even when the base image already has
# one; if that build still predates the fix, deselect both roots in
# /etc/ca-certificates.conf ('!' prefix, only where they are listed) and
# rebuild the system bundle. The check after the pip install fails the build
# if either root is still trusted.
RUN if dpkg --compare-versions \
        "$(dpkg-query -W -f='${Version}' ca-certificates)" lt 20260816+nmu1; then \
        sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3\.crt$|!&|' \
               -e 's|^mozilla/Comodo_AAA_Services_root\.crt$|!&|' \
               /etc/ca-certificates.conf && \
        update-ca-certificates; \
    fi

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
#
# mcp pulls in httpx, which trusts certifi's CA bundle rather than the system
# one. GHSA-6q48-6c7w-9gw2 is fixed in certifi 2026.10.19, which drops emSign
# ECC Root CA - G3, so floor it there. The exception is a Debian
# python3-certifi that a Kali package already installed: keep that one. Debian
# patches its certifi.where() to return the system bundle fixed above, and pip
# cannot upgrade an apt-owned copy (it has no RECORD file, so pip stops with
# uninstall-no-record-file and the build fails).
RUN certifi='certifi>=2026.10.19' && \
    if [ "$(dpkg-query -W -f='${db:Status-Status}' python3-certifi 2>/dev/null)" = installed ]; then \
        certifi=certifi; \
    fi && \
    pip3 install --no-cache-dir --break-system-packages \
    "mcp<2" \
    "$certifi"

# Fail the build if either distrusted root is still trusted anywhere a client
# in this image looks: the system bundle and the per-certificate files behind
# OpenSSL's hashed lookup directory (what curl, wget, the Ruby tools such as
# wpscan and Metasploit, and Debian's pip trust), plus the certifi bundle that
# httpx loads. A file openssl cannot read fails the build too, rather than
# passing as "no match".
RUN for f in /etc/ssl/certs/*.crt /etc/ssl/certs/*.pem \
        "$(python3 -c 'import certifi; print(certifi.where())')"; do \
        subjects="$(openssl crl2pkcs7 -nocrl -certfile "$f" \
            | openssl pkcs7 -print_certs -noout)" || exit 1; \
        if printf '%s\n' "$subjects" | grep -E \
            '^subject=.*CN ?= ?(emSign ECC Root CA - G3|AAA Certificate Services)(,|$)'; then \
            echo "ERROR: $f still trusts a root behind the compromised eMudhra CAs" >&2; \
            exit 1; \
        fi; \
    done

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