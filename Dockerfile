# A neko desktop with a browser exposing CDP. neko only shows the screen and takes input: its server runs unchanged
# and without authentication, behind the gate. Its client is rebuilt without its name, logo and login form.
# Built locally: Chrome is downloaded at build time and not redistributed.
ARG NEKO_VERSION=3.1.5

FROM node:24-slim AS client
ARG NEKO_VERSION
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends git ca-certificates; rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "v${NEKO_VERSION}" https://github.com/m1k1o/neko.git /neko
COPY client/ /neutral/
RUN set -eux; cd /neko/client; node /neutral/neutralize.mjs .; npm ci --no-audit --no-fund --loglevel=error; npm run build

FROM node:24-slim AS mcp
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
RUN npm install --prefix /opt/mcp --no-audit --no-fund --loglevel=error "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}"

FROM ghcr.io/m1k1o/neko/base:${NEKO_VERSION}
ARG CHROME_DEB=https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
# Google Chrome where Google builds it (amd64); Debian's Chromium elsewhere. Either answers as /usr/local/bin/browser.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openbox socat nginx; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -qO /tmp/chrome.deb "$CHROME_DEB"; \
        apt-get install -y --no-install-recommends /tmp/chrome.deb; rm -f /tmp/chrome.deb; \
        ln -s /usr/bin/google-chrome /usr/local/bin/browser; \
    else \
        apt-get install -y --no-install-recommends chromium; \
        ln -s /usr/bin/chromium /usr/local/bin/browser; \
    fi; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

COPY --from=client /neko/client/dist /var/www
COPY --from=mcp /usr/local/bin/node /usr/local/bin/node
COPY --from=mcp /opt/mcp /opt/mcp
COPY supervisord.conf /etc/neko/supervisord/chrome.conf
COPY policies.json /etc/opt/chrome/policies/managed/policies.json
COPY policies.json /etc/chromium/policies/managed/policies.json
COPY nginx.conf /etc/neko/nginx.conf
COPY gate.py /usr/local/bin/gate.py
