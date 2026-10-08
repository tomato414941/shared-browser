# A browser exposing CDP on a desktop that neko shows and takes input for. neko is used as it ships: unchanged,
# without authentication, behind the gate, as the part of the viewer under /screen/.
# Built locally: Chrome is downloaded at build time and not redistributed.
ARG NEKO_VERSION=3.1.5

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

COPY --from=mcp /usr/local/bin/node /usr/local/bin/node
COPY --from=mcp /opt/mcp /opt/mcp
COPY supervisord.conf /etc/neko/supervisord/chrome.conf
COPY openbox.xml /etc/neko/openbox.xml
COPY policies.json /etc/opt/chrome/policies/managed/policies.json
COPY policies.json /etc/chromium/policies/managed/policies.json
COPY nginx.conf /etc/neko/nginx.conf
COPY gate.py /usr/local/bin/gate.py

# Healthy while every part supervisord runs is running. A part it could not start again stays down and shows here.
HEALTHCHECK --interval=10s --timeout=5s CMD supervisorctl -c /etc/neko/supervisord.conf status > /dev/null || exit 1
