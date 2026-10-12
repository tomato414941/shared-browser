# A browser on a display of its own. People watch and drive it through WebRTC (screen.py), agents through CDP and
# MCP, and everyone comes in through the gate (gate.py).
# Built locally: Chrome is downloaded at build time and not redistributed.
FROM node:24-slim AS mcp
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
RUN npm install --prefix /opt/mcp --no-audit --no-fund --loglevel=error "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}"

FROM debian:trixie-slim
ARG CHROME_DEB=https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
# Google Chrome where Google builds it (amd64); Debian's Chromium elsewhere. Either answers as /usr/local/bin/browser.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates wget supervisor xvfb x11-utils openbox socat \
        python3 python3-gi python3-xlib python3-websockets \
        gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0 gir1.2-gst-plugins-bad-1.0 \
        gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
        gstreamer1.0-nice gstreamer1.0-x fonts-noto-cjk fonts-noto-color-emoji; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -qO /tmp/chrome.deb "$CHROME_DEB"; \
        apt-get install -y --no-install-recommends /tmp/chrome.deb; rm -f /tmp/chrome.deb; \
        ln -s /usr/bin/google-chrome /usr/local/bin/browser; \
    else \
        apt-get install -y --no-install-recommends chromium; \
        ln -s /usr/bin/chromium /usr/local/bin/browser; \
    fi; \
    apt-get clean; rm -rf /var/lib/apt/lists/*; \
    useradd -m -u 1000 browser; \
    install -d -o browser -g browser /var/log/shared-browser /home/browser/profile /home/browser/state

COPY --from=mcp /usr/local/bin/node /usr/local/bin/node
COPY --from=mcp /opt/mcp /opt/mcp
COPY policies.json /etc/opt/chrome/policies/managed/policies.json
COPY policies.json /etc/chromium/policies/managed/policies.json
COPY supervisord.conf openbox.xml gate.py screen.py fields.js viewer.html /opt/shared-browser/

USER browser
ENV DISPLAY=:99
# Healthy while every part supervisord runs is running. A part it could not start again stays down and shows here.
HEALTHCHECK --interval=10s --timeout=5s CMD supervisorctl -c /opt/shared-browser/supervisord.conf status > /dev/null || exit 1
CMD ["supervisord", "-c", "/opt/shared-browser/supervisord.conf"]
