# A neko desktop with Google Chrome exposing CDP. The viewer is neko's own client, rebuilt without its name and logo.
# Built locally: Chrome is downloaded at build time and not redistributed.
ARG NEKO_VERSION=3.1.5

FROM node:24-slim AS client
ARG NEKO_VERSION
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends git ca-certificates; rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "v${NEKO_VERSION}" https://github.com/m1k1o/neko.git /neko
COPY client/ /neutral/
RUN set -eux; cd /neko/client; node /neutral/neutralize.mjs .; npm ci --no-audit --no-fund --loglevel=error; npm run build

FROM ghcr.io/m1k1o/neko/base:${NEKO_VERSION}
ARG CHROME_DEB=https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN set -eux; \
    apt-get update; \
    wget -qO /tmp/chrome.deb "$CHROME_DEB"; \
    apt-get install -y --no-install-recommends openbox socat nginx /tmp/chrome.deb; \
    rm -f /tmp/chrome.deb; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

COPY --from=client /neko/client/dist /var/www
COPY supervisord.conf /etc/neko/supervisord/chrome.conf
COPY policies.json /etc/opt/chrome/policies/managed/policies.json
COPY nginx.conf /etc/neko/nginx.conf
COPY gate.py /usr/local/bin/gate.py
