# A neko desktop with Google Chrome exposing CDP. The viewer is neko's own client, rebuilt without its name and logo.
# Built locally: Chrome is downloaded at build time and not redistributed.
ARG NEKO_VERSION=3.1.5

FROM node:24-slim AS source
ARG NEKO_VERSION
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends git ca-certificates; rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "v${NEKO_VERSION}" https://github.com/m1k1o/neko.git /neko
COPY cookie-auth.patch /tmp/cookie-auth.patch
RUN cd /neko && git apply /tmp/cookie-auth.patch

FROM source AS client
COPY client/ /neutral/
RUN set -eux; cd /neko/client; node /neutral/neutralize.mjs .; npm ci --no-audit --no-fund --loglevel=error; npm run build

FROM golang:1.25-trixie AS server
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends \
    libx11-dev libxrandr-dev libxtst-dev libgtk-3-dev libxcvt-dev \
    libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev; \
    rm -rf /var/lib/apt/lists/*
COPY --from=source /neko/server /src
WORKDIR /src
COPY tests/session_test.go internal/http/legacy/cookie_session_test.go
RUN go test ./internal/http/legacy && go build -o /usr/bin/neko -ldflags "-s -w" ./cmd/neko

FROM node:24-slim AS mcp
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
RUN npm install --prefix /opt/mcp --no-audit --no-fund --loglevel=error "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}"

FROM ghcr.io/m1k1o/neko/base:${NEKO_VERSION}
ARG CHROME_DEB=https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN set -eux; \
    apt-get update; \
    wget -qO /tmp/chrome.deb "$CHROME_DEB"; \
    apt-get install -y --no-install-recommends openbox socat nginx /tmp/chrome.deb; \
    rm -f /tmp/chrome.deb; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

COPY --from=client /neko/client/dist /var/www
COPY --from=server /usr/bin/neko /usr/bin/neko
COPY --from=mcp /usr/local/bin/node /usr/local/bin/node
COPY --from=mcp /opt/mcp /opt/mcp
COPY supervisord.conf /etc/neko/supervisord/chrome.conf
COPY policies.json /etc/opt/chrome/policies/managed/policies.json
COPY nginx.conf /etc/neko/nginx.conf
COPY gate.py /usr/local/bin/gate.py
