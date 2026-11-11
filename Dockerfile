FROM node:22.23.4-bookworm-slim AS auth-build
WORKDIR /build/auth
COPY auth/package.json auth/package-lock.json ./
RUN npm ci --ignore-scripts
COPY auth/tsconfig.json ./
COPY auth/src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:22.23.4-bookworm-slim
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates curl gosu \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) checksum=fd29f51030dde6919b6ca9173bc87852d3846f253d198022ea2d9ee63527b945 ;; \
      arm64) checksum=2837145e72922d558538494d0da30ac6c509681fc0791f8818f4ddb87f5125b4 ;; \
      *) echo "Unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --retry-all-errors --connect-timeout 20 "https://github.com/larksuite/cli/releases/download/v1.0.99/lark-cli-1.0.99-linux-${arch}.tar.gz" -o /tmp/lark.tar.gz; \
    echo "$checksum  /tmp/lark.tar.gz" | sha256sum -c -; \
    mkdir /tmp/lark; tar xzf /tmp/lark.tar.gz -C /tmp/lark; \
    find /tmp/lark -type f -name lark-cli -exec install -m755 {} /usr/local/bin/lark-cli \;; \
    rm -rf /tmp/lark /tmp/lark.tar.gz
WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home --home-dir /data --shell /bin/bash monitor
COPY --from=auth-build /build/auth/node_modules /app/auth/node_modules
COPY --from=auth-build /build/auth/dist /app/auth/dist
COPY auth/package.json /app/auth/package.json
COPY dot_feishu /app/dot_feishu
COPY scripts/container_init.py scripts/entrypoint.sh /app/scripts/
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=UTC
EXPOSE 8560
ENTRYPOINT ["bash", "/app/scripts/entrypoint.sh"]
