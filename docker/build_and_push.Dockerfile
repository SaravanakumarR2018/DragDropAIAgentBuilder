# syntax=docker/dockerfile:1
# Keep this syntax directive! It's used to enable Docker BuildKit

################################
# BUILDER-BASE
# Used to build deps + create our virtual environment
################################

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV RUSTFLAGS='--cfg reqwest_unstable'

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
    build-essential \
    git \
    npm \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/nginx/sites-enabled/default \

# Copy files first to avoid permission issues with bind mounts
COPY ./uv.lock /app/uv.lock
COPY ./README.md /app/README.md
COPY ./pyproject.toml /app/pyproject.toml
COPY ./src/backend/base/README.md /app/src/backend/base/README.md
COPY ./src/backend/base/uv.lock /app/src/backend/base/uv.lock
COPY ./src/backend/base/pyproject.toml /app/src/backend/base/pyproject.toml
COPY ./src/lfx/README.md /app/src/lfx/README.md
COPY ./src/lfx/pyproject.toml /app/src/lfx/pyproject.toml

RUN --mount=type=cache,target=/root/.cache/uv \
    RUSTFLAGS='--cfg reqwest_unstable' \
    uv sync --no-install-project --no-editable --extra postgresql

COPY ./src /app/src

################################
# BUILD FRONTEND 1
################################
ARG VITE_AUTO_LOGIN=true
ENV VITE_AUTO_LOGIN=$VITE_AUTO_LOGIN
ARG VITE_CLERK_AUTH_ENABLED=false
ARG VITE_CLERK_PUBLISHABLE_KEY=""
ENV VITE_CLERK_AUTH_ENABLED=$VITE_CLERK_AUTH_ENABLED
ENV VITE_CLERK_PUBLISHABLE_KEY=$VITE_CLERK_PUBLISHABLE_KEY

COPY src/frontend1 /tmp/src/frontend1
WORKDIR /tmp/src/frontend1

RUN --mount=type=cache,target=/root/.npm \
    npm ci \
    && ESBUILD_BINARY_PATH="" NODE_OPTIONS="--max-old-space-size=12288" JOBS=1 npm run build \
    && cp -r build /app/frontend1_build \
    && rm -rf /tmp/src/frontend1

################################
# BUILD FRONTEND 2
################################
COPY src/frontend2 /tmp/src/frontend2
WORKDIR /tmp/src/frontend2

RUN --mount=type=cache,target=/root/.npm \
    npm ci \
    && ESBUILD_BINARY_PATH="" NODE_OPTIONS="--max-old-space-size=12288" JOBS=1 npm run build \
    && cp -r build /app/frontend2_build \
    && rm -rf /tmp/src/frontend2

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    RUSTFLAGS='--cfg reqwest_unstable' \
    uv sync --frozen --no-editable --extra postgresql

################################
# RUNTIME
# Setup user, Nginx, and Python environment
################################
FROM python:3.12.3-slim AS runtime

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y curl git libpq5 gnupg nginx \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && useradd user -u 1000 -g 0 --no-create-home --home-dir /app/data \
    && mkdir -p /var/lib/nginx/body /var/tmp/nginx \
    && chown -R 1000:0 /var/lib/nginx /var/tmp/nginx /var/log/nginx /etc/nginx /usr/share/nginx/html \
    && mkdir -p /run && touch /run/nginx.pid && chown -R 1000:0 /run

COPY --from=builder --chown=1000 /app/.venv /app/.venv
COPY --from=builder /app/src/backend /app/src/backend
COPY --from=builder /app/frontend1_build /usr/share/nginx/html/frontend1
COPY --from=builder /app/frontend2_build /usr/share/nginx/html/frontend2
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

ENV PATH="/app/.venv/bin:$PATH"
ENV LANGFLOW_HOST=0.0.0.0
ENV LANGFLOW_PORT=7860

USER user
WORKDIR /app

EXPOSE 7860

CMD ["sh", "-c", "langflow run --host 0.0.0.0 --port 7861 --backend-only & nginx -g 'daemon off;'"]
