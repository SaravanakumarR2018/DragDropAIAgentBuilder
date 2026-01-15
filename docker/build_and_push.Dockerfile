# syntax=docker/dockerfile:1
# Keep this syntax directive! It's used to enable Docker BuildKit

################################
# BUILDER
################################

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV RUSTFLAGS='--cfg reqwest_unstable'

# ---- system deps + Node 20 ----
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        build-essential \
        git \
        gcc \
        curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ---- python deps (layered) ----
COPY ./uv.lock /app/uv.lock
COPY ./README.md /app/README.md
COPY ./pyproject.toml /app/pyproject.toml
COPY ./src/backend/base/README.md /app/src/backend/base/README.md
COPY ./src/backend/base/uv.lock /app/src/backend/base/uv.lock
COPY ./src/backend/base/pyproject.toml /app/src/backend/base/pyproject.toml
COPY ./src/lfx/README.md /app/src/lfx/README.md
COPY ./src/lfx/pyproject.toml /app/src/lfx/pyproject.toml

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-editable --extra postgresql

COPY ./src /app/src

# ---- frontend (Langflow UI) ----
ARG VITE_AUTO_LOGIN=true
ENV VITE_AUTO_LOGIN=$VITE_AUTO_LOGIN

COPY src/frontend /tmp/src/frontend
WORKDIR /tmp/src/frontend

ARG VITE_CLERK_AUTH_ENABLED=false
ARG VITE_CLERK_PUBLISHABLE_KEY=""
ENV VITE_CLERK_AUTH_ENABLED=$VITE_CLERK_AUTH_ENABLED
ENV VITE_CLERK_PUBLISHABLE_KEY=$VITE_CLERK_PUBLISHABLE_KEY

RUN --mount=type=cache,target=/root/.npm \
    npm ci \
    && ESBUILD_BINARY_PATH="" NODE_OPTIONS="--max-old-space-size=12288" JOBS=1 npm run build \
    && cp -r build /app/src/backend/langflow/frontend \
    && rm -rf /tmp/src/frontend

# ---- marketing landing page ----
COPY src/new-landingpage /tmp/src/new-landingpage
WORKDIR /tmp/src/new-landingpage

RUN --mount=type=cache,target=/root/.npm \
    npm ci \
    && npm run build \
    && mkdir -p /app/new-landingpage \
    && cp -r dist /app/new-landingpage/dist \
    && rm -rf /tmp/src/new-landingpage

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable --extra postgresql

################################
# RUNTIME
################################

FROM python:3.12.3-slim AS runtime

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
        curl \
        git \
        libpq5 \
        gnupg \
        nginx \
        gettext-base \
        supervisor \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && useradd user -u 1000 -g 0 --no-create-home --home-dir /app/data

COPY --from=builder --chown=1000 /app/.venv /app/.venv
COPY --from=builder --chown=1000 /app/new-landingpage /app/new-landingpage

COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf.template
COPY docker/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/entrypoint.sh /usr/local/bin/langflow-entrypoint.sh
RUN chmod +x /usr/local/bin/langflow-entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"

LABEL org.opencontainers.image.title=langflow
LABEL org.opencontainers.image.authors=['Langflow']
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.url=https://github.com/langflow-ai/langflow
LABEL org.opencontainers.image.source=https://github.com/langflow-ai/langflow

WORKDIR /app

ENV LANGFLOW_HOST=0.0.0.0
ENV LANGFLOW_PORT=7861
ENV LANGFLOW_BACKEND_PORT=7861
ENV NGINX_PORT=7860

CMD ["/usr/local/bin/langflow-entrypoint.sh"]
