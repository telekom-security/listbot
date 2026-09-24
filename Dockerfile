# syntax=docker/dockerfile:1.7

FROM python:3.14-slim AS runtime

COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /uvx /usr/local/bin/

ARG LISTBOT_UID=1000
ARG LISTBOT_GID=1000

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

RUN groupadd --gid "${LISTBOT_GID}" listbot \
    && useradd --uid "${LISTBOT_UID}" --gid "${LISTBOT_GID}" --home-dir /app --shell /usr/sbin/nologin listbot \
    && mkdir -p /config /data /cache/listbot

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY assets ./assets
COPY src ./src

RUN uv sync --frozen --no-dev --python 3.14 \
    && uv cache clean \
    && chown -R "${LISTBOT_UID}:0" /config /data /cache \
    && chmod -R g=u /config /data /cache

COPY --chown=${LISTBOT_UID}:0 config.toml /config/listbot.toml

# Numeric so Kubernetes runAsNonRoot can verify it. Writable dirs are owned by
# group 0 as well, so pods running with an arbitrary UID in group 0 still work.
USER ${LISTBOT_UID}:${LISTBOT_GID}

ENTRYPOINT ["listbot"]
CMD ["run", "--config", "/config/listbot.toml", "--output-dir", "/data", "--cache-dir", "/cache/listbot"]
