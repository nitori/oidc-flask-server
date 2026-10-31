FROM python:3.14-slim-trixie AS builder
COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app
# Dependencies first so this layer survives source changes.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --no-install-project
COPY pyproject.toml uv.lock README.md alembic.ini ./
COPY src/ src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable


# Same Debian and Python as the builder, so the venv's interpreter path resolves.
FROM python:3.14-slim-trixie
# psycopg is installed without its binary extra, so it needs the system's libpq.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 1000 --create-home openid
WORKDIR /app
COPY --from=builder --chown=openid:openid /app /app
RUN mkdir -p /app/var && chown openid:openid /app/var
# The executable bit set here, as git checkouts on Windows may lose it.
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint

# Logs go to var/logs relative to the working directory, uploads (profile pictures) are kept next to them.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    FLASK_UPLOAD_FOLDER=/app/var/uploads \
    FLASK_UPLOAD_URL_PATH=/uploads/ \
    PORT=8000

# Starts as root only to make the data dir writable for `openid`, then runs everything as that user.
ENTRYPOINT ["docker-entrypoint"]
VOLUME /app/var
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec serve"]
