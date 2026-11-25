# One image for the API, the scan worker and the scheduler; Compose picks the command.
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# libseccomp: the parser jail (app/sandbox) loads its syscall allowlist through it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libseccomp2 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin sentinel \
    && mkdir -p /var/lib/sentinel/uploads \
    && chown sentinel:sentinel /var/lib/sentinel/uploads \
    && chmod 700 /var/lib/sentinel/uploads

WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
# Build with --build-arg WITH_BROWSER=true to include the isolated headless browser
# used by the website analyzer. It adds about 400 MB to the image.
ARG WITH_BROWSER=false
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN if [ "$WITH_BROWSER" = "true" ]; then \
        pip install ".[browser]" && python -m playwright install --with-deps chromium; \
    else \
        pip install .; \
    fi

COPY alembic.ini ./
COPY alembic ./alembic

USER sentinel
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
