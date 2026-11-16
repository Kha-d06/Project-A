# One image for the API, the scan worker and the scheduler; Compose picks the command.
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin sentinel \
    && mkdir -p /var/lib/sentinel/uploads \
    && chown sentinel:sentinel /var/lib/sentinel/uploads \
    && chmod 700 /var/lib/sentinel/uploads

WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
RUN pip install .

COPY alembic.ini ./
COPY alembic ./alembic

USER sentinel
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
