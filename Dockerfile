FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MEMBER_DB_PATH=/data/members.sqlite3

WORKDIR /app

COPY member_auth/requirements.txt /app/member_auth/requirements.txt
RUN pip install --no-cache-dir -r /app/member_auth/requirements.txt \
    && useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data

COPY member_auth /app/member_auth
COPY docs /app/docs

USER appuser
EXPOSE 8000
CMD ["sh", "-c", "uvicorn member_auth.app:app --host 0.0.0.0 --port ${PORT:-8000}"]