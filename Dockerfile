# Hosted Saikou API (saikou.api): verify, batch verify, check catalogue, playground.
#
#   docker build -t saikou-api .
#   docker run -p 8080:8080 -e API_TOKENS=<comma-separated tokens> saikou-api
#
# Fails closed: without API_TOKENS every authenticated endpoint answers 503. The hosted
# service never touches the file system or git; see saikou/api.py.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ENVIRONMENT=production

RUN useradd --create-home --uid 10001 saikou
WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY saikou ./saikou
RUN pip install --no-cache-dir ".[api]" && rm -rf /app/saikou /app/pyproject.toml

USER saikou
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"
CMD ["uvicorn", "saikou.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
