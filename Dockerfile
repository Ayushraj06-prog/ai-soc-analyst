FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data /tmp/app \
    && chown -R 10001:10001 /app /data /tmp/app

USER 10001:10001
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "deployment.entrypoint"]
