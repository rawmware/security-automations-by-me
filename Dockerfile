FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Non-root runtime user (least privilege).
RUN useradd --create-home --shell /usr/sbin/nologin sentinel

COPY requirements.txt pyproject.toml ./
COPY src/ ./src/
COPY config/ ./config/
RUN pip install --no-cache-dir -e .

# Writable at runtime: state (incl. SQLite), reports, and the mounted auth log.
RUN mkdir -p /app/state /app/reports && chown -R sentinel:sentinel /app
USER sentinel

VOLUME ["/app/state", "/app/reports"]
EXPOSE 8000

ENTRYPOINT ["sentinel"]
CMD ["web", "--host", "0.0.0.0", "--port", "8000", "--config", "/app/config/automations.yaml"]
