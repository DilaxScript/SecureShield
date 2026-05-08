FROM node:20-bookworm-slim AS frontend-build

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


FROM docker:27-cli AS docker-cli


FROM aquasec/trivy:0.64.1 AS trivy-bin


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    TRIVY_CACHE_DIR=/var/lib/trivy

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=trivy-bin /usr/local/bin/trivy /usr/local/bin/trivy

COPY requirements.txt pyproject.toml setup.py ./
COPY secureshield ./secureshield

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir .

COPY --from=frontend-build /app/frontend/dist ./secureshield/web/static

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()" || exit 1

CMD ["uvicorn", "secureshield.web.api:app", "--host", "0.0.0.0", "--port", "8000"]
