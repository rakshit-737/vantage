# VANTAGE API + UI. The real catalog is mounted read-only at /data (build it on the host with
# `python -m vantage.download && python -m vantage.ingest.build`). Without it the offline
# seed catalog is served.
# base pinned by digest (python:3.12-slim, 2026-10-02); Dependabot bumps it
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
RUN useradd --create-home --uid 10001 vantage
WORKDIR /app
# Dependencies come from a hash-locked file (uv pip compile ... --generate-hashes; regenerate it when
# pyproject.toml changes); the package itself is installed without resolving anything else.
COPY requirements-docker.txt pyproject.toml README.md LICENSE ./
COPY vantage ./vantage
RUN pip install --no-cache-dir --require-hashes -r requirements-docker.txt \
    && pip install --no-cache-dir --no-deps .
USER vantage
ENV VANTAGE_DATA_DIR=/data VANTAGE_CATALOG=seed
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
# The API needs a bearer token: pass VANTAGE_API_TOKEN, or read the generated one from `docker logs`.
# 0.0.0.0 is the container interface only; publish it as 127.0.0.1:8000:8000 (see docker-compose.yml).
CMD ["uvicorn", "vantage.api:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--limit-concurrency", "32"]
