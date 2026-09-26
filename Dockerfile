# VANTAGE API + UI. The real catalog is mounted read-only at /data (build it on the host with
# `python scripts/download_data.py && python -m vantage.ingest.build`). Without it the offline
# seed catalog is served.
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 vantage
WORKDIR /app
COPY pyproject.toml README.md ./
COPY vantage ./vantage
COPY examples ./examples
RUN pip install --no-cache-dir ".[api,report]"
USER vantage
ENV VANTAGE_DATA_DIR=/data VANTAGE_CATALOG=seed
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "vantage.api:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000"]
