# Offline-only image for the restricted X.509 path validator.
# Dependencies are installed at build time; the runtime container has no
# network namespace (network_mode: none in compose.yaml).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for layer caching.
COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir "cryptography>=42"

# Copy the package sources and examples (no network fetch at runtime).
COPY src /app/src
COPY examples /app/examples
COPY compose/entrypoint.sh /usr/local/bin/x509path-offline
RUN chmod +x /usr/local/bin/x509path-offline \
    && pip install --no-cache-dir --no-deps -e .

ENTRYPOINT ["/usr/local/bin/x509path-offline"]
