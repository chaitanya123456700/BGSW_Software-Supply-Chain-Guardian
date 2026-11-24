FROM anchore/syft:v1.57.2 AS syft
FROM node:22-bookworm-slim AS node
FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
WORKDIR /app
COPY requirements.lock /tmp/guardian-requirements.lock
RUN python -m pip install --no-cache-dir -r /tmp/guardian-requirements.lock && python -m pip check
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "uvicorn", "guardian.app:app", "--host", "0.0.0.0", "--port", "8000"]
