# Upstream tag: python:3.13.7-slim
FROM python@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689
COPY requirements-dev.lock /tmp/requirements-dev.lock
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-dev.lock
ENV PYTHONPATH=/workspace/src:/workspace
ENV PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
ENV PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
WORKDIR /workspace
