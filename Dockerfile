FROM python:3.12-slim AS base
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[dashboard,hitl]"

EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import agentshield; print('ok')" || exit 1

CMD ["python", "-m", "agentshield.server"]
