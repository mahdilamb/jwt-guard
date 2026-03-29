FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder
WORKDIR /app
COPY pyproject.toml uv.lock /app/
RUN uv sync --no-install-project
COPY main.py .
RUN uv sync --editable

FROM python:3.13-slim-bookworm
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY *.py .
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["python", "main.py"]
