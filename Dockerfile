FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md guard.config.example.json ./
COPY guard ./guard
RUN pip install --no-cache-dir . && useradd -m runner
USER runner
ENTRYPOINT ["guard"]
