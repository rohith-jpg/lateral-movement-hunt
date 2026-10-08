FROM python:3.12.10-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
COPY src ./src
COPY data ./data
RUN mkdir /app/results && chown -R 10001:10001 /app
USER 10001:10001
ENTRYPOINT ["python", "-m", "lateral_hunt"]
