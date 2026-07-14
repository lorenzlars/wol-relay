FROM python:3.13-alpine

WORKDIR /app
COPY relay.py .

ENTRYPOINT ["python", "-u", "/app/relay.py"]
