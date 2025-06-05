FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create a non-root user and set permissions
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import requests; import os; url=os.environ.get('HEALTHCHECK_URL', 'http://localhost:8000/health'); print(requests.get(url).status_code)"]

ENTRYPOINT ["python", "app.py"]
