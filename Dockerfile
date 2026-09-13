# Multi-stage Dockerfile for Q-Shield PQC Suite
FROM python:3.11-slim

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree
COPY . .

# Expose Streamlit dashboard and PQC TCP socket port
EXPOSE 8501 9123

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default entrypoint starts the Streamlit dashboard
CMD ["streamlit", "run", "faz4_dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
