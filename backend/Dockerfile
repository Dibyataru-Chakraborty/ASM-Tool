FROM golang:alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git libpcap-dev gcc musl-dev

# Copy and run the ProjectDiscovery installation script
COPY scripts/install_pd_tools.sh /install_pd_tools.sh
RUN chmod +x /install_pd_tools.sh && /install_pd_tools.sh

# Stage 2: Final runtime Python image
FROM python:3.12-slim

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/usr/local/pd_tools:$PATH \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directory and copy compiled Go tools from builder
RUN mkdir -p /usr/local/pd_tools
COPY --from=go-builder /usr/local/bin/pd/* /usr/local/pd_tools/

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
