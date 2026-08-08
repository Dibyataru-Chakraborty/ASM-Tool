FROM python:3.12-slim

# System deps — nmap, chromium for gowitness screenshots, libpcap for naabu, golang for tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    chromium \
    chromium-driver \
    curl wget git \
    libpq-dev gcc \
    libpcap-dev \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools and gowitness
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/sensepost/gowitness@latest && \
    cp /root/go/bin/* /usr/local/bin/ && \
    rm -rf /root/go /root/.cache

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/screenshots /app/logs

RUN useradd -m -u 1000 asmuser && chown -R asmuser:asmuser /app
USER asmuser

ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CHROME_BIN=/usr/bin/chromium

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
