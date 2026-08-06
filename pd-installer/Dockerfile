FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TOOLS_DIR=/usr/local/pd_tools \
    GEM_HOME=/usr/local/pd_tools/ruby-gems \
    GEM_PATH=/usr/local/pd_tools/ruby-gems \
    PATH=/usr/local/pd_tools:/usr/local/pd_tools/venv/bin:/usr/local/pd_tools/ruby-gems/bin:$PATH

RUN mkdir -p /etc/apt/apt.conf.d && \
    echo 'Acquire::Retries "10";' > /etc/apt/apt.conf.d/80-retries && \
    echo 'Acquire::http::Timeout "30";' >> /etc/apt/apt.conf.d/80-retries && \
    echo 'Acquire::ftp::Timeout "30";' >> /etc/apt/apt.conf.d/80-retries

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    default-jre-headless \
    dirb \
    git \
    golang-go \
    jq \
    libcurl4-openssl-dev \
    libffi-dev \
    libio-socket-ssl-perl \
    libjson-pp-perl \
    libnet-ssleay-perl \
    libssl-dev \
    libxml2-dev \
    libxml-writer-perl \
    libxslt1-dev \
    nodejs \
    npm \
    pkg-config \
    ruby \
    ruby-dev \
    tar \
    unzip \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY install-tools.sh /usr/local/bin/install-tools.sh
RUN chmod +x /usr/local/bin/install-tools.sh

ENTRYPOINT ["/usr/local/bin/install-tools.sh"]
