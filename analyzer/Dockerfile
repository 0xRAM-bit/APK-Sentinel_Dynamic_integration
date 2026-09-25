# APK Sentinel Analyzer Container
# This container is run with strict security constraints:
# - Non-root user
# - network_mode=none (no network access)
# - CPU and memory limits
# - No Docker socket access
# - No privileged mode
# - Read-only APK input mount
# - Controlled writable output directory
# - tmpfs for tool temp directories

FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    python3 \
    python3-pip \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install APKTool 2.10.0
RUN mkdir -p /opt/tools && \
    wget --timeout=30 --tries=2 -q https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar \
    -O /usr/local/bin/apktool.jar && \
    wget --timeout=30 --tries=2 -q https://raw.githubusercontent.com/iBotPeaches/Apktool/v2.10.0/scripts/linux/apktool \
    -O /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# Install JADX 1.5.5
RUN wget --timeout=30 --tries=2 -q https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip \
    -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    rm /tmp/jadx.zip

# Install Python dependencies for analysis scripts
COPY requirements.txt /opt/analyzer/requirements.txt
RUN pip3 install --no-cache-dir -r /opt/analyzer/requirements.txt

# Copy analysis scripts
COPY scripts/ /opt/analyzer/scripts/
COPY entrypoint.sh /opt/analyzer/entrypoint.sh
RUN chmod +x /opt/analyzer/entrypoint.sh

# Create non-root analyzer user
RUN useradd -m -s /bin/bash analyzer && \
    mkdir -p /analysis && \
    chown -R analyzer:analyzer /analysis

USER analyzer

WORKDIR /analysis

ENTRYPOINT ["/opt/analyzer/entrypoint.sh"]
