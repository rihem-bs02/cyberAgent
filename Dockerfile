
# ── Red Team Agent — Dockerfile ───────────────────────────────────────────────
# Base: Kali Linux rolling (has nmap, netcat, curl pre-available)
# Python: 3.11 pinned explicitly
# ─────────────────────────────────────────────────────────────────────────────
 
FROM kalilinux/kali-rolling:latest
 
# ── Metadata ──────────────────────────────────────────────────────────────────
LABEL maintainer="RedTeam Agent"
LABEL description="Autonomous AI Red Team Agent — MedFlow Healthcare"
LABEL version="2.0"
 
# ── Avoid interactive prompts during apt ──────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
 
# ── Install system dependencies ───────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python 3.11
    python3 \
    python3-dev \
    python3-venv \
    python3-pip \
    # Security tools
    nmap \
    netcat-openbsd \
    curl \
    wget \
    git \
    # Build tools (needed for some pip packages)
    build-essential \
    libssl-dev \
    libffi-dev \
    # Network tools
    dnsutils \
    iputils-ping \
    net-tools \
    # Utilities
    jq \
    nano \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
 
# ── Set Python 3.11 as default ────────────────────────────────────────────────
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python  python  /usr/bin/python3.11 1
 
# ── Upgrade pip ───────────────────────────────────────────────────────────────
RUN python3.11 -m pip install --upgrade pip setuptools wheel --break-system-packages
 
# ── Set working directory ─────────────────────────────────────────────────────
WORKDIR /app
 
# ── Install Python dependencies first (layer cache optimization) ──────────────
COPY requirements.txt .
RUN python3.11 -m pip install -r requirements.txt --break-system-packages
 
# ── Copy project files ────────────────────────────────────────────────────────
COPY . .
 
# ── Create necessary directories ──────────────────────────────────────────────
RUN mkdir -p /app/reports \
             /app/logs \
             /app/data/raw \
             /app/data/processed
 
# ── Set nmap capabilities (allows SYN scan without full root) ─────────────────
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true
 
# ── Default entrypoint ────────────────────────────────────────────────────────
ENTRYPOINT ["python3.11", "main.py"]
CMD ["--help"]