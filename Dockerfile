# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Prevent python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt .

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip

# Install CPU-only torch first to avoid massive CUDA packages and cache it
RUN pip install --no-cache-dir --default-timeout=1000 torch --index-url https://download.pytorch.org/whl/cpu

# Install the rest of the requirements
RUN pip install --no-cache-dir --default-timeout=1000 --retries 20 -r requirements.txt

# Copy the rest of the application code
COPY . .

# Convert Windows line endings to Unix line endings for entrypoint.sh and redteam.sh
RUN sed -i 's/\r$//' entrypoint.sh redteam.sh || true && \
    chmod +x entrypoint.sh redteam.sh || true

# Expose ports for lab target server
EXPOSE 8080 2222 33060 6380

# Set default entrypoint and command
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]
