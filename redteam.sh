#!/bin/bash
# ── Red Team Agent — Kali Docker Manager ─────────────────────────────────────
# One script to build, run, and manage the entire Docker stack.
# Usage:
#   ./redteam.sh build              — build the image
#   ./redteam.sh up                 — start Qdrant + Neo4j services
#   ./redteam.sh down               — stop all services
#   ./redteam.sh run 192.168.1.0/24 — run a campaign
#   ./redteam.sh shell              — open shell inside container
#   ./redteam.sh logs               — show agent logs
#   ./redteam.sh import             — import Qdrant data from Windows path
#   ./redteam.sh status             — show container status
# ─────────────────────────────────────────────────────────────────────────────

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Config ────────────────────────────────────────────────────────────────────
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
IMAGE_NAME="redteam-agent"
QDRANT_DATA_DEFAULT="./qdrant_data"

# ── Helper functions ──────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; exit 1; }

# ── Check .env ────────────────────────────────────────────────────────────────
check_env() {
    if [ ! -f "$ENV_FILE" ]; then
        warn ".env not found — creating from template"
        cat > "$ENV_FILE" << 'EOF'
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL_HEAVY=llama-3.3-70b-versatile
GROQ_MODEL_FAST=qwen
EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
STEALTH_LEVEL=high
LOG_LEVEL=INFO
NEO4J_PASSWORD=redteam2024
EOF
        error "Edit .env and add your GROQ_API_KEY, then re-run."
    fi

    if grep -q "your_groq_api_key_here" "$ENV_FILE"; then
        error "GROQ_API_KEY not set in .env. Edit it first."
    fi
    success ".env loaded"
}

# ── Commands ──────────────────────────────────────────────────────────────────

cmd_build() {
    info "Building Red Team Agent Docker image..."
    docker build -t "$IMAGE_NAME" . --no-cache
    success "Image built: $IMAGE_NAME"
}

cmd_up() {
    check_env
    info "Starting supporting services (Qdrant + Neo4j)..."
    docker compose -f "$COMPOSE_FILE" up -d qdrant neo4j
    info "Waiting for services to be healthy..."
    sleep 8
    docker compose -f "$COMPOSE_FILE" ps
    success "Services running."
    echo ""
    echo "  Qdrant UI  → http://localhost:6333/dashboard"
    echo "  Neo4j UI   → http://localhost:7474"
}

cmd_down() {
    info "Stopping all services..."
    docker compose -f "$COMPOSE_FILE" down
    success "All services stopped."
}

cmd_run() {
    check_env
    TARGET="$1"
    STEALTH="${2:-high}"
    OBJECTIVE="${3:-}"

    if [ -z "$TARGET" ]; then
        error "Usage: ./redteam.sh run <target> [stealth] [objective]
Examples:
  ./redteam.sh run 192.168.1.0/24
  ./redteam.sh run 10.10.10.50 high
  ./redteam.sh run medflow.local medium 'Compromise domain controller'"
    fi

    # Check if Qdrant data exists locally
    QDRANT_PATH="${QDRANT_DATA_PATH:-$QDRANT_DATA_DEFAULT}"
    if [ ! -d "$QDRANT_PATH" ]; then
        warn "Qdrant data not found at $QDRANT_PATH"
        warn "Set QDRANT_DATA_PATH env var to your Qdrant data directory"
        warn "Example: export QDRANT_DATA_PATH=/path/to/your/qdrant"
    fi

    info "Launching campaign against: $TARGET"
    info "Stealth: $STEALTH"

    # Run with host networking for real scanning
    docker run --rm -it \
        --name redteam_campaign_$(date +%s) \
        --env-file "$ENV_FILE" \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        --network host \
        -v "${QDRANT_PATH}:/app/qdrant_data:ro" \
        -v "$(pwd)/reports:/app/reports" \
        -v "$(pwd)/logs:/app/logs" \
        -e QDRANT_PATH=/app/qdrant_data \
        -e STEALTH_LEVEL="$STEALTH" \
        "$IMAGE_NAME" \
        --target "$TARGET" \
        --stealth "$STEALTH" \
        ${OBJECTIVE:+--objective "$OBJECTIVE"}
}

cmd_shell() {
    check_env
    info "Opening shell inside Red Team Agent container..."
    docker run --rm -it \
        --name redteam_shell \
        --env-file "$ENV_FILE" \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        --network host \
        -v "${QDRANT_DATA_PATH:-$QDRANT_DATA_DEFAULT}:/app/qdrant_data:ro" \
        -v "$(pwd)/reports:/app/reports" \
        -v "$(pwd)/logs:/app/logs" \
        -v "$(pwd):/app" \
        -e QDRANT_PATH=/app/qdrant_data \
        --entrypoint bash \
        "$IMAGE_NAME"
}

cmd_logs() {
    info "Recent campaign logs:"
    if [ -d "./logs" ]; then
        ls -lt ./logs/*.log 2>/dev/null | head -5
        LATEST=$(ls -t ./logs/*.log 2>/dev/null | head -1)
        if [ -n "$LATEST" ]; then
            tail -50 "$LATEST"
        fi
    else
        docker compose -f "$COMPOSE_FILE" logs --tail=50 redteam
    fi
}

cmd_import() {
    info "Import Qdrant data from Windows share"
    echo ""
    echo "Option 1 — Copy from Windows path (if dual boot):"
    echo "  cp -r /mnt/c/Users/rihem/Desktop/datasetAGENT/qdrant ./qdrant_data"
    echo ""
    echo "Option 2 — Copy over network (from Windows to Kali):"
    echo "  scp -r user@windows_ip:'C:/Users/rihem/Desktop/datasetAGENT/qdrant' ./qdrant_data"
    echo ""
    echo "Option 3 — USB transfer then:"
    echo "  cp -r /media/usb/qdrant ./qdrant_data"
    echo ""
    echo "Then set: export QDRANT_DATA_PATH=\$(pwd)/qdrant_data"
    echo "Then run: ./redteam.sh run 192.168.1.0/24"
}

cmd_status() {
    info "Container status:"
    docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || docker ps --filter "name=redteam"
    echo ""
    info "Reports generated:"
    ls -lh ./reports/*.json 2>/dev/null || echo "  No reports yet"
    echo ""
    info "Logs:"
    ls -lh ./logs/*.log 2>/dev/null || echo "  No logs yet"
}

cmd_clean() {
    warn "This will remove all containers and volumes. Are you sure? (y/N)"
    read -r confirm
    if [ "$confirm" = "y" ]; then
        docker compose -f "$COMPOSE_FILE" down -v
        docker rmi "$IMAGE_NAME" 2>/dev/null || true
        success "Cleaned."
    else
        info "Cancelled."
    fi
}

# ── Main dispatcher ───────────────────────────────────────────────────────────
echo ""
echo -e "${RED}╔══════════════════════════════════════╗${NC}"
echo -e "${RED}║   Red Team Agent — Docker Manager   ║${NC}"
echo -e "${RED}╚══════════════════════════════════════╝${NC}"
echo ""

case "${1:-help}" in
    build)   cmd_build ;;
    up)      cmd_up ;;
    down)    cmd_down ;;
    run)     shift; cmd_run "$@" ;;
    shell)   cmd_shell ;;
    logs)    cmd_logs ;;
    import)  cmd_import ;;
    status)  cmd_status ;;
    clean)   cmd_clean ;;
    help|*)
        echo "Usage: ./redteam.sh <command> [args]"
        echo ""
        echo "Commands:"
        echo "  build              Build the Docker image"
        echo "  up                 Start Qdrant + Neo4j services"
        echo "  down               Stop all services"
        echo "  run <target>       Run a full campaign"
        echo "  shell              Open shell inside container"
        echo "  logs               Show recent logs"
        echo "  import             Instructions to import Qdrant data"
        echo "  status             Show container + report status"
        echo "  clean              Remove all containers and volumes"
        echo ""
        echo "Examples:"
        echo "  ./redteam.sh build"
        echo "  ./redteam.sh up"
        echo "  ./redteam.sh run 192.168.1.0/24"
        echo "  ./redteam.sh run 10.10.10.50 high 'Get domain admin'"
        echo "  ./redteam.sh shell"
        ;;
esac
