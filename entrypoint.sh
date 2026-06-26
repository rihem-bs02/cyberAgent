#!/bin/bash
# ── Red Team Agent — Docker Entrypoint ───────────────────────────────────────
# Handles startup checks before launching the agent.
# ─────────────────────────────────────────────────────────────────────────────

set -e

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     Red Team Agent — Docker Container        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Check GROQ_API_KEY ────────────────────────────────────────────────────────
if [ -z "$GROQ_API_KEY" ] || [ "$GROQ_API_KEY" = "your_groq_api_key_here" ]; then
    echo "ERROR: GROQ_API_KEY not set."
    echo "Set it in your .env file or pass it with:"
    echo "  docker run -e GROQ_API_KEY=your_key ..."
    exit 1
fi
echo "[OK] GROQ_API_KEY found"

# ── Wait for Qdrant ───────────────────────────────────────────────────────────
if [ -n "$QDRANT_HOST" ] && [ "$QDRANT_HOST" != "localhost" ]; then
    echo "[..] Waiting for Qdrant at $QDRANT_HOST:$QDRANT_PORT..."
    for i in $(seq 1 30); do
        if curl -sf "http://$QDRANT_HOST:$QDRANT_PORT/healthz" > /dev/null 2>&1; then
            echo "[OK] Qdrant ready"
            break
        fi
        sleep 2
    done
fi

# ── Wait for Neo4j ────────────────────────────────────────────────────────────
if [ -n "$NEO4J_URI" ]; then
    echo "[..] Waiting for Neo4j..."
    sleep 5
    echo "[OK] Neo4j ready (assumed)"
fi

# ── Check nmap ────────────────────────────────────────────────────────────────
if command -v nmap &> /dev/null; then
    echo "[OK] nmap available: $(nmap --version | head -1)"
else
    echo "[WARN] nmap not found — TCP fallback will be used"
fi

# ── Set Qdrant path ───────────────────────────────────────────────────────────
# Priority: env var → mounted volume → default
if [ -z "$QDRANT_PATH" ]; then
    if [ -d "/app/qdrant_data" ]; then
        export QDRANT_PATH="/app/qdrant_data"
    else
        export QDRANT_PATH="/app/data/qdrant"
    fi
fi
echo "[OK] Qdrant data path: $QDRANT_PATH"

echo ""
echo "Starting Red Team Agent..."
echo ""

# ── Launch ────────────────────────────────────────────────────────────────────
exec python3.11 main.py "$@"