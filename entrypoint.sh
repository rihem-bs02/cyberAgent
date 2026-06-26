#!/bin/bash
set -e

# Helper script for Red Team Agent Docker Entrypoint

# If no args or args start with flags, run main.py
if [ $# -eq 0 ] || [ "${1#-}" != "$1" ]; then
    # Check if --qdrant-path was passed
    has_qdrant_path=false
    for arg in "$@"; do
        if [ "$arg" = "--qdrant-path" ]; then
            has_qdrant_path=true
            break
        fi
    done

    # If --qdrant-path was not provided, and QDRANT_PATH is set in environment, append it
    if [ "$has_qdrant_path" = false ] && [ -n "$QDRANT_PATH" ]; then
        echo "Injecting default QDRANT_PATH: $QDRANT_PATH"
        exec python main.py "$@" --qdrant-path "$QDRANT_PATH"
    else
        exec python main.py "$@"
    fi
else
    # Otherwise execute whatever command was passed
    exec "$@"
fi
