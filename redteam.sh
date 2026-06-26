#!/bin/bash
# Red Team Agent Docker Helper Script

set -e

show_help() {
    echo "Usage: ./redteam.sh [command] [args...]"
    echo ""
    echo "Commands:"
    echo "  build       Build the docker images"
    echo "  up          Start neo4j and the lab target server in the background"
    echo "  run [args]  Run the Red Team Agent container with custom arguments"
    echo "              Example: ./redteam.sh run --target lab-target"
    echo "  down        Stop and clean up all containers"
    echo "  status      Show status of running services"
    echo "  logs        Show logs from all running containers"
    echo "  help        Show this help message"
}

case "$1" in
    build)
        docker compose build
        ;;
    up)
        echo "Starting Neo4j and Lab Target Server..."
        docker compose up -d neo4j lab-target
        echo "Services started successfully."
        ;;
    run)
        shift
        docker compose run --rm redteam-agent "$@"
        ;;
    down)
        echo "Stopping all containers..."
        docker compose down
        ;;
    status)
        docker compose ps
        ;;
    logs)
        shift
        docker compose logs -f "$@"
        ;;
    *)
        show_help
        ;;
esac
