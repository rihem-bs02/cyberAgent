"""
Red Team Agent — Main Entry Point
Usage:
    python main.py --target 192.168.1.0/24
    python main.py --target medflow.local --stealth high
    python main.py --target 10.10.10.50 --objective "Compromise domain controller"
"""
import argparse, sys, os, io
from loguru import logger
from rich.console import Console

# ── Force UTF-8 output on Windows to avoid CP1252 UnicodeEncodeError ─────────
if sys.stdout.encoding and sys.stdout.encoding.upper() != "UTF-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.upper() != "UTF-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Add project root to path ──────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from agents.orchestrator.campaign_orchestrator import CampaignOrchestrator
from config.settings import STEALTH_LEVEL

console = Console(force_terminal=True, highlight=False)

# ── IMPORTANT: update this to your actual Qdrant data path ───────────────────
DEFAULT_QDRANT_PATH = "/dataset/qdrant"


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Red Team Agent — MedFlow Healthcare Infrastructure"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target IP, subnet, hostname, or CIDR (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--objective", default="",
        help="Campaign objective (default: full compromise)"
    )
    parser.add_argument(
        "--stealth", default=STEALTH_LEVEL, choices=["low", "medium", "high"],
        help="Stealth level (default: high)"
    )
    parser.add_argument(
        "--qdrant-path", default=DEFAULT_QDRANT_PATH,
        help="Path to your local Qdrant data directory"
    )
    args = parser.parse_args()

    # ── Configure logging ─────────────────────────────────────────────────────
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}")
    logger.add(
        f"logs/campaign_{args.target.replace('/', '_').replace('.', '_')}.log",
        level="DEBUG", rotation="10 MB"
    )
    os.makedirs("logs", exist_ok=True)

    # ── Run ───────────────────────────────────────────────────────────────────
    console.print(f"\n[bold red]>> Red Team Agent Starting[/bold red]")
    console.print(f"  Target      : [cyan]{args.target}[/cyan]")
    console.print(f"  Stealth     : [green]{args.stealth}[/green]")
    console.print(f"  Qdrant path : [dim]{args.qdrant_path}[/dim]\n")

    orchestrator = CampaignOrchestrator(
        qdrant_path=args.qdrant_path,
        stealth_level=args.stealth,
    )
    state = orchestrator.run(
        target_input=args.target,
        objective=args.objective,
    )

    sys.exit(0 if state.current_phase.value == "complete" else 1)


if __name__ == "__main__":
    main()
