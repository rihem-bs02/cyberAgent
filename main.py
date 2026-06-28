"""
Red Team Agent — Main Entry Point (v2 — Autonomous)
"""
import argparse, sys, os, io
from loguru import logger
from rich.console import Console

if sys.stdout.encoding and sys.stdout.encoding.upper() != "UTF-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.upper() != "UTF-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from agents.autonomous_agent import AutonomousAgent

console = Console(force_terminal=True, highlight=False)

# Resolve default Qdrant path
DEFAULT_QDRANT_PATH = os.getenv("QDRANT_PATH")
if not DEFAULT_QDRANT_PATH:
    if os.path.exists("./qdrant"):
        DEFAULT_QDRANT_PATH = "./qdrant"
    elif os.path.exists("/dataset/qdrant"):
        DEFAULT_QDRANT_PATH = "/dataset/qdrant"
    else:
        DEFAULT_QDRANT_PATH = "./qdrant"

def main():
    parser = argparse.ArgumentParser(description="Autonomous Red Team Agent")
    parser.add_argument("--target",      required=True)
    parser.add_argument("--objective",   default="")
    parser.add_argument("--stealth",     default="high", choices=["low","medium","high"])
    parser.add_argument("--qdrant-path", default=DEFAULT_QDRANT_PATH)
    parser.add_argument("--steps",       default=40, type=int)
    args = parser.parse_args()

    logger.remove()
    logger.add(sys.stderr, level="INFO",
               format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}")
    os.makedirs("logs", exist_ok=True)
    logger.add(f"logs/campaign_{args.target.replace('/','_').replace('.','_')}.log",
               level="DEBUG", rotation="10MB")

    console.print(f"\n[bold red]>> Red Team Agent Starting[/bold red]")
    console.print(f"  Target  : [cyan]{args.target}[/cyan]")
    console.print(f"  Stealth : [green]{args.stealth}[/green]")
    console.print(f"  Qdrant  : [dim]{args.qdrant_path}[/dim]\n")

    # Import MAX_STEPS and patch it
    import agents.autonomous_agent as agent_module
    agent_module.MAX_STEPS = args.steps

    agent = AutonomousAgent(qdrant_path=args.qdrant_path)
    agent.run(
        target    = args.target,
        objective = args.objective or f"Full compromise of {args.target}",
        stealth   = args.stealth,
    )

if __name__ == "__main__":
    main()
