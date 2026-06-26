"""
Base Specialist Agent
All Layer 2 agents inherit this.
Provides: LLM access, RAG access, state access, decision engine, logging.
"""
import os, sys
from abc import ABC, abstractmethod
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from core.campaign_state   import CampaignState
from core.llm_client       import LLMClient
from core.decision_engine  import AutonomousDecisionEngine
from knowledge.qdrant.rag_retriever import RAGRetriever


class BaseAgent(ABC):
    """
    Every Layer 2 specialist agent inherits this.
    Subclasses implement: run(state) → bool
    """

    def __init__(
        self,
        name:        str,
        llm:         LLMClient,
        rag:         RAGRetriever,
        engine:      AutonomousDecisionEngine,
    ):
        self.name   = name
        self.llm    = llm
        self.rag    = rag
        self.engine = engine
        self.logger = logger.bind(agent=name)

    @abstractmethod
    def run(self, state: CampaignState) -> bool:
        """
        Execute this agent's phase.
        Returns True  → phase succeeded, advance kill chain
        Returns False → phase failed, trigger pivot logic
        """

    def log(self, msg: str):
        state_tag = f"[{self.name}]"
        logger.info(f"{state_tag} {msg}")

    def decide(self, question: str, context: str, state: CampaignState) -> dict:
        return self.engine.debate_and_decide(question, context, state)

    def query_rag(self, phase: str, context: str, top_k: int = 5) -> str:
        return self.rag.query_phase(phase, context, top_k=top_k)
