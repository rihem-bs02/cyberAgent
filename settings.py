from dotenv import load_dotenv
import os

load_dotenv()

# ── LLM ────────────────────────────────────────────────
GROQ_API_KEY        = os.getenv("GROQ_API_KEY")
GROQ_MODEL_HEAVY    = os.getenv("GROQ_MODEL_HEAVY",  "llama-3.3-70b-versatile")
GROQ_MODEL_FAST     = os.getenv("GROQ_MODEL_FAST",   "qwen-qwq-32b")
LOCAL_MODEL         = os.getenv("LOCAL_MODEL",       "qwen")
EMBEDDING_MODEL     = os.getenv("EMBEDDING_MODEL",    "BAAI/bge-small-en-v1.5")

# ── Qdrant ─────────────────────────────────────────────
QDRANT_HOST         = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT         = int(os.getenv("QDRANT_PORT", 6333))

COLLECTIONS = {
    "mitre_attack":    os.getenv("QDRANT_COLLECTION_MITRE",    "mitre_attack"),
    "nvd_cve":         os.getenv("QDRANT_COLLECTION_CVE",       "nvd_cve"),
    "exploitdb":       os.getenv("QDRANT_COLLECTION_EXPLOITDB", "exploitdb"),
    "atomic_red_team": os.getenv("QDRANT_COLLECTION_ATOMIC",    "atomic_red_team"),
    "mitre_ics":       os.getenv("QDRANT_COLLECTION_ICS",       "mitre_ics"),
    "sigma_rules":     os.getenv("QDRANT_COLLECTION_SIGMA",     "sigma_rules"),
    "cisa_advisories": os.getenv("QDRANT_COLLECTION_CISA",      "cisa_advisories"),
}

# ── Neo4j ──────────────────────────────────────────────
NEO4J_URI           = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER          = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD      = os.getenv("NEO4J_PASSWORD", "password")

# ── NVD API ────────────────────────────────────────────
NVD_API_KEY         = os.getenv("NVD_API_KEY", "")

# ── Campaign ───────────────────────────────────────────
STEALTH_LEVEL       = os.getenv("STEALTH_LEVEL", "high")
MAX_THREADS         = int(os.getenv("MAX_THREADS", 4))
LOG_LEVEL           = os.getenv("LOG_LEVEL", "INFO")
REPORTS_DIR         = os.getenv("REPORTS_DIR", "./reports")
