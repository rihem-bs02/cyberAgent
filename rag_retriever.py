"""
Unified RAG Retriever
Each collection lives in its own Qdrant local database (sub-directory).
Opens a separate QdrantClient per sub-directory and queries the correct
collection name inside it.
"""
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer
from loguru import logger
from typing import Optional
import os, sys

sys.path.insert(0, os.path.dirname(__file__))
from config.settings import EMBEDDING_MODEL

# ── Collection registry ────────────────────────────────────────────────────────
# Maps logical name → (sub-directory name, actual Qdrant collection name inside it)
COLLECTIONS = {
    "mitre_attack":      ("qdrant_attack_enterprise", "mitre_attack_enterprise"),
    "exploitdb":         ("exploitdb",                "exploitdb"),
    "metasploit":        ("metasploit",               "metasploit"),
    "atomic_red_team":   ("atomic_red_team",          "atomic_red_team"),
    "sigma_rules":       ("sigma_rules",              "sigma_rules"),
    "kali_tools":        ("kali_tools",               "kali_tools"),
    "cisa_advisories":   ("qdrant_cisa_advisories",   "cisa_advisories"),
    "reverse_shells":    ("reverse_shells",            "reverse_shells"),
    "mitre_ics":         ("mitre_ics",                "mitre_ics"),
    "payloads":          ("payloads_all_things",       "payloads_all_things"),
}

# ── Phase → collections mapping ───────────────────────────────────────────────
PHASE_COLLECTIONS = {
    "recon":        ["mitre_attack", "kali_tools", "cisa_advisories"],
    "scanning":     ["cisa_advisories", "mitre_attack", "kali_tools"],
    "exploitation": ["exploitdb", "metasploit", "atomic_red_team", "payloads", "mitre_attack"],
    "privesc":      ["atomic_red_team", "metasploit", "kali_tools", "mitre_attack"],
    "persistence":  ["atomic_red_team", "reverse_shells", "metasploit", "mitre_attack"],
    "exfil":        ["reverse_shells", "payloads", "mitre_attack"],
    "evasion":      ["sigma_rules", "mitre_attack"],
    "ics":          ["mitre_ics", "mitre_attack"],
    "all":          list(COLLECTIONS.keys()),
}


class RAGRetriever:
    """
    Single entry point for all RAG queries.
    Each collection is its own Qdrant local database stored in a sub-directory.

    Usage:
        rag = RAGRetriever(qdrant_path="C:/Users/rihem/Desktop/datasetAGENT/qdrant")
        results = rag.query("privilege escalation windows", phase="privesc", top_k=5)
    """

    def __init__(self, qdrant_path: str):
        """
        qdrant_path: absolute path to the parent qdrant data folder
        e.g. C:/Users/rihem/Desktop/datasetAGENT/qdrant
        Each sub-directory inside is a separate Qdrant database.
        """
        self.qdrant_path = qdrant_path
        logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        self.embedder = SentenceTransformer(EMBEDDING_MODEL)

        # Build one QdrantClient per sub-directory database
        self._clients: dict[str, tuple[QdrantClient, str]] = {}  # logical → (client, collection_name)
        self._init_clients()

    def _init_clients(self):
        """Open a QdrantClient for each sub-directory and verify its collection."""
        missing = []
        for logical, (subdir, collection_name) in COLLECTIONS.items():
            db_path = os.path.join(self.qdrant_path, subdir)
            if not os.path.isdir(db_path):
                missing.append(f"{logical} (folder missing: {subdir})")
                continue
            try:
                client = QdrantClient(path=db_path)
                existing = {c.name for c in client.get_collections().collections}
                if collection_name not in existing:
                    missing.append(f"{logical} (collection '{collection_name}' not in {subdir}; found: {existing})")
                    client.close()
                    continue
                self._clients[logical] = (client, collection_name)
            except Exception as e:
                missing.append(f"{logical} ({e})")

        if missing:
            logger.warning(f"Unavailable collections ({len(missing)}): {missing}")
        available = list(self._clients.keys())
        if available:
            logger.success(f"RAG ready — {len(available)}/{len(COLLECTIONS)} collections: {available}")
        else:
            logger.error("No Qdrant collections available — RAG will return empty results.")

    @staticmethod
    def _extract_text(payload: dict) -> str:
        """
        Extract the best available text from a Qdrant payload.
        Handles varied schemas across collections — some store full_doc as a dict,
        others as a string. text_for_embedding is always a string when present.
        """
        # Priority 1: text_for_embedding (always a reliable string field)
        tfe = payload.get("text_for_embedding")
        if isinstance(tfe, str) and tfe:
            return tfe

        # Priority 2: full_doc — may be str or dict
        full_doc = payload.get("full_doc")
        if isinstance(full_doc, str) and full_doc:
            return full_doc
        if isinstance(full_doc, dict):
            # Try to get the best text from inside the dict
            for sub_key in ("text_for_embedding", "description", "content_preview", "short_description"):
                sub_val = full_doc.get(sub_key)
                if isinstance(sub_val, str) and sub_val:
                    return sub_val
            # Last resort: serialize the dict
            import json
            return json.dumps(full_doc, default=str)

        # Priority 3: other common text fields
        for field in ("description", "command", "payload", "content_preview", "short_description"):
            val = payload.get(field)
            if isinstance(val, str) and val:
                return val

        return ""

    def query(
        self,
        query_text: str,
        phase: str = "all",
        top_k: int = 5,
        score_threshold: float = 0.35,
        collections_override: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Query relevant collections for a given kill chain phase.

        Returns list of:
        {
            "collection": str,
            "score":      float,
            "text":       str,
            "metadata":   dict,
        }
        """
        target_keys = collections_override or PHASE_COLLECTIONS.get(phase, PHASE_COLLECTIONS["all"])

        # Embed query once
        vector = self.embedder.encode(
            query_text, normalize_embeddings=True
        ).tolist()

        all_results = []
        for key in target_keys:
            if key not in self._clients:
                continue
            client, collection_name = self._clients[key]
            try:
                result = client.query_points(
                    collection_name=collection_name,
                    query=vector,
                    limit=top_k,
                    score_threshold=score_threshold,
                    with_payload=True,
                )
                for hit in result.points:
                    payload = hit.payload or {}
                    text = self._extract_text(payload)
                    all_results.append({
                        "collection": key,
                        "score":      round(hit.score, 4),
                        "text":       text[:2000],
                        "metadata":   payload,
                    })
            except Exception as e:
                logger.warning(f"Query failed on {collection_name}: {e}")

        # Sort by score descending, deduplicate by text prefix
        all_results.sort(key=lambda x: x["score"], reverse=True)
        seen, deduped = set(), []
        for r in all_results:
            key_str = r["text"][:120]
            if key_str not in seen:
                seen.add(key_str)
                deduped.append(r)

        return deduped[:top_k * len(target_keys)]

    def query_phase(self, phase: str, context: str, top_k: int = 5) -> str:
        """
        Convenience method — returns formatted string for agent prompt injection.
        """
        results = self.query(context, phase=phase, top_k=top_k)
        if not results:
            return "No relevant knowledge found."

        lines = [f"[RAG — {phase.upper()} phase | {len(results)} results]\n"]
        for i, r in enumerate(results, 1):
            meta = r["metadata"]
            source_id = (
                meta.get("attack_id")
                or meta.get("cve_id")
                or meta.get("exploit_id")
                or meta.get("technique_id")
                or meta.get("title")
                or r["collection"]
            )
            lines.append(
                f"[{i}] [{r['collection']}] {source_id} (score={r['score']})\n"
                f"{r['text'][:600]}\n"
            )
        return "\n".join(lines)

    def get_evasion_context(self, technique_id: str) -> str:
        """
        Special query: given an ATT&CK technique ID,
        return Sigma rules that detect it so the agent can evade them.
        """
        results = self.query(
            query_text=f"detection rule {technique_id}",
            phase="evasion",
            top_k=3,
        )
        if not results:
            return f"No detection rules found for {technique_id} — proceed normally."

        lines = [f"[DETECTION AWARENESS — {technique_id}]"]
        for r in results:
            title = r["metadata"].get("title", "unknown rule")
            level = r["metadata"].get("level", "?")
            lines.append(f"- Sigma rule: {title} (level={level})\n  {r['text'][:300]}")
        return "\n".join(lines)

    def close(self):
        """Close all open Qdrant client connections."""
        for logical, (client, _) in self._clients.items():
            try:
                client.close()
            except Exception:
                pass
        self._clients.clear()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass  # suppress ImportError during Python interpreter shutdown
