"""
CVE Lookup Tool
Matches discovered services/versions to known CVEs.
Two sources:
  1. Local Qdrant RAG (cisa_advisories collection) — fast, offline
  2. NVD API — live, comprehensive
"""
import requests
import time
import os, sys
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import NVD_API_KEY


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVETool:

    def __init__(self, rag_retriever=None):
        self.rag = rag_retriever
        self.headers = {}
        if NVD_API_KEY:
            self.headers["apiKey"] = NVD_API_KEY
        self._cache = {}

    def lookup_service(
        self,
        product: str,
        version: str = "",
        top_k:   int = 5,
    ) -> list[dict]:
        """
        Find CVEs for a specific product/version combo.
        Returns list of CVE dicts sorted by CVSS score descending.
        """
        cache_key = f"{product}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results = []

        # ── Source 1: Local RAG (fast) ────────────────────────────
        if self.rag:
            query = f"{product} {version} vulnerability CVE".strip()
            rag_results = self.rag.query(
                query_text=query,
                phase="scanning",
                top_k=top_k,
            )
            for r in rag_results:
                meta = r["metadata"]
                if meta.get("cve_id") or meta.get("vulnerability_name"):
                    results.append({
                        "source":      "rag_local",
                        "cve_id":      meta.get("cve_id", ""),
                        "title":       meta.get("vulnerability_name", meta.get("title", "")),
                        "description": meta.get("short_description", r["text"][:300]),
                        "cvss_score":  meta.get("cvss_score", 0.0),
                        "product":     meta.get("product", product),
                        "severity":    self._cvss_to_severity(meta.get("cvss_score", 0)),
                        "score":       r["score"],
                    })

        # ── Source 2: NVD API (live) ──────────────────────────────
        try:
            params = {
                "keywordSearch": f"{product} {version}".strip(),
                "resultsPerPage": top_k,
                "cvssV3Severity": "HIGH",
            }
            resp = requests.get(
                NVD_API, params=params,
                headers=self.headers, timeout=15
            )
            if resp.status_code == 200:
                for item in resp.json().get("vulnerabilities", []):
                    cve   = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    descs = cve.get("descriptions", [])
                    desc  = next(
                        (d["value"] for d in descs if d.get("lang") == "en"), ""
                    )
                    metrics = cve.get("metrics", {})
                    score   = 0.0
                    for key in ("cvssMetricV31", "cvssMetricV30"):
                        if key in metrics and metrics[key]:
                            score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                            break
                    results.append({
                        "source":      "nvd_live",
                        "cve_id":      cve_id,
                        "title":       cve_id,
                        "description": desc[:400],
                        "cvss_score":  score,
                        "product":     product,
                        "severity":    self._cvss_to_severity(score),
                        "score":       score / 10,
                    })
            time.sleep(0.6)  # NVD rate limit
        except Exception as e:
            logger.warning(f"NVD API lookup failed for {product}: {e}")

        # Sort by CVSS score, deduplicate by CVE ID
        seen_cves = set()
        deduped   = []
        for r in sorted(results, key=lambda x: x["cvss_score"], reverse=True):
            cve_id = r.get("cve_id", "")
            if cve_id and cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            deduped.append(r)

        self._cache[cache_key] = deduped[:top_k]
        return deduped[:top_k]

    def lookup_port_service(self, port: int, service: str) -> list[dict]:
        """Quick lookup by port+service name for common services."""
        service_map = {
            21:    "ftp",
            22:    "openssh",
            23:    "telnet",
            25:    "smtp",
            80:    "apache nginx http",
            110:   "pop3",
            135:   "msrpc windows",
            139:   "smb netbios",
            143:   "imap",
            443:   "ssl https",
            445:   "smb windows",
            1433:  "mssql microsoft sql server",
            1521:  "oracle database",
            3306:  "mysql mariadb",
            3389:  "rdp remote desktop windows",
            5432:  "postgresql",
            5900:  "vnc",
            6379:  "redis",
            8080:  "tomcat http proxy",
            8443:  "https tomcat",
            9200:  "elasticsearch",
            27017: "mongodb",
        }
        query_term = service_map.get(port, service)
        return self.lookup_service(query_term, top_k=3)

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0:    return "low"
        return "info"
