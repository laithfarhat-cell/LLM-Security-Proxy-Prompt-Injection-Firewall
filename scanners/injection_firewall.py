from __future__ import annotations

import base64
import codecs
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    from sentence_transformers import SentenceTransformer
except ImportError:  # pragma: no cover
    SentenceTransformer = None  # type: ignore[assignment]


ZERO_WIDTH_AND_BIDI_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\U000e0000-\U000e007f]"
)

DELIMITER_PATTERNS = [
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|endoftext\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    r"###\s*System\s*:",
    r"###\s*Instruction\s*:",
]
DELIMITER_RE = re.compile("|".join(DELIMITER_PATTERNS), re.IGNORECASE)

OVERRIDE_PATTERNS = [
    r"\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules|prompts?)\b",
    r"\bdisregard\s+(your\s+)?(system\s+prompt|instructions|rules|guidelines)\b",
    r"\bforget\s+(everything|all)\s+(you\s+were\s+told|above|before)\b",
    r"\byou\s+are\s+now\s+(DAN|in\s+developer\s+mode|unrestricted)\b",
    r"\boverride\s+(safety|security|ethical)\s+(protocols?|filters?|rules?)\b",
    r"\brepeat\s+(the\s+exact\s+text\s+of\s+)?your\s+system\s+prompt\b",
    r"\bprint\s+your\s+(initial|system)\s+(instructions|prompt)\b",
]
OVERRIDE_RE = re.compile("|".join(OVERRIDE_PATTERNS), re.IGNORECASE)

BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
HEX_CANDIDATE_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{20,}\b")
ROT13_HINT_RE = re.compile(r"\b(?:rot13|caesar)\b", re.IGNORECASE)


@dataclass
class InjectionScanResult:
    risk_score: float
    lexical_score: float
    semantic_score: float
    categories: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    top_corpus_match: Optional[str] = None
    latency_ms: float = 0.0
    stage1_ms: float = 0.0
    stage2_ms: float = 0.0


class _FallbackHashEmbedder:
    """Deterministic lightweight n-gram hashing embedder used only if HuggingFace weights are unavailable."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    def encode(
        self,
        sentences: List[str],
        normalize_embeddings: bool = True,
        show_progress_bar: bool = False,
    ) -> np.ndarray:
        vecs = np.zeros((len(sentences), self.dim), dtype=np.float32)
        for idx, text in enumerate(sentences):
            lowered = text.lower()
            for n in (3, 4):
                for i in range(max(0, len(lowered) - n + 1)):
                    gram = lowered[i : i + n]
                    h = hash(gram) % self.dim
                    vecs[idx, h] += 1.0
            for word in re.findall(r"\w+", lowered):
                h = hash(word) % self.dim
                vecs[idx, h] += 2.0
        if normalize_embeddings:
            norms = np.linalg.norm(vecs, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            vecs = vecs / norms
        return vecs


class InjectionFirewall:
    def __init__(
        self,
        corpus_path: str | Path = "data/attack_corpus.json",
        model_name: str = "all-MiniLM-L6-v2",
        lexical_weight: float = 0.45,
        semantic_weight: float = 0.55,
        canary_prefix: str = "CANARY-",
    ) -> None:
        self.lexical_weight = lexical_weight
        self.semantic_weight = semantic_weight
        self.canary_prefix = canary_prefix
        self.corpus_entries = self._load_corpus(Path(corpus_path))
        self.embedder = self._init_embedder(model_name)
        self.corpus_texts = [entry["text"] for entry in self.corpus_entries]
        if self.corpus_texts:
            self.corpus_embeddings = self.embedder.encode(
                self.corpus_texts, normalize_embeddings=True, show_progress_bar=False
            )
        else:
            self.corpus_embeddings = np.zeros((0, 384), dtype=np.float32)

    @staticmethod
    def _load_corpus(path: Path) -> List[Dict[str, str]]:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("patterns", [])

    @staticmethod
    def _init_embedder(model_name: str) -> Any:
        if SentenceTransformer is not None:
            try:
                return SentenceTransformer(model_name)
            except Exception:
                pass
        return _FallbackHashEmbedder()

    @staticmethod
    def _is_printable_ascii(text: str) -> bool:
        if not text:
            return False
        printable = sum(1 for ch in text if 32 <= ord(ch) <= 126 or ch in "\n\r\t")
        return (printable / len(text)) > 0.85

    def _decode_obfuscated_substrings(self, text: str, depth: int = 0) -> List[str]:
        if depth >= 2:
            return []
        decoded_chunks: List[str] = []

        for match in BASE64_CANDIDATE_RE.findall(text):
            try:
                raw = base64.b64decode(match, validate=True)
                decoded = raw.decode("utf-8", errors="strict")
                if self._is_printable_ascii(decoded) and len(decoded.strip()) >= 6:
                    decoded_chunks.append(decoded)
                    decoded_chunks.extend(self._decode_obfuscated_substrings(decoded, depth + 1))
            except Exception:
                continue

        for match in HEX_CANDIDATE_RE.findall(text):
            cleaned = match[2:] if match.lower().startswith("0x") else match
            if len(cleaned) % 2 != 0:
                continue
            try:
                decoded = bytes.fromhex(cleaned).decode("utf-8", errors="strict")
                if self._is_printable_ascii(decoded) and len(decoded.strip()) >= 6:
                    decoded_chunks.append(decoded)
            except Exception:
                continue

        if ROT13_HINT_RE.search(text):
            rot = codecs.decode(text, "rot_13")
            if rot != text:
                decoded_chunks.append(rot)

        return decoded_chunks

    def _stage1_lexical_scan(self, text: str) -> Tuple[float, List[str], List[str], List[str]]:
        score = 0.0
        rules: List[str] = []
        categories: List[str] = []

        if ZERO_WIDTH_AND_BIDI_RE.search(text):
            score += 0.45
            rules.append("unicode_smuggling")
            categories.append("obfuscation")

        if DELIMITER_RE.search(text):
            score += 0.70
            rules.append("delimiter_spoofing")
            categories.append("direct_injection")

        if OVERRIDE_RE.search(text):
            score += 0.65
            rules.append("override_signature")
            categories.append("direct_injection")

        decoded_chunks = self._decode_obfuscated_substrings(text)
        for chunk in decoded_chunks:
            if DELIMITER_RE.search(chunk) or OVERRIDE_RE.search(chunk):
                score += 0.70
                rules.append("encoded_injection")
                categories.append("obfuscation")
                break

        return min(score, 1.0), rules, categories, decoded_chunks

    @staticmethod
    def _sliding_sentences(text: str, window_words: int = 18, stride: int = 9) -> List[str]:
        words = text.split()
        if len(words) <= window_words:
            return [text] if text.strip() else []
        chunks: List[str] = []
        for i in range(0, len(words), stride):
            chunk = " ".join(words[i : i + window_words])
            chunks.append(chunk)
            if i + window_words >= len(words):
                break
        return chunks

    def _stage2_semantic_scan(self, texts: List[str]) -> Tuple[float, Optional[str], Optional[str]]:
        if not texts or self.corpus_embeddings.shape[0] == 0:
            return 0.0, None, None

        windows: List[str] = []
        for t in texts:
            windows.extend(self._sliding_sentences(t))
        if not windows:
            return 0.0, None, None

        query_embs = self.embedder.encode(
            windows, normalize_embeddings=True, show_progress_bar=False
        )
        sim_matrix = np.matmul(query_embs, self.corpus_embeddings.T)
        max_idx = np.unravel_index(np.argmax(sim_matrix), sim_matrix.shape)
        max_sim = float(sim_matrix[max_idx])
        matched_entry = self.corpus_entries[int(max_idx[1])]
        return max(0.0, min(1.0, max_sim)), matched_entry["id"], matched_entry["category"]

    def scan_prompt(self, text: str) -> InjectionScanResult:
        t0 = time.perf_counter()
        lex_score, rules, categories, decoded_chunks = self._stage1_lexical_scan(text)
        t1 = time.perf_counter()

        texts_for_semantic = [text] + decoded_chunks
        sem_score, top_id, top_cat = self._stage2_semantic_scan(texts_for_semantic)
        t2 = time.perf_counter()

        if top_cat and sem_score >= 0.55 and top_cat not in categories:
            categories.append(top_cat)
        if top_id and sem_score >= 0.55:
            rules.append(f"semantic:{top_id}")

        combined = min(1.0, self.lexical_weight * lex_score + self.semantic_weight * sem_score)
        # Boost if either stage has very high confidence
        if lex_score >= 0.70 or sem_score >= 0.80:
            combined = max(combined, max(lex_score, sem_score) * 0.92)

        return InjectionScanResult(
            risk_score=round(combined, 4),
            lexical_score=round(lex_score, 4),
            semantic_score=round(sem_score, 4),
            categories=sorted(set(categories)),
            matched_rules=sorted(set(rules)),
            top_corpus_match=top_id,
            latency_ms=round((t2 - t0) * 1000, 3),
            stage1_ms=round((t1 - t0) * 1000, 3),
            stage2_ms=round((t2 - t1) * 1000, 3),
        )

    def generate_canary_token(self) -> str:
        return f"[{self.canary_prefix}{secrets.token_hex(6).upper()}]"

    def inject_canary(self, messages: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
        canary = self.generate_canary_token()
        updated = [dict(m) for m in messages]
        for msg in updated:
            if msg.get("role") == "system":
                msg["content"] = f"{msg.get('content', '')}\n[CONFIDENTIAL_CANARY: {canary}]"
                return updated, canary
        updated.insert(0, {"role": "system", "content": f"[CONFIDENTIAL_CANARY: {canary}]"})
        return updated, canary

    @staticmethod
    def check_canary_leak(text: str, canary_token: Optional[str]) -> bool:
        if not canary_token or not text:
            return False
        return canary_token in text
