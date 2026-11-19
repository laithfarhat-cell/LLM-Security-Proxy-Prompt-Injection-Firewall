# Security Architecture & Threat Model

## 1. Alignment with OWASP Top 10 for LLM Applications

### LLM01: Prompt Injection (Direct & Indirect)
Attackers craft inputs that override system instructions or hijack tool-calling workflows. Indirect injections arrive via retrieved RAG documents or tool outputs.
- **Mitigation**: A two-stage hybrid detector:
  1. **Stage 1 (Lexical & Encoding Guard, `< 2ms`)**: Detects zero-width/bidirectional Unicode smuggling, chat-template delimiter spoofing (`<|im_start|>`, `[INST]`), override signatures, and recursively decodes Base64, Hex, and ROT13 obfuscated payloads.
  2. **Stage 2 (Semantic Embedding Vector Guard)**: Splits inputs into overlapping sliding windows and computes vectorized cosine similarity against pre-computed normalized embeddings of `data/attack_corpus.json` using `all-MiniLM-L6-v2`.

### LLM02: Sensitive Information Disclosure
Users or internal applications may inadvertently send API keys, JWTs, private keys, or PII (SSNs, credit cards, emails) to third-party LLM providers.
- **Mitigation**: Bidirectional DLP with **Vaulted Pseudonymization**. Sensitive entities are replaced with session-scoped placeholders (`<EMAIL_1>`, `<API_KEY_1>`) before leaving the trust boundary, and optionally re-hydrated on the return path.

### LLM07: System Prompt Leakage
Adversaries attempt to extract confidential system instructions.
- **Mitigation**: Cryptographic **Canary Token** injection (`[CANARY-<hex>]`) into upstream system prompts, paired with real-time egress scanning (including sliding-window inspection on SSE streams).

## 2. Security vs. Latency Tradeoffs
- Running a full LLM-as-a-Judge guardrail adds 300–1500ms of latency per request.
- By combining deterministic regex/decoding (`< 1ms`) with a compact 384-dimensional bi-encoder (`all-MiniLM-L6-v2`) and pre-computed corpus embeddings, the proxy achieves sub-30ms p95 overhead while maintaining high recall against both known signatures and paraphrased attacks.
