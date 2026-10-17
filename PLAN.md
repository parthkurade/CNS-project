# PhishShield – Implementation Plan
**Team ZeroTrace | SPIT Mumbai | CNS Course Project**

---

## Environment
| Tool | Version |
|------|---------|
| Python | 3.11.16 (uv-managed) |
| Node / npm | 24.15.0 / 11.12.1 |
| Git | 2.53.0 |
| uv | 0.12.5 |
| Docker | NOT AVAILABLE on this machine – Docker steps are written but must be run on a Docker-capable host |
| GitHub CLI | Installing via winget |

---

## Phase 0 – Repo Skeleton & Tooling
- [x] `git init`, configure author
- [ ] Create `.gitignore`
- [ ] Create `.env.example`
- [ ] Create `pyproject.toml` (backend)
- [ ] Create `package.json` for frontend (Vite + React + TS + Tailwind)
- [ ] Create `docker-compose.yml`, `Dockerfile` (backend), `Dockerfile` (frontend)
- [ ] Create `scripts/gen_certs.sh` (and `.ps1` Windows equivalent)
- [ ] GitHub Actions CI workflow

---

## Phase 1 – Backend Core (FastAPI)
Directory: `/backend`

### 1.1 App Structure
```
backend/
  app/
    main.py          ← FastAPI app, HTTPS/TLS config, CORS, security headers
    config.py        ← Settings from env vars (pydantic-settings)
    database.py      ← SQLAlchemy + SQLite setup
    models.py        ← ORM models (Email, Log, Key, User, Nonce)
    schemas.py       ← Pydantic request/response schemas
    deps.py          ← JWT auth dependency, role check
    routers/
      auth.py        ← /auth/login, /auth/refresh
      emails.py      ← /emails/, /emails/{id}, /emails/{id}/release, /emails/{id}/delete
      analysis.py    ← /analyze (POST raw email), /analyze/url
      simulation.py  ← /simulate/{scenario}
      keys.py        ← /keys/ CRUD
      dashboard.py   ← /dashboard/stats
      logs.py        ← /logs/ search/filter/export
      model.py       ← /model/metrics, /model/retrain
      settings.py    ← /settings/ thresholds
  crypto/
    aes.py           ← AES-256-GCM encrypt/decrypt, HKDF key derivation
    signatures.py    ← Ed25519 sign/verify, RSA-PSS sign/verify
    hmac_util.py     ← HMAC-SHA256 (constant-time), PBKDF2/Argon2 key derive
    hashing.py       ← SHA-256 message hash, attachment hash
    replay.py        ← NonceCache (TTL-based, thread-safe)
    keys.py          ← Key generation, rotation, revocation
    tls.py           ← TLS context builder, cert loader
  analysis/
    email_parser.py  ← Parse raw RFC 2822 emails, extract headers/body/attachments
    spf_check.py     ← SPF DNS lookup + evaluation (pyspf / dnspython)
    dkim_check.py    ← DKIM verify (dkimpy)
    dmarc_check.py   ← DMARC policy fetch + evaluation
    url_analyzer.py  ← Extract + analyze URLs (shortener, punycode, IP, TLD, etc.)
    attachment.py    ← Extension check, double-ext, macro detection, hash
    spoofing.py      ← Display-name spoof, lookalike domain (Levenshtein/homoglyph), Reply-To mismatch
    header_analyzer.py ← Received-chain, Return-Path, Authentication-Results
  ml/
    features.py      ← Feature extraction (TF-IDF + engineered)
    train.py         ← Training script, metrics, model persistence
    predict.py       ← Load model, predict, explain top features
    download_data.py ← Download public datasets (Enron, SpamAssassin, etc.) or use synthetic fallback
  simulation/
    scenarios.py     ← 5 attack scenarios (generate + send + report)
    smtp_client.py   ← SMTP send helper
  smtp/
    ingest.py        ← aiosmtpd handler, STARTTLS, pipeline invocation
  tests/
    test_crypto.py
    test_replay.py
    test_scoring.py
    test_analysis.py
    test_simulation.py
    test_ml.py
    conftest.py
```

### 1.2 Security Requirements (Backend)
- All input validated with Pydantic v2
- Parameterized queries (SQLAlchemy ORM)
- JWT tokens (python-jose), bcrypt/argon2 password hashing
- Rate limiting (slowapi)
- CORS restricted, security headers (helmet-style middleware)
- Constant-time HMAC/hash comparisons (`hmac.compare_digest`)
- No MD5 or SHA-1 for security; SHA-256+ only
- Master AES key from `AES_MASTER_KEY` env var (never hardcoded)
- Nonce cache with TTL rejects replays; timestamps ±5 min window

---

## Phase 2 – Cryptography Module
All using the `cryptography` library:

| Feature | Algorithm | Notes |
|---------|-----------|-------|
| Symmetric encryption | AES-256-GCM | Random 96-bit nonce per message |
| Key derivation | HKDF-SHA256 or PBKDF2-HMAC-SHA256 | From master key + salt |
| Digital signatures | Ed25519 | Fast, secure, small key |
| MAC | HMAC-SHA256 | Constant-time compare |
| Message hashing | SHA-256 | Tamper detection |
| Password hashing | bcrypt / Argon2id | For admin accounts |
| TLS | TLS 1.2+ | Self-signed CA for dev |

---

## Phase 3 – Sender Authentication
- **SPF**: DNS TXT lookup, parse `v=spf1` record, evaluate against sending IP (using `dnspython`)
- **DKIM**: Verify signature in `DKIM-Signature` header (`dkimpy` library)
- **DMARC**: Look up `_dmarc.domain` TXT record, evaluate `p=` policy against SPF/DKIM alignment
- **Test mode**: A local fake-DNS resolver that returns predefined records (no real DNS needed in tests)
- **Spoofing detection**: Levenshtein distance for lookalike domains, Unicode homoglyph normalization, Reply-To ≠ From check

---

## Phase 4 – Email Analysis Module
Extract and score:
1. Headers (Received chain, Return-Path, X-Originating-IP)
2. Body text (urgency keywords, grammar analysis)
3. HTML body (form actions, scripts, hidden elements)
4. URLs (30+ features per URL)
5. Attachments (extension, MIME, hash, macro detection)

---

## Phase 5 – ML Phishing Detection
- **Data**: Try to download SpamAssassin public corpus + Enron ham; synthetic labeled dataset as fallback (clearly labeled)
- **Pipeline**: sklearn `Pipeline` with TF-IDF + feature union + classifier
- **Models**: LogisticRegression + RandomForest → VotingClassifier ensemble
- **Metrics**: accuracy, precision, recall, F1, ROC-AUC, confusion matrix on 20% held-out test set
- **Explainability**: `eli5` or manual top-feature extraction per prediction
- **Persistence**: `joblib` to `ml/model.pkl` + `ml/vectorizer.pkl`

---

## Phase 6 – Risk Scoring Engine
```
Score = Σ(weight_i × factor_i) capped at 100

Factors:
  auth_score      (SPF+DKIM+DMARC)   weight=25
  url_score       (URL analysis)      weight=20
  attachment_score                    weight=15
  ml_score        (phishing prob)     weight=25
  header_score    (spoofing checks)   weight=10
  crypto_score    (sig/hmac/hash)     weight=5

Hard overrides → score=100:
  - Signature fail on claimed-signed message
  - Replay detected
  - Known-malicious attachment hash
```

---

## Phase 7 – Decision & Response
| Score | Decision | Action |
|-------|----------|--------|
| 0–40  | LEGITIMATE | Deliver |
| 41–70 | SUSPICIOUS | Deliver with warning banner |
| 71–100 | MALICIOUS | Quarantine (AES-encrypted) |

---

## Phase 8 – Attack Simulation Module
Each scenario:
1. **Phishing**: credential-harvesting template, malicious URL, legitimate-looking sender
2. **Sender Spoofing**: forged From field (real domain, bad SPF record)
3. **Message Tampering**: valid signed message, body modified → hash/sig fail
4. **Replay Attack**: resend a previously valid nonce → nonce cache rejects
5. **MitM Simulation**: invalid cert / TLS downgrade attempt → show TLS checks

Batch mode: N=10 iterations each, detection rate, false-positive rate, avg latency.

---

## Phase 9 – Frontend (React + Vite + TS + Tailwind)
Pages:
- `/login` – admin login
- `/dashboard` – stats, charts (Recharts)
- `/inbox` – delivered + warned emails
- `/quarantine` – blocked emails, admin decrypt/preview
- `/logs` – searchable security log, export CSV/JSON
- `/simulate` – attack simulation panel + results
- `/model` – ML metrics, confusion matrix, feature importance
- `/keys` – key management (generate, rotate, revoke)
- `/settings` – threshold configuration
- `/email/:id` – full email analysis detail + "Explain this" educational panel

---

## Phase 10 – SMTP Ingest
- `aiosmtpd` listening on port 2525 (not 25, no root needed)
- STARTTLS with generated cert
- On receipt: parse → full pipeline → DB store → WebSocket push

---

## Phase 11 – Docs
- `README.md` – full setup, architecture Mermaid diagram, pipeline flow, screenshots, metrics, threat model, credits
- `docs/THREAT_MODEL.md`
- `docs/CRYPTO_DESIGN.md`

---

## Phase 12 – CI & GitHub
- `.github/workflows/ci.yml` – lint (ruff) + pytest + frontend build
- `gh repo create phishshield --public`
- Conventional commits throughout

---

## Delivery Checklist
- [ ] App starts (HTTPS backend + React frontend)
- [ ] Real email analyzable through SMTP ingest
- [ ] All 5 attack simulations produce real results
- [ ] ML metrics from real held-out test set
- [ ] All tests pass
- [ ] Repo pushed to GitHub with README + .env.example
- [ ] No unexplained TODO/mock/fake in production code
