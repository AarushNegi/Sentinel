# Blue Team phishing: AI-driven scenarios

* `ai/scenario_generator.py` - Ollama adapter (server-side only). The model writes *narrative seeds*; code validates them.
* `blue_phishing/composer.py` - deterministically derives indicators, ground truth, evidence and attacker progression from a seed.
* `blue_phishing/engine.py` - state machine, evidence disclosure, scoring (max 1000), final report.
* `blue_phishing/templates.py` - 3 validated offline scenarios used when Ollama is unavailable.

## Environment (all optional)
| Variable | Default |
|---|---|
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | `qwen3:4b` |
| `OLLAMA_TIMEOUT_SECONDS` | `60` |
| `OLLAMA_KEEP_ALIVE` | `30m` |
| `BLUE_PHISHING_AI_ENABLED` | `true` |
| `BLUE_PHISHING_WARMUP` | `true` (loads the model in the background at start-up) |

## Run / test
```powershell
winget install --id Ollama.Ollama -e
ollama pull qwen3:4b
cd backend; pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q
python app.py
cd ..\frontend; npm install; npm test; npm run dev
```

## Workspace overview (frontend)
Alert queue -> email client -> IOC lab -> users & logs -> evidence locker -> containment / remediation -> structured closure -> report.
Scenario types: `no_compromise`, `blocked_campaign`, `spoofed_internal`, `credential_compromise`, `malicious_attachment`, `multi_user_campaign` (each easy/medium/hard).

Endpoints: `POST /api/blue-phishing/start`, `/<id>/action`, `/<id>/query` (read-only log search), `/<id>/complete`, `GET /<id>/report`, `GET /ai-status`.
