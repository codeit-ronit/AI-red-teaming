# AgentSec Ops static dashboard

Buildless HTML/CSS/JavaScript, published from `dist/` using Sites. All displayed numbers come from the parent project's evidence export.

- Rebuild data from the parent checkout: `uv run --frozen python scripts/build_dashboard.py`.
- Local interactive dashboard from the parent checkout: `uv run --frozen uvicorn app.dashboard:app --host 127.0.0.1 --port 8010`.
- Public hosting is a static evidence explorer; no backend or model execution is hosted.
- `dist/index.html` declares snapshot runtime. The local backend changes this marker only in its own HTML response to enable deterministic execution.
- Full setup and methodology: https://github.com/codeit-ronit/AI-red-teaming/blob/main/docs/dashboard.md.

The `.openai/hosting.json` identity belongs to the project owner's Site. Deployments require that owner's authenticated source credentials; this file contains no credential.
