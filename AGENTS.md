# Repository Guidelines

## Project Structure & Module Organization

This repository is a small CCDC hardening tracker with these primary runtime files:

- `hardening_agent.sh`: Linux host collector. It gathers security state and prints or POSTs a JSON report.
- `server.go`: Go HTTP server that receives reports, stores decoded JSON, serves the dashboard, and triggers analysis.
- `analyzer.py`: LLM prompt builder and provider client wrapper for Anthropic or OpenAI.
- `server.py`: legacy FastAPI server kept for compatibility.
- `README.md` and `README_spanish.md`: user-facing setup and operating documentation.

Runtime reports are written to `./reports` by default through `HARDEN_DATA`; treat them as generated data and do not commit sensitive host output.

## Build, Test, and Development Commands

There is no dependency lock file. Run the Go server directly:

```bash
HARDEN_TOKEN=ccdcagent2026 ANTHROPIC_API_KEY=sk-... go run .
```

Install Python analyzer dependencies manually when using `/analyze/{host}`:

```bash
pip install anthropic openai
```

Run the legacy FastAPI server only when needed:

```bash
HARDEN_TOKEN=ccdcagent2026 ANTHROPIC_API_KEY=sk-... uvicorn server:app --host 0.0.0.0 --port 8000
```

Run agent checks locally:

```bash
sudo ./hardening_agent.sh text
sudo ./hardening_agent.sh local
```

Validate syntax before submitting changes:

```bash
go test ./...
python3 -m py_compile analyzer.py server.py
bash -n hardening_agent.sh
```

## Coding Style & Naming Conventions

Use 4-space indentation in Python and keep functions small with `snake_case` names. Prefer standard library modules already in use, such as `os`, `json`, `base64`, `pathlib`, and `logging`, before adding dependencies. Environment variables should use the existing `HARDEN_` prefix.

For shell code, keep Bash-compatible syntax, quote variable expansions, and follow the current function-based collector style (`collect_users`, `collect_network`, etc.). Keep comments short and operational.

## Testing Guidelines

At minimum, run Go tests, Python compilation, Bash syntax validation, and a manual smoke test of `go run .`. For behavior changes, test both `hardening_agent.sh local` and a `/report` then `/analyze/{host}` flow with a non-production token.

## Commit & Pull Request Guidelines

Recent history uses very short commit messages, so prefer improving clarity with imperative summaries such as `Add report retention setting` or `Fix OpenAI analyzer errors`. Pull requests should include a concise description, commands run, any changed environment variables, linked issues when available, and screenshots if the dashboard HTML changes.

## Security & Configuration Tips

Never commit API keys, shared `HARDEN_TOKEN` values, or collected host reports. Keep defaults safe for local testing, but document any production-facing configuration changes in `README.md`.
