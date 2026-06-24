# OWASP MongoDB Security Lab

This lab demonstrates modern application security (AppSec) concepts and tooling (SAST, DAST, dependency scanning) applied to a Python application connecting to a MongoDB database.

## Project Structure
- `db_query.py`: Simple CLI script to query MongoDB documents.
- `main.py`: A FastAPI web application demonstrating MongoDB queries and potential vulnerability points.
- `.env`: Environment variables (excluded from Git).
- `requirements.txt`: Python package requirements.

## Security Tooling
- **SAST**: `bandit`, `semgrep`
- **Dependency Audit**: `pip-audit`
