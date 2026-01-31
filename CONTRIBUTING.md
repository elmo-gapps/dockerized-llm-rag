# Contributing to the Enterprise LLM Platform

Welcome! As this is an enterprise-grade solution, we maintain high standards for code quality, security, and documentation.

## 1. Development Principles
- **Security First**: Never hardcode secrets. Use environment variables.
- **Privacy by Design**: All inference must remain local. Avoid any external API calls in inference paths.
- **Container-Native**: Ensure all new features are properly containerized and documented in `docker-compose.yml`.

## 2. Coding Standards
- **Python**: Follow PEP 8. Use type hints where possible.
- **Frontend**: Functional components with Hooks. Use Tailwind v4 for styling.
- **API**: All new endpoints must include JWT validation using the `RS256` pattern established in `llm-api/app.py`.

## 3. Pull Request Process
1.  **Issue Link**: Every PR must reference an internal Jira/Ticket ID.
2.  **Documentation**: Update the relevant markdown files in `docs/` if you change architecture or operations.
3.  **ADRs**: If you make a significant architectural change (e.g., swapping a database), you MUST submit a new ADR in `docs/architecture/adr/`.
4.  **Testing**: Run `./test_e2e.sh` and ensure all tests pass before submitting.

## 4. Branching Strategy
- `main`: Stable production-ready code.
- `develop`: Integration branch for new features.
- `feature/*`: Short-lived branches for specific tickets.

## 5. Security Reporting
If you discover a security vulnerability, do NOT open a public issue. Report it immediately to the internal Security Operations Center (SOC) or the project lead.
