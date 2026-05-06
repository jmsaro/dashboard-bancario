# AGENTS.md

## Cursor Cloud specific instructions

This is a static HTML/CSS/JS banking KPI dashboard ("BancoVista — Panel Ejecutivo"). There are no build tools, package managers, or backend services.

### Running the application

Serve `index.html` with any static file server. The simplest approach:

```bash
python3 -m http.server 8080
```

Then open `http://localhost:8080/index.html` in a browser.

### Project structure

- `index.html` — Self-contained dashboard with embedded CSS and JavaScript. No external dependencies.
- `README.md` — Project description.

### Notes

- No linting, testing frameworks, or build steps are configured.
- The application code lives on the `cursor/banking-kpi-dashboard-db86` branch; `main` currently only has `README.md`.
