# Contributing to GIF CAPTCHA

Thanks for your interest in contributing to GIF CAPTCHA! This project explores whether animated GIF-based CAPTCHAs can distinguish humans from AI, and there are several meaningful ways to help.

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Guide](#development-guide)
- [Project Architecture](#project-architecture)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Research Contributions](#research-contributions)

## Ways to Contribute

### 🔬 Research
- **New GIF test cases**: Find GIFs with unexpected twists and test them against current AI models
- **Model benchmarking**: Run the GIF CAPTCHA test against newer multimodal models (GPT-4o, Claude 3.5 Sonnet, Gemini 2.0, etc.) and report results
- **Adversarial GIF generation**: Design GIFs that specifically exploit frame-by-frame vs. continuous processing gaps
- **Category analysis**: Propose new cognitive categories or refine the existing taxonomy

### 🐛 Bug Reports
- GIFs that no longer load (external CDN links break over time)
- Rendering issues on specific browsers or screen sizes
- Chart rendering problems in the analysis dashboard
- Accessibility issues

### ✨ Feature Ideas
- New visualizations for the analysis dashboard
- Improved interactive demo mechanics
- Accessibility improvements
- Performance optimizations

### 📝 Documentation
- Improve clarity of research findings
- Add citations to related CAPTCHA research
- Fix typos or outdated information

## Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)
- Git
- (Optional) Node.js for HTML validation: `npm install -g htmlhint`
- (Optional) Docker for container testing

### Setup

```bash
# Clone the repository
git clone https://github.com/sauravbhattacharya001/gif-captcha.git
cd gif-captcha

# Open directly in your browser
start index.html     # Windows
open index.html      # macOS
xdg-open index.html  # Linux
```

No build step required — the project is pure HTML/CSS/JS.

### Validation

```bash
# Validate HTML
npx htmlhint index.html demo.html analysis.html

# Test Docker build
docker build -t gif-captcha .
docker run -p 8080:80 gif-captcha
# Visit http://localhost:8080
```

## Development Guide

### Pages Overview

| File | Purpose | Key Features |
|------|---------|-------------|
| `index.html` | Case study results | Results table, key findings, 2025 update |
| `demo.html` | Interactive demo | 10 GIF challenges, scoring, reveal panels |
| `analysis.html` | Research dashboard | Canvas charts, radar diagram, taxonomy filters, timeline |

### Making Changes

1. **Edit HTML files directly** — no compilation needed
2. **Refresh your browser** to see changes
3. **Test responsive layouts** using browser DevTools (resize to 480px, 768px, and full width)
4. **Check all three pages** if your change affects shared elements (navigation, color variables, etc.)

### Docker Testing

```bash
docker build -t gif-captcha .
docker run -p 8080:80 gif-captcha
```

This serves the site through nginx with security headers from `nginx-security.conf`.

## Project Architecture

```
gif-captcha/
├── index.html              # Main case study (static HTML + CSS)
├── demo.html               # Interactive demo (HTML + CSS + inline JS)
├── analysis.html            # Analysis dashboard (HTML + CSS + Canvas 2D charts)
├── Dockerfile               # nginx:alpine container
├── nginx-security.conf      # Security headers for Docker deployment
└── .github/
    ├── workflows/           # CI, Pages deployment, Docker, CodeQL
    └── ISSUE_TEMPLATE/      # Bug, feature, research question templates
```

### Design Decisions

- **Self-contained pages**: Each HTML file includes all its CSS and JS inline. This avoids external dependencies and simplifies deployment
- **No JavaScript frameworks**: Vanilla JS only, for simplicity and zero build overhead
- **Canvas 2D for charts**: The analysis page renders charts with the Canvas API rather than a charting library, keeping the project dependency-free
- **Dark theme**: GitHub-inspired dark color scheme using CSS custom properties

## Coding Standards

### HTML

- Use semantic elements (`<header>`, `<nav>`, `<main>`, `<section>`, `<footer>`)
- Maintain proper heading hierarchy (`h1` → `h2` → `h3`)
- Include `alt` attributes on images
- Keep Content-Security-Policy meta tags consistent across pages

### CSS

- Use CSS custom properties from `:root` — don't hardcode color values
- Follow existing naming conventions (`.finding`, `.badge`, `.tag-{category}`)
- Support responsive breakpoints at 768px and 480px
- Maintain accessible contrast ratios (WCAG AA minimum)

### JavaScript

- Use `var` declarations (for consistency with existing code and broad compatibility)
- No external libraries or CDN imports
- Follow the existing data-driven pattern: define data arrays/objects, then render from them
- Use `sanitize()` helper for user-generated content to prevent XSS

### Content-Security-Policy

All pages enforce strict CSP via `<meta>` tags:
- `style-src 'unsafe-inline'` — inline styles only
- `script-src 'unsafe-inline'` — inline scripts only (demo.html and analysis.html)
- `img-src https:` — HTTPS images only
- `frame-ancestors 'none'` — no iframe embedding

Don't add external script or stylesheet sources — they'll be blocked.

## Submitting Changes

### Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b your-feature`
3. **Make your changes** following the coding standards above
4. **Validate**: `npx htmlhint index.html demo.html analysis.html`
5. **Test visually**: Open all three pages, check responsive layouts
6. **Commit** with a clear message: `git commit -m "Add temporal analysis chart to analysis dashboard"`
7. **Push** and open a Pull Request

### PR Guidelines

- Keep PRs focused — one feature or fix per PR
- Include screenshots for visual changes
- Describe what you changed and why
- If adding new research data, cite your sources

### Commit Messages

Use clear, descriptive commit messages:
- `Fix broken Tenor GIF URL for duel challenge`
- `Add GPT-4o benchmark results to comparison table`
- `Improve radar chart accessibility with ARIA labels`

## Research Contributions

If you've tested the GIF CAPTCHAs against a new AI model:

1. **Open an issue** using the "Research Question" template
2. Include:
   - Model name and version
   - Date of testing
   - Results for each of the 10 GIFs (pass/fail + model response)
   - Any interesting observations
3. We'll review the data and potentially add it to the analysis dashboard

### Adding New GIF Test Cases

When proposing new GIFs for the test suite:

1. The GIF must contain a **clear unexpected event** requiring temporal comprehension
2. Categorize it using the existing taxonomy (Narrative Twist, Physical Comedy, Animal Behavior, Visual Trick, Social Subversion, Optical Illusion) or propose a new category
3. Provide the human baseline description
4. Test against at least one AI model and include results
5. Host the GIF on a reliable CDN (Giphy, Tenor) for longevity

---

## Code of Conduct

Be kind, constructive, and respectful. We're all here to advance understanding of AI capabilities and CAPTCHA design.

## Questions?

Open an issue or start a discussion. We're happy to help!
