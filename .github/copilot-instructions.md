# Copilot Instructions for gif-captcha

## Project Overview

**GIF CAPTCHA** is a research case study exploring whether animated GIF-based CAPTCHAs can distinguish humans from AI systems. It includes an interactive demo, a research analysis dashboard with data visualizations, and the original case study — all as self-contained static HTML pages.

## Architecture

- **Multi-page static site**: Three HTML pages (case study, interactive demo, analysis dashboard)
- **Pure HTML/CSS/JS**: No frameworks, no bundler, no dependencies. Each page is self-contained
- **Deployment**: GitHub Pages (`pages.yml` workflow) + Docker (nginx-alpine)
- **Security**: CSP headers via `<meta>` tags in HTML and `nginx-security.conf` for Docker deployments

## Project Structure

```
gif-captcha/
├── index.html              # Main case study page — results table, key findings, 2025 update
├── demo.html               # Interactive CAPTCHA demo — 10 GIF challenges with scoring
├── analysis.html            # Research analysis dashboard — charts, radar, taxonomy, timeline
├── Dockerfile               # Multi-stage nginx:alpine container for static hosting
├── nginx-security.conf      # Security headers (X-Frame-Options, CSP, HSTS) for Docker
├── README.md                # Project documentation with badges and full feature list
├── LICENSE                  # MIT license
├── .gitignore               # OS/editor/node exclusions
└── .github/
    ├── copilot-instructions.md   # This file
    ├── copilot-setup-steps.yml   # Copilot agent environment setup
    ├── dependabot.yml            # Dependabot config for GitHub Actions updates
    ├── PULL_REQUEST_TEMPLATE.md  # PR template
    ├── ISSUE_TEMPLATE/           # Bug report, feature request, research question templates
    │   ├── bug_report.yml
    │   ├── config.yml
    │   ├── feature_request.yml
    │   └── research_question.yml
    └── workflows/
        ├── ci.yml            # HTML/CSS validation CI
        ├── codeql.yml        # CodeQL security scanning
        ├── docker.yml        # Docker build/push workflow
        └── pages.yml         # GitHub Pages deployment
```

## Conventions

### CSS

- **CSS Variables**: All colors use CSS custom properties defined in `:root` (dark theme)
  - Core: `--bg`, `--surface`, `--border`, `--text`, `--muted`, `--accent`
  - Semantic: `--green`, `--red`, `--yellow`, `--purple`, `--orange`, `--cyan`
  - Each semantic color has a `*-bg` variant for translucent backgrounds
- **Dark theme**: GitHub-inspired dark color scheme across all pages
- **Responsive**: Media queries at 768px and 480px breakpoints

### HTML

- **Self-contained pages**: Each HTML file includes its own `<style>` and `<script>` blocks — no external CSS/JS files
- **Semantic HTML**: Proper heading hierarchy (`h1` → `h2` → `h3`), tables for tabular data, semantic class names
- **Security meta tags**: Each page has `Content-Security-Policy`, `referrer` meta tags
- **No external scripts**: All JavaScript is inline. CSP blocks external script loading by design

### Component Patterns

- **Finding cards**: `.finding` class with `.success` or `.warning` modifiers (index.html)
- **Badges**: `.badge` + `.badge-pass` / `.badge-fail` for pass/fail indicators
- **Tags**: `.tag` + `.tag-{category}` for color-coded category labels (analysis.html)
- **Filter tabs**: `.filter-tab` with `.active` state for category filtering
- **Expandable cards**: `.gif-analysis-card` with `.expanded` toggle for detail panels
- **Difficulty meters**: `.difficulty-meter` with animated fill bars
- **Canvas charts**: Bar charts, radar charts rendered via Canvas 2D API (analysis.html)

### JavaScript

- **Vanilla JS only**: No jQuery, React, or other libraries
- **`var` declarations**: Existing code uses `var` for broad browser compatibility — follow this convention
- **Canvas rendering**: Charts in analysis.html are drawn with Canvas 2D API, including `roundRect` polyfill
- **Challenge data**: Demo page stores all 10 GIF challenge entries in a `challenges` array with URLs, human/AI answers

## How to Test

```bash
# Validate all HTML files
npx htmlhint index.html demo.html analysis.html

# Open pages in browser for visual inspection
start index.html     # Windows
open index.html      # macOS

# Run Docker container locally
docker build -t gif-captcha .
docker run -p 8080:80 gif-captcha
# Visit http://localhost:8080
```

### Validation Checklist

1. All three pages render correctly in Chrome/Firefox/Safari
2. Dark theme colors are consistent across pages
3. Navigation links between pages work (index ↔ demo ↔ analysis)
4. Charts in analysis.html render on page load and resize correctly
5. Demo interactive flow: start → answer/skip 10 challenges → results
6. Responsive layout works at mobile (480px), tablet (768px), and desktop widths
7. CSP headers don't block any required functionality

## Content Notes

- The study tested GPT-4 (text-only, 2023) against 10 animated GIFs requiring narrative comprehension
- Results: GPT-4 failed all 10 (couldn't process animated content)
- 2025 update section notes multimodal models (GPT-4o, Claude 3.5, Gemini 1.5 Pro) have changed the landscape
- GIF URLs in demo.html point to external CDNs (Tenor, Giphy, Gifer) — these may break over time
- Analysis page includes estimated (not measured) scores for 2025 models

## When Making Changes

1. **Maintain consistency**: Dark theme aesthetic, self-contained pages, no external dependencies
2. **Update all pages**: If adding navigation or shared elements, update all three HTML files
3. **Test chart rendering**: Changes to analysis.html should verify Canvas charts still render and resize
4. **Follow CSP**: Don't add external script/style sources — they'll be blocked by Content-Security-Policy
5. **Validate HTML**: Run `htmlhint` on any modified pages before committing
6. **Consider accessibility**: Proper contrast ratios, semantic HTML, descriptive link text, alt attributes
7. **Keep `var`**: Use `var` in JavaScript for consistency with existing code style
