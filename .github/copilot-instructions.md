# Copilot Instructions for gif-captcha

## Project Overview

**GIF CAPTCHA** is a case study exploring whether animated GIF-based CAPTCHAs can distinguish humans from AI systems. The project consists of a single-page HTML application that presents research findings.

## Architecture

- **Single-page app**: `index.html` contains all HTML, CSS, and content (no build step)
- **Pure HTML/CSS**: No JavaScript frameworks, no bundler, no dependencies
- **Deployment**: Azure Static Web Apps (see `.github/workflows/azure-static-web-apps-*.yml`)

## Project Structure

```
gif-captcha/
├── index.html          # Main page — all markup, styles, and content
├── README.md           # Project documentation
├── LICENSE             # MIT license
└── .github/
    └── workflows/      # CI/CD for Azure Static Web Apps
```

## Conventions

- **CSS Variables**: All colors use CSS custom properties defined in `:root` (dark theme: `--bg`, `--surface`, `--border`, `--text`, `--muted`, `--accent`, `--green`, `--red`)
- **Self-contained**: Everything is in one HTML file — styles in `<style>`, no external CSS/JS
- **Semantic HTML**: Uses proper heading hierarchy (`h1` → `h2` → `h3`), tables for data, semantic class names
- **Finding cards**: Research findings use `.finding` class with `.success` or `.warning` modifiers
- **Badges**: Results shown with `.badge` + `.badge-pass` / `.badge-fail`

## How to Test

Since this is a static HTML file, validation is the primary testing approach:

```bash
# Validate HTML syntax
npx htmlhint index.html

# Open in browser for visual inspection
open index.html  # macOS
start index.html # Windows
```

## Content Notes

- The study tested GPT-4 (2023) against 10 animated GIFs requiring narrative comprehension
- Results: GPT-4 failed all 10 (couldn't process animated content)
- 2025 update section notes that multimodal models have changed the landscape
- GIF links point to external sources (Tenor, Gifer, Pinterest, Tumblr)

## When Making Changes

1. Maintain the dark theme aesthetic (GitHub-inspired dark colors)
2. Keep the page self-contained — avoid adding external dependencies
3. If adding new test results or findings, follow the existing table structure
4. Test that the page renders properly at different viewport widths (responsive via `max-width: 900px`)
5. The page should remain accessible — proper contrast ratios, semantic HTML, descriptive link text
