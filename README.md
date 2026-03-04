<div align="center">

# 🎞️ GIF CAPTCHA

**Can animated GIFs distinguish humans from AI?**

A research case study exploring GIF-based CAPTCHAs as a human-verification mechanism against large language models.

[![CI](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/ci.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/codeql.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/codeql.yml)
[![Docker](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/docker.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/docker.yml)
[![GitHub Pages](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/pages.yml/badge.svg)](https://github.com/sauravbhattacharya001/gif-captcha/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/gif-captcha)](https://www.npmjs.com/package/gif-captcha)
![HTML](https://img.shields.io/badge/Built%20with-HTML%2FCSS%2FJS-orange)
![GitHub repo size](https://img.shields.io/github/repo-size/sauravbhattacharya001/gif-captcha)
![GitHub last commit](https://img.shields.io/github/last-commit/sauravbhattacharya001/gif-captcha)
![GitHub issues](https://img.shields.io/github/issues/sauravbhattacharya001/gif-captcha)

[**View Live Demo →**](https://sauravbhattacharya001.github.io/gif-captcha/) · [**API Docs →**](https://sauravbhattacharya001.github.io/gif-captcha/docs/)

</div>

---

## 📖 Overview

This case study tests whether GIF-based CAPTCHAs — specifically those requiring comprehension of unexpected events in animated sequences — can serve as an effective human-verification mechanism against LLMs.

GPT-4 was given 10 GIFs, each containing a narrative twist or unexpected event, and asked to *"describe the unexpected event."* Human responses were collected as a baseline.

## 🔬 Methodology

| Component | Details |
|-----------|---------|
| **Model Tested** | GPT-4 (text-only, pre-vision) |
| **Test Set** | 10 animated GIFs with unexpected narrative twists |
| **Prompt** | *"Describe the unexpected event"* |
| **Baseline** | Human descriptions collected for each GIF |
| **Success Criteria** | AI must produce a semantically accurate description of the animated event |

## 📊 Results

**Score: 10/10 CAPTCHAs successfully blocked GPT-4**

| # | GIF | Human Could Describe? | GPT-4 Could Describe? |
|---|-----|:---:|:---:|
| 1 | Duel plot twist | ✅ | ❌ |
| 2 | Rappers roller skating | ✅ | ❌ |
| 3 | Flying skateboarder | ✅ | ❌ |
| 4 | Banana mascot dance-off | ✅ | ❌ |
| 5 | Tic Tac Toe dog | ✅ | ❌ |
| 6 | Parent dog sacrifice | ✅ | ❌ |
| 7 | Mirror hand illusion | ✅ | ❌ |
| 8 | Highway 180° drift | ✅ | ❌ |
| 9 | Road rage hug | ✅ | ❌ |
| 10 | Birthday cake face cover | ✅ | ❌ |

GPT-4 responded identically to every test:
> *"I currently cannot view animations, including animated GIFs, so I can't provide real-time descriptions of events within them."*

## 🔑 Key Findings

### 2023: GIF CAPTCHAs Were Effective
Text-only LLMs had zero ability to process animated visual content. GIF-based CAPTCHAs requiring narrative comprehension of animated sequences were a **100% effective** human-verification mechanism.

### 2025 Update: The Landscape Has Changed
Multimodal LLMs (GPT-4V, GPT-4o, Claude 3.5, Gemini 1.5 Pro) can now:
- Describe static frames extracted from GIFs
- Infer likely motion from visual context clues
- Identify objects, people, and scenes

**Simple visual recognition CAPTCHAs are no longer sufficient.** However, CAPTCHAs requiring understanding of **timing**, **narrative surprise**, and **comedic subversion** may still challenge AI systems that process frames independently rather than as continuous sequences.

## 🚀 Live Demo

The interactive case study is deployed as a static page:

**[sauravbhattacharya001.github.io/gif-captcha](https://sauravbhattacharya001.github.io/gif-captcha/)**

### 🎮 Interactive CAPTCHA Demo

**[Try the Demo →](https://sauravbhattacharya001.github.io/gif-captcha/demo.html)**

Take the GIF CAPTCHA challenge yourself! The interactive demo:
- Shows you each of the 10 GIFs with unexpected twists
- Lets you type your own description of the unexpected event
- Reveals how humans and GPT-4 answered after you submit
- Tracks your "humanity score" across all challenges
- Provides a detailed results summary comparing you to GPT-4's 0/10

### 📊 Research Analysis Dashboard

**[View Analysis →](https://sauravbhattacharya001.github.io/gif-captcha/analysis.html)**

Deep dive into the research data with interactive visualizations:
- **CAPTCHA Taxonomy** — 6 cognitive categories (Narrative Twist, Physical Comedy, Animal Behavior, Visual Trick, Social Subversion, Optical Illusion) with filter tabs
- **Category & Difficulty Charts** — Canvas-rendered bar charts showing distribution and AI difficulty ratings (2023 vs 2025 estimates)
- **Human vs AI Radar Chart** — 6-axis cognitive capability comparison (Temporal Sequencing, Narrative Surprise, Cultural Context, Motion Tracking, Humor Detection, Object Recognition)
- **Multi-Model Comparison** — GPT-4, GPT-4o, Claude 3.5, and Gemini 1.5 Pro estimated scores per category
- **AI Capability Timeline** — Evolution from 0/10 (2023) to projected future performance
- **Per-GIF Analysis Cards** — Expandable breakdowns with difficulty meters, cognitive skills, and explanations of why each CAPTCHA works

### 🛠️ CAPTCHA Workshop

**[Open Workshop →](https://sauravbhattacharya001.github.io/gif-captcha/generator.html)**

Create your own custom GIF CAPTCHA challenge sets:
- **Build** — Add GIF challenges with titles, URLs, expected answers, categories, and difficulty ratings
- **Preview** — Test your CAPTCHA set as a user would experience it, with answer submission and reveal
- **Export/Import** — Export as JSON, download as file, or generate shareable URL links
- **Local Storage** — Auto-saves your work in the browser so you never lose progress
- **Sample Set** — Load a pre-built set of 5 challenges to get started quickly

### 🤖 AI Response Simulator

**[Try Simulator →](https://sauravbhattacharya001.github.io/gif-captcha/simulator.html)**

Explore how different AI models respond to each GIF CAPTCHA:
- **5 AI Models** — GPT-4 (2023), GPT-4V (2023 Q4), GPT-4o (2024), Claude 3.5 (2024), Gemini 1.5 Pro (2024)
- **Simulated Responses** — See exactly what each model would say for each CAPTCHA
- **Capability Breakdown** — Per-CAPTCHA analysis of model capabilities vs. requirements (frame analysis, motion tracking, narrative comprehension, cultural context, humor detection, object recognition)
- **Reasoning Explanations** — Why each model succeeds, partially succeeds, or fails
- **Model × CAPTCHA Heatmap** — Pass/fail matrix across all models and CAPTCHAs
- **Comparative Charts** — Stacked effectiveness bar chart and capability radar overlay
- **Interactive Model Switching** — Click any model to see its full response set

### ⏱️ Temporal Sequence Challenge

**[Try Temporal Challenge →](https://sauravbhattacharya001.github.io/gif-captcha/temporal.html)**

A harder CAPTCHA format testing temporal event ordering:
- **Event Sequencing** — Watch each GIF and arrange 4 events in correct chronological order
- **Drag & Drop + Buttons** — Reorder events by dragging or using arrow buttons (mobile-friendly)
- **Kendall Tau Scoring** — Pairwise concordance scoring (0–100%) for partial credit on near-correct orderings
- **Per-Challenge AI Analysis** — Why frame-by-frame AI processing fails at temporal sequencing
- **Research Context** — Explores temporal CAPTCHAs as a next-generation human verification approach
- **Results Dashboard** — Overall score, per-challenge breakdown with score bars, research implications

### Case Study Page

Features a dark-themed UI with:
- Full results table with CAPTCHA pass/fail badges
- Linked GIF sources for manual verification
- Key findings with visual callouts

## 🛠️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| HTML5 | Page structure |
| CSS3 (Custom Properties) | Dark theme, responsive design |
| JavaScript | Core CAPTCHA library (UMD, browser + Node.js) |
| GitHub Pages | Hosting |
| npm | Package distribution |

## 📦 Installation

Install as an npm package for programmatic access to the CAPTCHA utilities:

```bash
npm install gif-captcha
```

```javascript
const gifCaptcha = require("gif-captcha");

// Create a challenge
const challenge = gifCaptcha.createChallenge({
  id: 1,
  title: "Surprise Ending",
  gifUrl: "https://example.com/twist.gif",
  humanAnswer: "The cat fell off the table unexpectedly",
});

// Pick 5 random challenges from a pool
const selected = gifCaptcha.pickChallenges(challengePool, 5);

// Validate a user's answer (fuzzy matching with Jaccard similarity)
const result = gifCaptcha.validateAnswer(
  userAnswer,
  challenge.humanAnswer,
  { threshold: 0.3, requiredKeywords: ["cat", "fell"] }
);
console.log(result); // { passed: true, score: 0.75, hasKeywords: true }

// Sanitize untrusted input for safe HTML rendering
const safe = gifCaptcha.sanitize('<script>alert("XSS")</script>');
```

Or use via CDN in the browser:

```html
<script src="https://unpkg.com/gif-captcha/src/index.js"></script>
<script>
  const challenge = gifCaptcha.createChallenge({ ... });
  gifCaptcha.loadGifWithRetry(container, challenge);
</script>
```

## 📂 Project Structure

```
gif-captcha/
├── src/
│   └── index.js    # Core library (UMD — browser + Node.js)
├── index.html      # Interactive case study page
├── demo.html       # Interactive CAPTCHA demo (try it yourself!)
├── analysis.html   # Research analysis dashboard with charts & taxonomy
├── generator.html  # CAPTCHA Workshop — create custom challenge sets
├── simulator.html  # AI Response Simulator — model comparison & capability analysis
├── temporal.html   # Temporal Sequence Challenge — event ordering CAPTCHA format
├── shared.js       # Browser-specific shared utilities
├── shared.css      # Shared dark theme styles
├── tests/          # Test suite (Node.js built-in test runner)
├── README.md       # This file
└── LICENSE         # MIT License
```

## 📖 API Reference

See **[API.md](API.md)** for complete documentation of all 13 factory functions and utility exports, including:

- **Challenge Management** — `createChallenge`, `createAttemptTracker`, `createPoolManager`
- **Analysis & Calibration** — `createSetAnalyzer`, `createDifficultyCalibrator`, `createSecurityScorer`
- **Session & Security** — `createSessionManager`, `createTokenVerifier`
- **Bot Detection & Reputation** — `createBotDetector`, `createReputationTracker`, `createChallengeRouter`

## 🔮 Future Research Directions

- **Temporal sequence CAPTCHAs** — Require understanding of event ordering across frames
- **Narrative surprise detection** — Test whether AI can identify *why* something is unexpected, not just *what* happened
- **Multi-model benchmarking** — Extend testing to GPT-4o, Claude 3.5 Opus, Gemini 2.0 with video input
- **Adversarial GIF generation** — Create GIFs specifically designed to exploit frame-by-frame vs. continuous processing gaps

## 📄 License

[MIT](LICENSE) — Saurav Bhattacharya

## 👤 Author

**Saurav Bhattacharya**
- GitHub: [@sauravbhattacharya001](https://github.com/sauravbhattacharya001)
