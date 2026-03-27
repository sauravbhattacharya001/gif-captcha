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

## 🚀 Getting Started

### Installation
Install the package via npm:
```bash
npm install gif-captcha
```

### Basic Usage
```javascript
import { GifCaptcha } from 'gif-captcha';

// Initialize and render a random challenge
const captcha = new GifCaptcha('captcha-container');
captcha.render();
```

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

GPT-4 responded identically to ever