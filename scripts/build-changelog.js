// Build docs/changelog.html from the GitHub releases of this repo.
// Run: gh api 'repos/sauravbhattacharya001/gif-captcha/releases?per_page=100' > releases-raw.json
// then: node build-changelog.js
const fs = require('fs');

const raw = JSON.parse(fs.readFileSync('releases-raw.json', 'utf8'));

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Mojibake question-mark sequences come from emoji that got mangled in earlier
// release notes; strip them so the rendered page stays clean.
function cleanBody(body) {
  if (!body) return '';
  return body
    .replace(/\?\?+/g, '')      // "??" or longer mojibake runs
    .replace(/\u0007/g, '')     // stray bells
    .replace(/\r\n/g, '\n')
    .trim();
}

// Render a body as small HTML: parse top-level "### Heading" sections and
// the bullet lines under them. Anything else becomes a paragraph.
function renderBody(body) {
  const out = [];
  const lines = body.split('\n');
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const h = line.match(/^#{2,4}\s+(.+?)\s*$/);
    if (h) {
      out.push(`<h4>${esc(h[1])}</h4>`);
      i++;
      continue;
    }
    // bullet list
    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, '').trim());
        i++;
      }
      out.push('<ul>' + items.map(it => `<li>${inline(it)}</li>`).join('') + '</ul>');
      continue;
    }
    if (line.trim() === '') { i++; continue; }
    // paragraph: gather until blank or heading or bullet
    const para = [];
    while (i < lines.length && lines[i].trim() !== '' && !/^#{2,4}\s+/.test(lines[i]) && !/^\s*[-*]\s+/.test(lines[i])) {
      para.push(lines[i]);
      i++;
    }
    out.push(`<p>${inline(para.join(' '))}</p>`);
  }
  return out.join('\n');
}

// Inline markdown: bold, code, links
function inline(s) {
  s = esc(s);
  // code spans first
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  // bold
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // links [text](url) — text was already escaped
  s = s.replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  return s;
}

function shortDate(iso) {
  const d = new Date(iso);
  return d.toISOString().slice(0, 10);
}

function summary(body) {
  // first heading or first sentence
  const m = body.match(/^#{2,4}\s+(.+)$/m);
  if (m) return m[1].slice(0, 120);
  const first = body.split('\n').find(l => l.trim());
  return (first || '').slice(0, 160);
}

// Sort newest first
raw.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));

const cards = raw.map((r, idx) => {
  const body = cleanBody(r.body);
  const isLatest = idx === 0;
  const name = (r.name || r.tag_name || '').replace(/[\u2014\u2013]/g, '—'); // normalize dashes
  return `
    <article class="release${isLatest ? ' release-latest' : ''}" id="${esc(r.tag_name)}">
      <header class="release-head">
        <div class="release-title">
          <h3>${esc(name)}</h3>
          ${isLatest ? '<span class="badge badge-latest">latest</span>' : ''}
        </div>
        <div class="release-meta">
          <span class="tag"><code>${esc(r.tag_name)}</code></span>
          <span class="date">${esc(shortDate(r.published_at))}</span>
          <a href="${esc(r.html_url)}" target="_blank" rel="noopener" class="external">View on GitHub →</a>
        </div>
      </header>
      <div class="release-body">
        ${renderBody(body) || '<p class="muted">No release notes.</p>'}
      </div>
    </article>`;
}).join('\n');

const tocItems = raw.map(r => {
  const name = (r.name || r.tag_name).replace(/^v?\d+\.\d+\.\d+\s*[—-]\s*/, '');
  return `<li><a href="#${esc(r.tag_name)}"><code>${esc(r.tag_name)}</code> <span class="muted">${esc(shortDate(r.published_at))}</span></a> <span class="toc-summary">${esc(summary(cleanBody(r.body)))}</span></li>`;
}).join('\n');

const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="GIF CAPTCHA release notes and version history.">
    <title>Changelog - GIF CAPTCHA</title>
    <link rel="stylesheet" href="../shared.css">
    <style>
        body { padding: 2rem; max-width: 960px; margin: 0 auto; }
        h1 { font-size: 2rem; margin-bottom: 0.3rem; }
        .subtitle { color: var(--muted); font-size: 1rem; margin-bottom: 1.5rem; }
        .nav { display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }
        .nav a { color: var(--accent); text-decoration: none; font-size: 0.9rem; }
        .nav a:hover { text-decoration: underline; }

        .toc { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; margin: 1.5rem 0 2.5rem; }
        .toc h3 { margin: 0 0 0.6rem; font-size: 1rem; }
        .toc ul { margin: 0; padding-left: 0; list-style: none; }
        .toc li { margin: 0.25rem 0; font-size: 0.9rem; display: flex; gap: 0.6rem; align-items: baseline; flex-wrap: wrap; }
        .toc a { color: var(--accent); text-decoration: none; white-space: nowrap; }
        .toc a:hover { text-decoration: underline; }
        .toc .toc-summary { color: var(--muted); font-size: 0.85rem; }
        .muted { color: var(--muted); }

        .release { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.4rem; margin: 1.2rem 0; scroll-margin-top: 1rem; }
        .release-latest { border-color: var(--accent); }
        .release-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.6rem; }
        .release-title { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
        .release-title h3 { margin: 0; font-size: 1.1rem; color: var(--text); }
        .release-meta { display: flex; gap: 0.8rem; align-items: center; font-size: 0.85rem; color: var(--muted); flex-wrap: wrap; }
        .release-meta code { background: var(--bg, #0d1117); padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85em; color: var(--accent); }
        .release-meta .external { color: var(--accent); text-decoration: none; }
        .release-meta .external:hover { text-decoration: underline; }

        .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        .badge-latest { background: #1a3a2a; color: #4ade80; }

        .release-body h4 { font-size: 0.95rem; margin: 1rem 0 0.3rem; color: var(--text); }
        .release-body p, .release-body li { color: var(--muted); line-height: 1.55; font-size: 0.92rem; }
        .release-body ul { margin: 0.3rem 0 0.6rem 1.2rem; padding: 0; }
        .release-body code { background: var(--bg, #0d1117); padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.88em; color: var(--accent); }
        .release-body a { color: var(--accent); }

        .footer-note { color: var(--muted); font-size: 0.85rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }
    </style>
</head>
<body>
    <div class="nav">
        <a href="../index.html">Case Study</a>
        <a href="../demo.html">Demo</a>
        <a href="../analysis.html">Analysis</a>
        <a href="../generator.html">Workshop</a>
        <a href="getting-started.html">Getting Started</a>
        <a href="index.html">API Reference</a>
        <a href="architecture.html">Architecture</a>
        <a href="security-guide.html">Security Guide</a>
        <a href="module-reference.html">Module Reference</a>
        <a href="testing-guide.html">Testing Guide</a>
        <a href="deployment-guide.html">Deployment Guide</a>
        <a href="advanced-intelligence.html">Advanced Intelligence</a>
        <a href="changelog.html"><strong>Changelog</strong></a>
    </div>

    <h1>Changelog</h1>
    <p class="subtitle">All notable changes to <code>gif-captcha</code>. ${raw.length} releases, latest <code>${esc(raw[0].tag_name)}</code> (${esc(shortDate(raw[0].published_at))}).</p>

    <div class="toc">
        <h3>Releases</h3>
        <ul>
${tocItems}
        </ul>
    </div>

${cards}

    <p class="footer-note">
        Generated from the <a href="https://github.com/sauravbhattacharya001/gif-captcha/releases" target="_blank" rel="noopener">GitHub Releases API</a>.
        For the full commit history, see <a href="https://github.com/sauravbhattacharya001/gif-captcha/commits/master" target="_blank" rel="noopener">commits on master</a>.
    </p>
</body>
</html>
`;

fs.writeFileSync('docs/changelog.html', html);
console.log(`wrote docs/changelog.html (${html.length} bytes, ${raw.length} releases)`);
