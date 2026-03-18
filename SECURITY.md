# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.1.x   | ✅ Active support  |
| < 1.0   | ❌ End of life     |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report security issues via [GitHub's private vulnerability reporting](https://github.com/sauravbhattacharya001/gif-captcha/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce (minimal example preferred)
- Potential impact assessment
- Suggested fix, if you have one

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix timeline**: Depends on severity; critical issues targeted within 72 hours

### Scope

The following are in scope for security reports:

- **XSS vulnerabilities** in HTML pages (especially `demo.html` which handles user input)
- **CSP bypass** techniques against the Content-Security-Policy headers
- **Server-side vulnerabilities** in the Node.js CAPTCHA verification API (`src/index.js`)
- **Rate limiter bypass** in `src/captcha-rate-limiter.js`
- **Session/token manipulation** in the trust score or session risk systems
- **CAPTCHA bypass techniques** that allow automated solving without visual comprehension
- **nginx configuration weaknesses** in `nginx-security.conf`

### Out of scope

- Denial of service via high traffic (use rate limiting)
- Social engineering attacks
- Issues in development dependencies only (not shipped)

## Security Design

GIF CAPTCHA enforces defense-in-depth:

- Strict Content-Security-Policy on all pages (no external scripts/styles)
- nginx security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Input sanitization via `sanitize()` helper to prevent XSS
- Rate limiting and anomaly detection in the server-side API
- Behavioral biometrics as an additional verification signal

## Disclosure Policy

We follow coordinated disclosure. Once a fix is released, we'll credit reporters (unless they prefer anonymity) in the release notes.
