# Hedwig Shield

> Real-time phishing and malicious website protection — a Chrome extension built as part of the Hedwig threat early warning system.

---

## What it does

Hedwig Shield analyses every website you visit and scores it for phishing risk before you interact with it. It detects:

- **Phishing and fake login pages** — login forms that POST credentials to a different domain.
- **Brand impersonation** — pages that mimic PayPal, Google, Microsoft, Apple, and other major brands.
- **Typosquatting and lookalike domains** — domains within edit distance of known brands (e.g. `paypa1.com`).
- **Suspicious URLs** — IP-address hosts, excessive subdomains, URL shorteners, homograph characters, suspicious TLDs.
- **Credential harvesting forms** — password fields over HTTP, forms with many hidden fields, cross-origin iframes containing login forms.
- **Redirect tricks** — meta-refresh redirects, brand names buried in URL paths.

When a high-risk site is detected, Hedwig Shield intercepts navigation and shows a full-page warning before you can submit any information.

---

## Installation (Developer / Unpacked)

Chrome does not auto-install unpacked extensions. Follow these steps:

### 1. Generate icons

Icons must be PNG files. Open the generator in Chrome:

1. In Chrome, open **File › Open File** (or `Ctrl+O`).
2. Navigate to `Extension/assets/generate-icons.html`.
3. Click each **Download** button to save `icon16.png`, `icon32.png`, `icon48.png`, `icon128.png`.
4. Move all four PNG files into `Extension/assets/icons/`.

### 2. Load the extension

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked**.
4. Select the `Extension/` folder (not the repository root).
5. Hedwig Shield appears in your toolbar. Pin it from the Extensions menu (🧩).

### 3. Verify it works

1. Navigate to any HTTP login page (e.g. a test phishing site from `https://www.phishtank.com/`).
2. The Hedwig Shield badge should show a non-zero risk score.
3. High-risk sites (score ≥ 60) trigger the warning page automatically.

---

## Architecture

```
Extension/
├── manifest.json               MV3 manifest — permissions, icons, CSP
├── background/
│   └── service-worker.js       Background worker: navigation events, risk orchestration, badge
├── content/
│   └── page-analyzer.js        Content script: DOM inspection, form detection (read-only)
├── detection/
│   ├── url-checker.js          URL heuristics: IP hosts, typosquatting, TLDs, encoding
│   ├── domain-checker.js       Domain pattern analysis: entropy, free hosting, hyphenated brands
│   ├── form-analyzer.js        Form/credential signals from page analysis data
│   └── risk-engine.js          Central aggregator: merges signals, computes 0-100 score
├── ui/
│   ├── popup.html / .css / .js Extension popup: risk dashboard, history, settings
│   ├── warning.html / .css / .js Full-page warning shown for high-risk sites
├── utils/
│   ├── constants.js            All thresholds, brand lists, signal weights
│   └── storage.js              chrome.storage.local wrappers
└── assets/
    ├── icons/                  PNG icons (generated via generate-icons.html)
    └── generate-icons.html     Icon generator (open in Chrome)
```

### Detection pipeline

```
URL committed
     │
     ▼
url-checker.js ──────┐
domain-checker.js ───┼──► risk-engine.js ──► score + signals
                     │              │
page-analyzer.js ────┘              ▼
(content script,              setTabRisk()
 runs after DOM ready)         updateBadge()
                               ─ score ≥ 60? → redirect to warning.html
                               ─ score ≥ 30? → append to history
```

### Signal weights

Each detected signal contributes a fixed number of points toward the 0–100 risk score:

| Signal | Points | Description |
|--------|--------|-------------|
| `DATA_URI` | 40 | data: URL scheme |
| `PASSWORD_FIELD_NO_HTTPS` | 40 | Password input on HTTP page |
| `SENSITIVE_FORM_HTTP` | 35 | Sensitive form on HTTP |
| `BRAND_IMPERSONATION` | 35 | Impersonation language in page text |
| `LOGIN_FORM_MISMATCH` | 30 | Form POSTs to different domain |
| `IP_ADDRESS_HOST` | 30 | Raw IP address instead of domain |
| `TYPOSQUATTING` | 25 | Domain close to known brand |
| `AT_SIGN_IN_URL` | 25 | @ in URL authority |
| `IFRAME_CREDENTIAL_FORM` | 25 | Cross-origin iframe with login form |
| `FREE_SUBDOMAIN_SERVICE` | 20 | Known free hosting platform |
| `ENCODED_OBFUSCATION` | 20 | Double-encoded URL |
| `HOMOGRAPH_CHARS` | 20 | Non-ASCII domain characters |
| `RAPID_REDIRECT` | 20 | Meta-refresh redirect |
| `BRAND_IN_SUBDOMAIN` | 20 | Brand in subdomain, not eTLD+1 |
| `EXCESSIVE_SUBDOMAINS` | 15 | 4+ subdomain labels |
| `URL_SHORTENER` | 15 | Known URL shortener |
| `HIDDEN_FORM_FIELDS` | 15 | >5 hidden form inputs |
| `MISLEADING_PATH` | 15 | Brand name in URL path |
| `NEW_DOMAIN_PATTERN` | 15 | High-entropy or hyphenated-brand domain |
| `SUSPICIOUS_QUERY_PARAMS` | 10 | `verify=`, `token=`, etc. in query |
| `SUSPICIOUS_TLD` | 10 | Abused TLD (.tk, .xyz, .zip, …) |
| `LONG_DOMAIN` | 10 | Domain label >40 characters |

Scores cap at 100. Legitimate domains (google.com, paypal.com, etc.) are whitelisted and return score 0.

### Risk levels

| Score | Level | Behaviour |
|-------|-------|-----------|
| 0–29 | Low Risk (🟢) | Badge shown, no interruption |
| 30–59 | Suspicious (🟠) | Badge shown, added to history |
| 60–79 | High Risk (🔴) | Full-page warning shown |
| 80–100 | Critical (🔴) | Full-page warning shown |

---

## Privacy

Hedwig Shield is fully client-side. It:

- **Does not transmit your browsing history** to any server.
- **Does not collect form values, passwords, or OTPs** — the content script reads only structural DOM properties (field types, form action URLs, field counts).
- **Does not require a user account or authentication.**
- Stores detection history only in `chrome.storage.local` on your own device.

### Permissions requested

| Permission | Why |
|-----------|-----|
| `storage` | Save settings and detection history locally |
| `tabs` | Read the active tab's URL and update the badge |
| `webNavigation` | Intercept navigation events to run URL analysis before page loads |
| `activeTab` | Allow the popup to read the current tab |
| `declarativeNetRequest` | Reserved for future static block rules |
| `http://*/*` `https://*/*` | Inject content script to inspect page structure |

---

## Known limitations and false positives

- **No live threat intelligence.** Detection is entirely heuristic. Hedwig Shield does not query VirusTotal, Google Safe Browsing, or any external API.
- **No WHOIS / domain age.** Domain age is a strong phishing signal but requires a live API. Hedwig uses pattern-based entropy heuristics as a proxy.
- **Legitimate sites may score > 0.** Sites with many hidden form fields, meta-refresh redirects, or brand names in subdomain paths may receive moderate scores. Review the signals list before proceeding.
- **Shortened URLs are not followed.** If a URL shortener redirects to a malicious site, only the shortener domain is checked — the final destination is not pre-fetched.
- **MV3 navigation timing.** Chrome MV3 does not allow asynchronous JavaScript to block navigation synchronously. Hedwig Shield detects and warns after navigation commits (the page has started loading) but before the user can interact with it (content script fires on `document_idle`).

---

## Development

No build step. The extension runs directly from source.

To reload after edits:
1. Go to `chrome://extensions`.
2. Click the refresh icon (↺) on the Hedwig Shield card.

To inspect the service worker:
1. On `chrome://extensions`, click **Service worker** under Hedwig Shield.
2. This opens DevTools for the background worker.

To inspect content script or popup:
- Right-click the extension popup → **Inspect**.
- On any page → DevTools → **Sources** → **Content scripts**.

---

## Contributing

This extension is part of the Hedwig threat early warning system. See the main project README for the overall architecture.

Detection logic lives in `detection/`. To improve detection accuracy:
1. Add new signal IDs and weights to `utils/constants.js`.
2. Implement the detector in the appropriate `detection/*.js` module.
3. The `risk-engine.js` aggregates all signals automatically.

