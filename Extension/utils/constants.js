/**
 * constants.js — Shared configuration, thresholds, and heuristic data for
 * Hedwig Shield's detection engine.
 *
 * All detection parameters are centralised here so they can be adjusted
 * without touching logic files.
 */

// ── Risk score thresholds ────────────────────────────────────────────────────

export const RISK_LEVELS = {
  LOW:      { min: 0,  max: 29, label: "Low Risk",    colour: "#4caf50" },
  MODERATE: { min: 30, max: 59, label: "Suspicious",  colour: "#ff9800" },
  HIGH:     { min: 60, max: 79, label: "High Risk",   colour: "#f44336" },
  CRITICAL: { min: 80, max: 100, label: "Critical",   colour: "#b71c1c" },
};

/** Threat category classifications for display. */
export const THREAT_CATEGORIES = {
  ACTIVE_PHISHING:     { id: "ACTIVE_PHISHING",     label: "ACTIVE PHISHING",     colour: "#b71c1c" },
  PHISHING_SIMULATION: { id: "PHISHING_SIMULATION", label: "PHISHING SIMULATION", colour: "#d32f2f" },
  SUSPICIOUS_WEBSITE:  { id: "SUSPICIOUS_WEBSITE",  label: "SUSPICIOUS WEBSITE",  colour: "#ff9800" },
  SAFE_WEBSITE:        { id: "SAFE_WEBSITE",        label: "SAFE WEBSITE",        colour: "#4caf50" },
};

/** Minimum score at which Hedwig shows a full-page warning. */
export const WARNING_THRESHOLD = 60;

/** Minimum score at which Hedwig blocks navigation (hard block). */
export const BLOCK_THRESHOLD = 85;

// ── Signal weights (contribution to risk score 0-100) ───────────────────────
// Each entry is the maximum points that signal can contribute.

export const SIGNAL_WEIGHTS = {
  // URL signals
  IP_ADDRESS_HOST:          30,  // URL uses a raw IP instead of a domain
  EXCESSIVE_SUBDOMAINS:     15,  // 4+ subdomain labels
  TYPOSQUATTING:            25,  // Close edit-distance to a known brand
  BRAND_IN_SUBDOMAIN:       20,  // Brand name appears in subdomain, not eTLD+1
  SUSPICIOUS_TLD:           10,  // Unusual / abused TLD
  URL_SHORTENER:            15,  // Known URL shortener domain
  ENCODED_OBFUSCATION:      20,  // Excessive % encoding or double-encoding
  AT_SIGN_IN_URL:           25,  // @ in URL (credential-style misdirection)
  LONG_DOMAIN:              10,  // Very long domain label (>50 chars)
  HOMOGRAPH_CHARS:          20,  // Mixed-script / lookalike Unicode characters
  MISLEADING_PATH:          15,  // Path contains brand names to look legitimate
  SUSPICIOUS_QUERY_PARAMS:  10,  // Query params typical in phishing (token=, verify= …)
  DATA_URI:                 40,  // data: URI scheme

  // Domain signals
  NEW_DOMAIN_PATTERN:       15,  // Domain pattern consistent with newly-registered domains
  FREE_SUBDOMAIN_SERVICE:   20,  // Known free subdomain / hosting abuse platform
  SUSPICIOUS_REGISTRAR:     10,  // (placeholder — no live WHOIS)

  // Page signals
  PASSWORD_FIELD_NO_HTTPS:  40,  // Password field on HTTP page
  LOGIN_FORM_MISMATCH:      30,  // Form POSTs to a different domain than the page
  BRAND_IMPERSONATION:      35,  // Page content impersonates a known brand
  BRAND_IN_PAGE_TITLE:      20,  // Page title contains a known brand but domain doesn't match
  HIDDEN_FORM_FIELDS:       15,  // Many hidden inputs (data harvesting pattern)
  RAPID_REDIRECT:           20,  // Page redirected quickly on load
  SENSITIVE_FORM_HTTP:      35,  // Any form requesting sensitive data over HTTP
  IFRAME_CREDENTIAL_FORM:       25,  // Login form inside a cross-origin iframe

  // Aggressive hackathon signals
  PHISHING_SIMULATION:          45,  // Explicit phishing simulation, demonstration or security test page
  CREDENTIAL_HARVESTING_FIELDS: 35,  // Standalone or embedded credential inputs (username + password)
  SOCIAL_ENGINEERING_URGENCY:   30,  // Fake update warnings, scareware or deceptive download prompts
  SECURITY_TEST_URL:            20,  // URL structure points to a known security/phishing test harness
};

// ── Known brands for impersonation / typosquatting detection ────────────────

export const KNOWN_BRANDS = [
  // Financial
  "paypal", "stripe", "visa", "mastercard", "americanexpress", "amex",
  "chase", "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
  "coinbase", "binance", "kraken", "robinhood", "etrade",

  // Tech / Cloud
  "google", "gmail", "youtube", "android", "googleplay",
  "microsoft", "outlook", "office", "azure", "onedrive", "teams", "xbox",
  "apple", "icloud", "itunes", "appstore",
  "amazon", "aws", "kindle", "alexa",
  "facebook", "instagram", "messenger", "whatsapp", "meta",
  "twitter", "x", "linkedin", "tiktok", "snapchat", "discord",
  "netflix", "spotify", "twitch",
  "github", "gitlab", "bitbucket", "digitalocean", "cloudflare",
  "dropbox", "box", "notion", "slack",
  "zoom", "webex", "meet",

  // Commerce
  "ebay", "etsy", "shopify", "walmart", "target", "bestbuy",
  "fedex", "ups", "dhl", "usps",

  // Government / ID (commonly impersonated)
  "irs", "gov", "ssa", "dmv",
];

// ── Suspicious TLDs frequently used in phishing ──────────────────────────────

export const SUSPICIOUS_TLDS = new Set([
  ".tk", ".ml", ".ga", ".cf", ".gq",   // Freenom abused TLDs
  ".xyz", ".top", ".click", ".link",
  ".buzz", ".cyou", ".icu", ".cam",
  ".monster", ".rest", ".gdn",
  ".zip", ".mov",                        // Google TLDs heavily abused in 2023+
]);

// ── Known URL shortener domains ──────────────────────────────────────────────

export const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
  "dlvr.it", "ift.tt", "adf.ly", "shorte.st", "bc.vc", "linktr.ee",
  "rb.gy", "cutt.ly", "short.io", "tiny.cc",
]);

// ── Known free subdomain / hosting abuse services ────────────────────────────

export const FREE_SUBDOMAIN_SERVICES = new Set([
  "appspot.com", "000webhostapp.com", "weebly.com", "wixsite.com", "sites.google.com",
  "blogspot.com", "wordpress.com", "web.app", "firebaseapp.com",
  "netlify.app", "vercel.app", "pages.dev", "glitch.me",
  "replit.co", "github.io", "surge.sh",
  "ngrok.io", "ngrok-free.app", "serveo.net",
]);

// ── Suspicious query parameter names typical in phishing ─────────────────────

export const PHISHING_QUERY_PARAMS = new Set([
  "verify", "validate", "confirm", "secure", "login", "signin",
  "account", "update", "token", "session", "auth", "otp",
  "redirect", "continue", "next", "return", "ref",
]);

// ── Brands that should only appear in eTLD+1, not in subdomain/path ──────────

export const PROTECTED_BRANDS_STRICT = new Set([
  "paypal", "google", "gmail", "microsoft", "outlook", "apple",
  "icloud", "amazon", "aws", "facebook", "instagram", "whatsapp",
  "twitter", "linkedin", "netflix", "bankofamerica", "chase",
  "wellsfargo", "coinbase", "binance",
]);

// ── Legitimate base domains for strict-brand checking ────────────────────────
// If the eTLD+1 matches one of these, brand signals are suppressed.

export const LEGITIMATE_DOMAINS = new Set([
  "google.com", "googleapis.com", "gstatic.com", "gmail.com",
  "youtube.com", "android.com", "chrome.com",
  "microsoft.com", "microsoftonline.com", "live.com", "office.com",
  "office365.com", "azure.com", "windows.com",
  "apple.com", "icloud.com", "itunes.com",
  "amazon.com", "amazonaws.com", "aws.amazon.com",
  "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "meta.com",
  "twitter.com", "x.com",
  "linkedin.com",
  "netflix.com",
  "paypal.com", "paypal.me",
  "coinbase.com",
  "binance.com",
  "github.com", "githubusercontent.com", "gitlab.com",
  "cloudflare.com",
  "stripe.com",
  "zoom.us",
  "slack.com",
  "dropbox.com",
  "notion.so",
  "discord.com",
  "spotify.com",
  "twitch.tv",
]);

// ── Sensitive input field name patterns ──────────────────────────────────────

export const SENSITIVE_FIELD_PATTERNS = [
  /password/i, /passwd/i, /pass\b/i,
  /\bpin\b/i, /\botp\b/i, /\b2fa\b/i, /\bmfa\b/i,
  /credit.?card/i, /card.?num/i, /\bccn\b/i, /\bcvc\b/i, /\bcvv\b/i,
  /social.?sec/i, /\bssn\b/i,
  /bank.?account/i, /routing/i,
  /secret/i, /private.?key/i,
];


// ── Phishing simulation and security test patterns ──────────────────────────

export const SIMULATION_PATTERNS = [
  /phishing (page|site|demonstration|demo|test|simulation|example)/i,
  /example of a phishing page/i,
  /social engineering (content|example|demo|test)/i,
  /security (test|testing|demonstration|demo|eval)/i,
  /antivirus (test|evaluation|demo)/i,
  /safe browsing test/i,
  /malicious (page|site|url) (example|demo|test)/i,
];

export const SIMULATION_URL_PATTERNS = [
  /testsafebrowsing/i,
  /\/s\/phishing(\.html)?/i,
  /\/demo\/phish/i,
  /\/test-phish/i,
  /wicar\.org/i,
  /smishing-demo/i,
];

export const SOCIAL_ENGINEERING_URGENCY_PATTERNS = [
  /software (is )?out.?of.?date/i,
  /browser (is )?(outdated|out.?of.?date)/i,
  /trick you into clicking ["']?update["']?/i,
  /mimics a dialogue from/i,
  /critical (security )?update required/i,
  /your (system|device|pc|mac|phone) is (infected|damaged|compromised)/i,
];

// ── Brand-impersonation text patterns (page content) ─────────────────────────

export const IMPERSONATION_TEXT_PATTERNS = [
  /your account (has been|will be) (suspended|terminated|locked)/i,
  /verify your (account|identity|information|email|phone)/i,
  /confirm your (payment|account|details|information)/i,
  /unusual (sign.?in|activity|login) (activity|attempt|detected)/i,
  /your (payment|card|account) (information|details) (is|are) (required|needed)/i,
  /click here to (verify|confirm|restore|reactivate)/i,
  /limited time/i,
  /act now/i,
  /your (password|account) (expires?|expiring)/i,
];

// ── Groq AI configuration ─────────────────────────────────────────────────────

/** Groq OpenAI-compatible chat completions endpoint. */
export const GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions";

/**
 * Default Groq model. Change this constant to switch models globally.
 * Available Groq models (free tier): llama-3.3-70b-versatile, llama3-70b-8192,
 * mixtral-8x7b-32768, gemma2-9b-it
 * Update to any model your Groq account has access to.
 */
export const GROQ_DEFAULT_MODEL = "openai/gpt-oss-120b";

/** Milliseconds before an AI request is aborted. */
export const GROQ_TIMEOUT_MS = 15_000;

/**
 * Maximum score contribution from AI analysis (0–100 total).
 * Caps how much the AI result can raise the final risk score, preventing the
 * AI from single-handedly triggering a block on a low-scored deterministic site.
 */
export const AI_MAX_SCORE_CONTRIBUTION = 40;

/**
 * Minimum AI confidence (0–100) before the AI result influences the risk score.
 * Below this threshold the AI finding is shown but does not change the score.
 */
export const AI_CONFIDENCE_THRESHOLD = 65;

/** TTL for cached AI results per URL (milliseconds). Default: 10 minutes. */
export const AI_CACHE_TTL_MS = 10 * 60 * 1000;

// ── Storage keys ─────────────────────────────────────────────────────────────

export const STORAGE_KEYS = {
  HISTORY:             "hedwig_history",
  SETTINGS:            "hedwig_settings",
  TAB_RISK:            "hedwig_tab_risk",
  AI_KEY:              "hedwig_ai_key",      // stored separately for security
  AI_SETTINGS:         "hedwig_ai_settings",
  AI_CACHE:            "hedwig_ai_cache",
  TAB_AI_RESULT:       "hedwig_tab_ai",
  BYPASS_URLS:         "hedwig_bypass_urls", // temporary user bypasses
};

/** TTL for temporary warning page bypass per URL (milliseconds). Default: 5 minutes. */
export const BYPASS_TTL_MS = 5 * 60 * 1000;

export const DEFAULT_SETTINGS = {
  enabled:           true,
  warningThreshold:  WARNING_THRESHOLD,
  blockThreshold:    BLOCK_THRESHOLD,
  showBadge:         true,
  historyLimit:      50,
};

export const DEFAULT_AI_SETTINGS = {
  aiEnabled:  false,                  // off by default until key is configured
  aiModel:    GROQ_DEFAULT_MODEL,
};

// ── Message types (between content script ↔ service worker ↔ popup) ──────────

export const MSG = {
  // content → background
  PAGE_ANALYSIS_RESULT: "PAGE_ANALYSIS_RESULT",
  // background → content
  GET_PAGE_ANALYSIS:    "GET_PAGE_ANALYSIS",
  // popup → background
  GET_TAB_RISK:         "GET_TAB_RISK",
  GET_HISTORY:          "GET_HISTORY",
  GET_SETTINGS:         "GET_SETTINGS",
  SET_SETTINGS:         "SET_SETTINGS",
  CLEAR_HISTORY:        "CLEAR_HISTORY",
  TOGGLE_PROTECTION:    "TOGGLE_PROTECTION",
  // AI
  GET_AI_SETTINGS:      "GET_AI_SETTINGS",
  SET_AI_SETTINGS:      "SET_AI_SETTINGS",
  SAVE_AI_KEY:          "SAVE_AI_KEY",
  GET_AI_KEY_STATUS:    "GET_AI_KEY_STATUS",
  CLEAR_AI_KEY:         "CLEAR_AI_KEY",
  TEST_AI_CONNECTION:   "TEST_AI_CONNECTION",
  GET_TAB_AI_RESULT:    "GET_TAB_AI_RESULT",
  // background → popup
  RISK_UPDATED:         "RISK_UPDATED",
  // warning page bypass
  SET_TEMPORARY_BYPASS: "SET_TEMPORARY_BYPASS",
  IS_URL_BYPASSED:      "IS_URL_BYPASSED",
};

