/**
 * prompt-builder.js — Constructs sanitized prompts for Groq phishing analysis.
 *
 * Implements Hackathon Aggressive Detection Mode:
 *   Instructs the model to evaluate actual webpage behaviour, forms, credential
 *   collection, and social engineering patterns independently of domain reputation.
 *
 * PRIVACY CONTRACT
 * ─────────────────
 * This module MUST NOT receive or include:
 *   • Form field values (passwords, OTPs, credit-card numbers, etc.)
 *   • Authentication tokens or session cookies
 *   • Any value that the user has typed into a form
 *
 * It only receives sanitized structural metadata collected by page-analyzer.js.
 */

// Maximum characters of body text to send (keeps token cost predictable).
const MAX_BODY_TEXT_CHARS = 800;

// Maximum URL length to include (prevents prompt injection via very long URLs).
const MAX_URL_CHARS = 300;

// Maximum page title length.
const MAX_TITLE_CHARS = 120;

// ── System prompt (Hackathon Aggressive Detection Mode) ──────────────────────

const SYSTEM_PROMPT = `You are analysing webpages for a cybersecurity phishing protection demonstration. Your job is to identify phishing characteristics and social engineering behaviour, not merely determine whether the hostname is reputable.

A legitimate website may intentionally host a phishing simulation or security test. Do not dismiss phishing indicators because the domain is trusted or the page identifies itself as a demonstration.

Evaluate the page's actual content, forms, credential collection behaviour, impersonation patterns and submission destinations.

Distinguish between:
- Active malicious phishing.
- Phishing simulation or security demonstration.
- Legitimate page without phishing characteristics.

For this hackathon's aggressive detection mode, both active phishing and phishing simulations exhibiting clear phishing behaviour should trigger a protection warning.

Never invent evidence. Explain exactly which observed indicators caused your verdict.

Return ONLY a JSON object with exactly this structure:
{
  "is_phishing": boolean,
  "is_simulation": boolean,
  "confidence": number,
  "risk_level": "low" | "suspicious" | "high" | "critical",
  "threat_category": "ACTIVE_PHISHING" | "PHISHING_SIMULATION" | "SUSPICIOUS_WEBSITE" | "SAFE_WEBSITE",
  "impersonated_brand": string | null,
  "reasons": string[],
  "recommendation": "Allow" | "Warn" | "Block"
}

Rules:
- Base your analysis only on the data provided. Do not hallucinate.
- "confidence" reflects how certain you are (0-100), not the severity.
- If the page is a security test, demo, or phishing simulation (e.g., Google Safe Browsing test), set "is_phishing": true, "is_simulation": true, "threat_category": "PHISHING_SIMULATION", and "recommendation": "Warn" or "Block".
- "reasons" must list the specific signals you observed, not generic statements.
- "impersonated_brand" is null if no specific brand is being impersonated.
- Return ONLY the JSON object. No markdown, no backticks, no extra text.`;

// ── Builder ───────────────────────────────────────────────────────────────────

/**
 * Build the messages array for a Groq chat completion phishing analysis request.
 *
 * @param {object} data
 * @param {string}   data.url               — full URL being analysed
 * @param {string}   data.hostname          — hostname only
 * @param {string}   data.pageTitle         — document.title (sanitized)
 * @param {string}   data.headings          — page H1/H2/H3 text
 * @param {string}   data.bodyText          — visible page text (sanitized, truncated)
 * @param {boolean}  data.hasPasswordField  — page has a password input
 * @param {boolean}  data.hasLoginForm      — page has a login form
 * @param {boolean}  data.hasCredentialFields — credential fields detected
 * @param {string[]} data.formTargets       — form action URLs (domains only, no values)
 * @param {boolean}  data.isHttp            — page served over HTTP
 * @param {boolean}  data.hasSensitiveFields — sensitive field names detected
 * @param {number}   data.hiddenFieldCount  — number of hidden inputs
 * @param {string[]} data.deterministicSignals — labels of fired deterministic signals
 * @returns {{ role: string, content: string }[]}
 */
export function buildPhishingPrompt(data) {
  const url       = sanitizeText(data.url       ?? "", MAX_URL_CHARS);
  const title     = sanitizeText(data.pageTitle  ?? "", MAX_TITLE_CHARS);
  const headings  = sanitizeText(data.headings   ?? "", 300);
  const bodyText  = sanitizeText(data.bodyText   ?? "", MAX_BODY_TEXT_CHARS);
  const hostname  = sanitizeText(data.hostname   ?? "", 120);

  // Summarise form targets as domains only — not full URLs with paths
  const formDomains = (data.formTargets ?? [])
    .map(urlToDomain)
    .filter(Boolean)
    .slice(0, 5);

  // Deterministic signals from Hedwig's rule engine (labels only, no scoring)
  const detSignals = (data.deterministicSignals ?? []).slice(0, 15).join("; ") || "none";

  const userContent = `
=== PAGE METADATA ===
URL: ${url}
Hostname: ${hostname}
Protocol: ${data.isHttp ? "HTTP (insecure)" : "HTTPS"}

=== PAGE CONTENT & HEADINGS ===
Title: ${title || "(none)"}
Headings: ${headings || "(none)"}
Visible text sample (up to 800 chars):
${bodyText || "(no text)"}

=== FORM & CREDENTIAL STRUCTURE ===
Has password field: ${data.hasPasswordField ? "yes" : "no"}
Has login form: ${data.hasLoginForm ? "yes" : "no"}
Has credential fields: ${data.hasCredentialFields ? "yes" : "no"}
Has sensitive field names: ${data.hasSensitiveFields ? "yes" : "no"}
Hidden field count: ${data.hiddenFieldCount ?? 0}
Form submission domains: ${formDomains.length > 0 ? formDomains.join(", ") : "none"}

=== DETERMINISTIC SIGNALS (from Hedwig rule engine) ===
${detSignals}

Analyse this page for phishing and simulation behavior. Return ONLY the JSON object.`.trim();

  return [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user",   content: userContent },
  ];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Truncate a string and strip null bytes / control chars.
 * @param {string} text
 * @param {number} maxLen
 * @returns {string}
 */
function sanitizeText(text, maxLen) {
  if (typeof text !== "string") return "";
  return text
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .slice(0, maxLen);
}

/**
 * Extract the hostname from a URL string; returns empty string on failure.
 * @param {string} urlString
 * @returns {string}
 */
function urlToDomain(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch (_) {
    return "";
  }
}
