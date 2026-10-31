/**
 * phishing-analyzer.js — AI-powered phishing analysis for Hedwig Shield.
 *
 * Orchestrates the full AI analysis pipeline:
 *   1. Accepts sanitized page metadata + deterministic signals.
 *   2. Builds a prompt via prompt-builder.js.
 *   3. Calls Groq via groq-client.js.
 *   4. Validates and normalises the response.
 *   5. Returns a structured result safe to consume by risk-engine.js.
 *
 * This module never executes code from the AI response. The JSON is only
 * used for its typed fields — validated against a strict schema.
 */

import { callGroq, extractContent, GroqError, GroqErrorKind } from "./groq-client.js";
import { buildPhishingPrompt }                                  from "./prompt-builder.js";
import { GROQ_DEFAULT_MODEL }                                   from "../utils/constants.js";

// ── Result schema ─────────────────────────────────────────────────────────────

/**
 * @typedef {object} AiAnalysisResult
 * @property {boolean}  success           — false on any error
 * @property {boolean}  isPhishing
 * @property {number}   confidence        — 0-100
 * @property {string}   riskLevel         — "low"|"moderate"|"high"|"critical"
 * @property {string|null} impersonatedBrand
 * @property {string[]} reasons
 * @property {string}   recommendation    — "Allow"|"Warn"|"Block"
 * @property {string}   [errorKind]       — set when success===false
 * @property {string}   [errorMessage]    — human-readable error description
 * @property {boolean}  [fromCache]       — true if result came from cache
 */

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Run AI-powered phishing analysis on sanitized page data.
 *
 * @param {object} opts
 * @param {object}   opts.pageData     — sanitized data from page-analyzer.js
 * @param {object[]} opts.deterministicSignals — signals from risk-engine
 * @param {string}   opts.apiKey       — user's Groq API key from storage
 * @param {string}  [opts.model]       — Groq model ID (default: GROQ_DEFAULT_MODEL)
 * @returns {Promise<AiAnalysisResult>}
 */
export async function analyzeWithGroq({
  pageData,
  deterministicSignals = [],
  apiKey,
  model = GROQ_DEFAULT_MODEL,
}) {
  if (!apiKey) {
    return failResult("INVALID_KEY", "No API key configured. Add your Groq API key in Settings.");
  }

  // Build the prompt with sanitized data
  const messages = buildPhishingPrompt({
    url:                  pageData.url            ?? "",
    hostname:             hostnameFromUrl(pageData.url ?? ""),
    pageTitle:            pageData.pageTitle       ?? "",
    headings:             pageData.headings        ?? "",
    bodyText:             pageData.bodyText        ?? "",
    hasPasswordField:     pageData.hasPasswordField ?? false,
    hasLoginForm:         pageData.hasLoginForm    ?? false,
    hasCredentialFields:  pageData.hasCredentialFields ?? false,
    formTargets:          pageData.formTargets     ?? [],
    isHttp:               pageData.isHttp          ?? false,
    hasSensitiveFields:   pageData.hasSensitiveFields ?? false,
    hiddenFieldCount:     pageData.hiddenFieldCount ?? 0,
    deterministicSignals: deterministicSignals.map(s => s.label ?? s.id ?? ""),
  });

  let rawResponse;
  try {
    rawResponse = await callGroq({ apiKey, model, messages, maxTokens: 512, temperature: 0.1 });
  } catch (err) {
    const kind = err instanceof GroqError ? err.kind : GroqErrorKind.UNKNOWN;
    return failResult(kind, err.message);
  }

  // Extract and validate the JSON response
  const content = extractContent(rawResponse);
  return parseAndValidate(content);
}

// ── Response validation ───────────────────────────────────────────────────────

/**
 * Parse and strictly validate the model's JSON output.
 * Treats the AI response as untrusted data — never executes anything from it.
 *
 * @param {string} content — raw text from model
 * @returns {AiAnalysisResult}
 */
function parseAndValidate(content) {
  if (!content || typeof content !== "string") {
    return failResult("PARSE_ERROR", "Model returned an empty response.");
  }

  // Extract JSON from content (model may wrap it in markdown fences)
  const jsonString = extractJson(content);
  if (!jsonString) {
    return failResult("PARSE_ERROR", "Model response did not contain valid JSON.");
  }

  let parsed;
  try {
    parsed = JSON.parse(jsonString);
  } catch (_) {
    return failResult("PARSE_ERROR", "Model response JSON could not be parsed.");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return failResult("PARSE_ERROR", "Model returned unexpected JSON structure.");
  }

  // ── Field validation and safe extraction ──────────────────────────────────
  const isPhishing = !!parsed.is_phishing;
  const isSimulation = !!parsed.is_simulation || parsed.threat_category === "PHISHING_SIMULATION";

  const confidence = clampInt(parsed.confidence, 0, 100, 50);

  const VALID_CATEGORIES = new Set(["ACTIVE_PHISHING", "PHISHING_SIMULATION", "SUSPICIOUS_WEBSITE", "SAFE_WEBSITE"]);
  let threatCategory = "SAFE_WEBSITE";
  if (VALID_CATEGORIES.has(parsed.threat_category)) {
    threatCategory = parsed.threat_category;
  } else if (isSimulation) {
    threatCategory = "PHISHING_SIMULATION";
  } else if (isPhishing) {
    threatCategory = "ACTIVE_PHISHING";
  } else if (confidence >= 40) {
    threatCategory = "SUSPICIOUS_WEBSITE";
  }

  const VALID_RISK_LEVELS = new Set(["low", "suspicious", "moderate", "high", "critical"]);
  const riskLevel = VALID_RISK_LEVELS.has(parsed.risk_level)
    ? (parsed.risk_level === "moderate" ? "suspicious" : parsed.risk_level)
    : deriveRiskLevel(confidence);

  // Sanitize brand: string, max 60 chars, no HTML
  const impersonatedBrand = (typeof parsed.impersonated_brand === "string" && parsed.impersonated_brand.trim())
    ? parsed.impersonated_brand.replace(/[<>&"']/g, "").slice(0, 60)
    : null;

  // Sanitize reasons: array of strings, max 8 items, each max 200 chars
  const reasons = Array.isArray(parsed.reasons)
    ? parsed.reasons
        .filter(r => typeof r === "string" && r.trim())
        .map(r => r.replace(/[<>&"']/g, "").slice(0, 200))
        .slice(0, 8)
    : [];

  const VALID_RECOMMENDATIONS = new Set(["Allow", "Warn", "Block"]);
  const recommendation = VALID_RECOMMENDATIONS.has(parsed.recommendation)
    ? parsed.recommendation
    : (isPhishing || isSimulation) ? "Warn" : "Allow";

  return {
    success:          true,
    isPhishing:       isPhishing || isSimulation,
    isSimulation,
    threatCategory,
    confidence,
    riskLevel,
    impersonatedBrand,
    reasons,
    recommendation,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a failure result with no phishing assertion. */
function failResult(kind, message) {
  return {
    success:          false,
    isPhishing:       false,
    isSimulation:     false,
    threatCategory:   "SAFE_WEBSITE",
    confidence:       0,
    riskLevel:        "low",
    impersonatedBrand: null,
    reasons:          [],
    recommendation:   "Allow",
    errorKind:        kind,
    errorMessage:     message,
  };
}

/** Extract a JSON object from text, handling markdown code fences. */
function extractJson(text) {
  // Try direct parse first
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return trimmed;

  // Strip markdown fences: ```json ... ``` or ``` ... ```
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]+?)\s*```/);
  if (fenceMatch) return fenceMatch[1].trim();

  // Try to find first { ... } block
  const braceStart = trimmed.indexOf("{");
  const braceEnd   = trimmed.lastIndexOf("}");
  if (braceStart !== -1 && braceEnd > braceStart) {
    return trimmed.slice(braceStart, braceEnd + 1);
  }

  return null;
}

/** Clamp a value to [min, max], defaulting to fallback if not a number. */
function clampInt(val, min, max, fallback) {
  const n = parseInt(val, 10);
  if (isNaN(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

/** Derive risk level from confidence when model omits it. */
function deriveRiskLevel(confidence) {
  if (confidence >= 80) return "critical";
  if (confidence >= 60) return "high";
  if (confidence >= 35) return "moderate";
  return "low";
}

/** Extract hostname from a URL string. */
function hostnameFromUrl(urlString) {
  try { return new URL(urlString).hostname.toLowerCase(); }
  catch (_) { return urlString.slice(0, 80); }
}

