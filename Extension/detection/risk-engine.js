/**
 * risk-engine.js — Central risk aggregator for Hedwig Shield.
 *
 * Implements Hackathon Aggressive Detection Mode:
 *   Evaluates five distinct inputs:
 *     1. Domain reputation
 *     2. URL risk
 *     3. Webpage phishing characteristics
 *     4. Credential harvesting indicators
 *     5. Groq AI analysis
 *
 * Domain reputation NEVER blindly overrides suspicious webpage behavior.
 * Legitimate infrastructure (including Google test domains) hosting phishing
 * simulations or credential-harvesting pages are detected and flagged.
 *
 * Distinct threat categories:
 *   - ACTIVE PHISHING
 *   - PHISHING SIMULATION
 *   - SUSPICIOUS WEBSITE
 *   - SAFE WEBSITE
 *
 * @module detection/risk-engine
 */

import { analyseUrl    } from "./url-checker.js";
import { analyseDomain } from "./domain-checker.js";
import { analyseForms  } from "./form-analyzer.js";
import {
  RISK_LEVELS,
  THREAT_CATEGORIES,
  LEGITIMATE_DOMAINS,
  AI_MAX_SCORE_CONTRIBUTION,
  AI_CONFIDENCE_THRESHOLD,
} from "../utils/constants.js";

// ── Exported helper ───────────────────────────────────────────────────────────

/**
 * Map a numeric risk score (0-100) to its risk level label and badge colour.
 *
 * @param {number} score
 * @returns {{ label: string, colour: string }}
 */
export function getRiskLevel(score) {
  for (const level of Object.values(RISK_LEVELS)) {
    if (score >= level.min && score <= level.max) {
      return { label: level.label, colour: level.colour };
    }
  }
  return { label: RISK_LEVELS.LOW.label, colour: RISK_LEVELS.LOW.colour };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Extract the eTLD+1 hostname from a URL string.
 *
 * @param {string} urlString
 * @returns {string}
 */
function hostnameFromUrl(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * Extract approximate eTLD+1 registered domain from hostname.
 *
 * @param {string} hostname
 * @returns {string}
 */
function registeredDomainFromHostname(hostname) {
  const labels = hostname.split(".");
  return labels.length >= 2 ? labels.slice(-2).join(".") : hostname;
}

/**
 * Merge multiple signal arrays, deduplicating by signal `id`.
 *
 * @param {...Array<{id,label,weight,detail}>} signalArrays
 * @returns {Array<{id,label,weight,detail}>}
 */
function mergeSignals(...signalArrays) {
  const map = new Map();

  for (const arr of signalArrays) {
    if (!Array.isArray(arr)) continue;
    for (const signal of arr) {
      if (!signal || !signal.id) continue;
      const existing = map.get(signal.id);
      if (!existing || (signal.weight || 0) > (existing.weight || 0)) {
        map.set(signal.id, signal);
      }
    }
  }

  return [...map.values()].sort((a, b) => (b.weight || 0) - (a.weight || 0));
}

// ── Signal categorization for 5-input model ─────────────────────────────────

const CREDENTIAL_SIGNAL_IDS = new Set([
  "PASSWORD_FIELD_NO_HTTPS",
  "LOGIN_FORM_MISMATCH",
  "CREDENTIAL_HARVESTING_FIELDS",
  "SENSITIVE_FORM_HTTP",
  "IFRAME_CREDENTIAL_FORM",
  "HIDDEN_FORM_FIELDS",
]);

const WEBPAGE_SIGNAL_IDS = new Set([
  "PHISHING_SIMULATION",
  "BRAND_IMPERSONATION",
  "BRAND_IN_PAGE_TITLE",
  "SOCIAL_ENGINEERING_URGENCY",
  "RAPID_REDIRECT",
]);

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Perform a full multi-input risk assessment for a URL and optional page analysis.
 *
 * @param {string}      url          — the URL being assessed
 * @param {object|null} pageAnalysis — data from content/page-analyzer.js, or null
 * @returns {Promise<{
 *   url:           string,
 *   score:         number,
 *   level:         string,
 *   colour:        string,
 *   threatCategory:string,
 *   isSimulation:  boolean,
 *   signals:       Array<{id,label,weight,detail}>,
 *   inputs: {
 *     domainReputation:       { score: number, signals: Array, isTrusted: boolean },
 *     urlRisk:                { score: number, signals: Array },
 *     webpageCharacteristics: { score: number, signals: Array },
 *     credentialHarvesting:   { score: number, signals: Array },
 *     groqAi:                 object|null,
 *   },
 *   urlSignals:    Array,
 *   domainSignals: Array,
 *   formSignals:   Array,
 *   assessedAt:    number,
 *   isLegitimate:  boolean,
 * }>}
 */
export async function assessRisk(url, pageAnalysis) {
  const assessedAt = Date.now();
  const hostname   = hostnameFromUrl(url);
  const regDomain  = registeredDomainFromHostname(hostname);
  const isTrustedDomain = LEGITIMATE_DOMAINS.has(regDomain);

  // ── Parallel detection ────────────────────────────────────────────────────
  const [urlResult, domainResult] = await Promise.all([
    analyseUrl(url),
    analyseDomain(hostname),
  ]);

  let formResult = { signals: [], score: 0 };
  if (pageAnalysis !== null && pageAnalysis !== undefined) {
    formResult = analyseForms(pageAnalysis, url);
  }

  // ── Separate into the 4 deterministic inputs ──────────────────────────────
  // Input 1: Domain reputation
  const domainSignals = domainResult.signals || [];
  const domainScore   = domainSignals.reduce((s, sig) => s + (sig.weight || 0), 0);

  // Input 2: URL risk
  const urlSignals = urlResult.signals || [];
  const urlScore   = urlSignals.reduce((s, sig) => s + (sig.weight || 0), 0);

  // Inputs 3 & 4: Webpage characteristics vs Credential harvesting
  const pageSignals = formResult.signals || [];
  const credentialSignals = pageSignals.filter((s) => CREDENTIAL_SIGNAL_IDS.has(s.id));
  const credentialScore   = credentialSignals.reduce((s, sig) => s + (sig.weight || 0), 0);

  const webpageSignals = pageSignals.filter((s) => WEBPAGE_SIGNAL_IDS.has(s.id));
  const webpageScore   = webpageSignals.reduce((s, sig) => s + (sig.weight || 0), 0);

  // ── Multi-input Signal Aggregation ────────────────────────────────────────
  const allSignals = mergeSignals(urlSignals, domainSignals, pageSignals);

  // ── Aggressive Hackathon Detection Rules ──────────────────────────────────
  // Check for simulation indicators
  const isSimulation = allSignals.some((s) =>
    s.id === "PHISHING_SIMULATION" || s.id === "SECURITY_TEST_URL"
  );

  let rawScore = allSignals.reduce((sum, sig) => sum + (sig.weight || 0), 0);

  // If page is on a trusted domain:
  // - A clean page on google.com or github.com with no page-level phishing indicators stays 0.
  // - BUT if it has phishing simulation or credential harvesting or social engineering,
  //   domain reputation DOES NOT suppress those indicators!
  let score = 0;
  let isLegitimate = false;

  if (isTrustedDomain) {
    if (pageSignals.length === 0 && urlSignals.length === 0) {
      // Entirely benign navigation on trusted domain (e.g. google search, github code)
      score = 0;
      isLegitimate = true;
    } else {
      // Trusted domain hosting suspicious / simulation / harvesting content
      // Score based directly on the observed webpage + credential + URL signals
      score = Math.min(100, rawScore);
      isLegitimate = false;
    }
  } else {
    // Untrusted / general domain
    score = Math.min(100, rawScore);
  }

  // ── Threat Classification ─────────────────────────────────────────────────
  let threatCategory = THREAT_CATEGORIES.SAFE_WEBSITE.id;

  if (isSimulation && (score >= 40 || credentialSignals.length > 0 || webpageSignals.length > 0)) {
    // Phishing simulation or security test page
    threatCategory = THREAT_CATEGORIES.PHISHING_SIMULATION.id;
    // Ensure simulation has high/critical severity in hackathon aggressive mode
    score = Math.max(score, 75);
  } else if (score >= 60 || credentialScore >= 35) {
    // Active phishing or strong credential harvesting
    threatCategory = THREAT_CATEGORIES.ACTIVE_PHISHING.id;
  } else if (score >= 30) {
    threatCategory = THREAT_CATEGORIES.SUSPICIOUS_WEBSITE.id;
  } else {
    threatCategory = THREAT_CATEGORIES.SAFE_WEBSITE.id;
  }

  const { label: level, colour } = getRiskLevel(score);

  return {
    url,
    score,
    level,
    colour,
    threatCategory,
    isSimulation,
    signals:       allSignals,
    inputs: {
      domainReputation:       { score: domainScore, signals: domainSignals, isTrusted: isTrustedDomain },
      urlRisk:                { score: urlScore, signals: urlSignals },
      webpageCharacteristics: { score: webpageScore, signals: webpageSignals },
      credentialHarvesting:   { score: credentialScore, signals: credentialSignals },
      groqAi:                 null,
    },
    urlSignals,
    domainSignals,
    formSignals:   pageSignals,
    assessedAt,
    isLegitimate,
  };
}

// ── AI result merger ──────────────────────────────────────────────────────────

/**
 * Merge a validated AI analysis result into an existing deterministic risk result.
 *
 * In Hackathon Aggressive Detection Mode:
 *  - AI can identify phishing or phishing simulations regardless of domain reputation.
 *  - If AI identifies a simulation, threat category is set to PHISHING_SIMULATION and score is boosted.
 *  - If AI identifies active phishing with high confidence, score is boosted.
 *
 * @param {object} deterministicResult — full output from assessRisk()
 * @param {object} aiResult            — validated output from phishing-analyzer.js
 * @returns {object} combined result with aiResult and aiSignals merged in
 */
export function mergeAiResult(deterministicResult, aiResult) {
  if (!aiResult || !aiResult.success) {
    return { ...deterministicResult, aiResult, aiSignals: [] };
  }

  const aiSignals = buildAiSignals(aiResult);
  let scoreBoost = 0;
  let threatCategory = deterministicResult.threatCategory;
  let isSimulation = deterministicResult.isSimulation;

  // Check if AI detected a simulation
  if (aiResult.isSimulation || aiResult.threatCategory === "PHISHING_SIMULATION") {
    threatCategory = THREAT_CATEGORIES.PHISHING_SIMULATION.id;
    isSimulation = true;
    // Boost simulation score so it crosses warning/block threshold
    scoreBoost = Math.max(scoreBoost, 35);
  } else if (aiResult.isPhishing) {
    if (threatCategory === THREAT_CATEGORIES.SAFE_WEBSITE.id || threatCategory === THREAT_CATEGORIES.SUSPICIOUS_WEBSITE.id) {
      threatCategory = THREAT_CATEGORIES.ACTIVE_PHISHING.id;
    }
  }

  // Calculate score boost based on AI confidence
  if (aiResult.confidence >= AI_CONFIDENCE_THRESHOLD && (aiResult.isPhishing || isSimulation)) {
    const confidenceRatio = (aiResult.confidence - AI_CONFIDENCE_THRESHOLD) /
                            (100 - AI_CONFIDENCE_THRESHOLD);
    scoreBoost = Math.max(scoreBoost, Math.round(AI_MAX_SCORE_CONTRIBUTION * confidenceRatio));
  }

  let combinedScore = Math.min(100, deterministicResult.score + scoreBoost);

  // If simulation or active phishing, ensure score is at least warning threshold
  if (threatCategory === THREAT_CATEGORIES.PHISHING_SIMULATION.id) {
    combinedScore = Math.max(combinedScore, 80);
  } else if (threatCategory === THREAT_CATEGORIES.ACTIVE_PHISHING.id && aiResult.confidence >= 80) {
    combinedScore = Math.max(combinedScore, 75);
  }

  const { label: level, colour } = getRiskLevel(combinedScore);

  return {
    ...deterministicResult,
    score:          combinedScore,
    level,
    colour,
    threatCategory,
    isSimulation,
    aiResult,
    aiSignals,
    aiScoreBoost:   scoreBoost,
    inputs: {
      ...deterministicResult.inputs,
      groqAi: aiResult,
    },
  };
}

/**
 * Convert an AI result into displayable signal objects.
 * @param {object} aiResult
 * @returns {Array<{id, label, weight, detail, source}>}
 */
function buildAiSignals(aiResult) {
  if (!aiResult?.success || (!aiResult.isPhishing && !aiResult.isSimulation)) return [];

  const signals = [];

  if (aiResult.isSimulation) {
    signals.push({
      id:     "AI_PHISHING_SIMULATION",
      label:  "Phishing simulation / security demonstration detected",
      weight: 40,
      detail: `Deep behavioral analysis detected a security test or phishing demonstration (${aiResult.confidence}% confidence).`,
      source: "ai",
    });
  }

  if (aiResult.impersonatedBrand) {
    signals.push({
      id:     "AI_BRAND_IMPERSONATION",
      label:  `Brand impersonation — ${aiResult.impersonatedBrand}`,
      weight: Math.round(aiResult.confidence * 0.3),
      detail: `Deep behavioral analysis identified impersonation of ${aiResult.impersonatedBrand} with ${aiResult.confidence}% confidence.`,
      source: "ai",
    });
  }

  if (aiResult.reasons && aiResult.reasons.length > 0) {
    aiResult.reasons.forEach((reason, i) => {
      signals.push({
        id:     `AI_REASON_${i}`,
        label:  reason,
        weight: 0,
        detail: `Deep behavioral threat inspection (${aiResult.confidence}% confidence)`,
        source: "ai",
      });
    });
  }

  return signals;
}
