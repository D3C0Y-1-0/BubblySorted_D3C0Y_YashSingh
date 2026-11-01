/**
 * risk-engine.js — Central risk aggregator for Hedwig Shield.
 *
 *   Evaluates five distinct inputs:
 *     1. Domain reputation
 *     2. URL risk
 *     3. Webpage phishing characteristics
 *     4. Credential harvesting indicators
 *     5. Groq AI analysis
 *
 * Domain reputation does not hide suspicious page behaviour: a trusted host
 * serving a phishing test page or a credential form with phishing indicators
 * is still scored on those indicators.
 *
 * The score is the sum of the signals that fired; nothing raises it to a
 * fixed floor. Threat categories (ACTIVE_PHISHING, PHISHING_SIMULATION, shown
 * as "Phishing test page", SUSPICIOUS_WEBSITE, SAFE_WEBSITE) follow the score.
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

  // Known phishing test page (published test URL, or test wording beside a login form)
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

  if (isSimulation && score >= 40) {
    threatCategory = THREAT_CATEGORIES.PHISHING_SIMULATION.id;
  } else if (score >= 60) {
    // Only call it phishing when the evidence reaches the warning threshold.
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
 * The model's verdict is untrusted input. It only counts when:
 *  - its confidence is at least AI_CONFIDENCE_THRESHOLD, and
 *  - it names the specific reasons it saw (a bare "phishing: true" is ignored).
 * Even then it adds at most AI_MAX_SCORE_CONTRIBUTION points, so the AI alone
 * can never push a clean page over the warning threshold.
 *
 * @param {object} deterministicResult — full output from assessRisk()
 * @param {object} aiResult            — validated output from phishing-analyzer.js
 * @returns {object} combined result with aiResult and aiSignals merged in
 */
export function mergeAiResult(deterministicResult, aiResult) {
  if (!aiResult || !aiResult.success) {
    return { ...deterministicResult, aiResult, aiSignals: [] };
  }

  const counts = aiResult.confidence >= AI_CONFIDENCE_THRESHOLD &&
                 Array.isArray(aiResult.reasons) && aiResult.reasons.length > 0 &&
                 (aiResult.isPhishing || aiResult.isSimulation);
  if (!counts) {
    return { ...deterministicResult, aiResult, aiSignals: [], aiScoreBoost: 0,
             inputs: { ...deterministicResult.inputs, groqAi: aiResult } };
  }

  const aiSignals = buildAiSignals(aiResult);
  const isSimulation = deterministicResult.isSimulation || !!aiResult.isSimulation;

  // Scale the boost with confidence above the threshold: 65% -> 0, 100% -> the cap.
  const confidenceRatio = (aiResult.confidence - AI_CONFIDENCE_THRESHOLD) /
                          (100 - AI_CONFIDENCE_THRESHOLD);
  const scoreBoost = Math.round(AI_MAX_SCORE_CONTRIBUTION * confidenceRatio);
  const combinedScore = Math.min(100, deterministicResult.score + scoreBoost);

  // The category follows the combined score, same rules as assessRisk().
  let threatCategory = THREAT_CATEGORIES.SAFE_WEBSITE.id;
  if (isSimulation && combinedScore >= 40) {
    threatCategory = THREAT_CATEGORIES.PHISHING_SIMULATION.id;
  } else if (combinedScore >= 60) {
    threatCategory = THREAT_CATEGORIES.ACTIVE_PHISHING.id;
  } else if (combinedScore >= 30) {
    threatCategory = THREAT_CATEGORIES.SUSPICIOUS_WEBSITE.id;
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

  // These are the model's own words. They are labelled as AI opinion and carry
  // no weight of their own: the score effect is the capped boost in mergeAiResult().
  const note = `AI model opinion (${aiResult.confidence}% confidence), not independently verified.`;

  if (aiResult.isSimulation) {
    signals.push({
      id:     "AI_PHISHING_SIMULATION",
      label:  "AI: looks like a phishing test page",
      weight: 0,
      detail: note,
      source: "ai",
    });
  }

  if (aiResult.impersonatedBrand) {
    signals.push({
      id:     "AI_BRAND_IMPERSONATION",
      label:  `AI: may be impersonating ${aiResult.impersonatedBrand}`,
      weight: 0,
      detail: note,
      source: "ai",
    });
  }

  if (aiResult.reasons && aiResult.reasons.length > 0) {
    aiResult.reasons.forEach((reason, i) => {
      signals.push({
        id:     `AI_REASON_${i}`,
        label:  `AI: ${reason}`,
        weight: 0,
        detail: note,
        source: "ai",
      });
    });
  }

  return signals;
}
