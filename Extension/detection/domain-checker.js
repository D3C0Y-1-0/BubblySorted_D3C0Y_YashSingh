/**
 * domain-checker.js — Static domain-pattern reputation analysis for Hedwig Shield.
 *
 * IMPORTANT: This module does NOT perform live WHOIS, DNS, or SSL lookups.
 * Scores reflect static heuristics only. All signals are derived from the
 * structural and lexical properties of the domain name itself.
 *
 * @module detection/domain-checker
 */

import {
  SIGNAL_WEIGHTS,
  SUSPICIOUS_TLDS,
  FREE_SUBDOMAIN_SERVICES,
  KNOWN_BRANDS,
} from "../utils/constants.js";

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Compute the Shannon entropy of a string (bits per character).
 * High entropy correlates with randomly generated labels common in DGA domains.
 *
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Count consecutive consonants in a string.
 * Long consonant clusters (e.g. "xkpzt") are rare in real words and common
 * in algorithmically generated domain labels.
 *
 * @param {string} str
 * @returns {number} length of the longest consonant run
 */
function longestConsonantCluster(str) {
  const consonants = /[bcdfghjklmnpqrstvwxyz]/i;
  let max = 0;
  let current = 0;
  for (const ch of str) {
    if (consonants.test(ch)) {
      current++;
      if (current > max) max = current;
    } else {
      current = 0;
    }
  }
  return max;
}

/**
 * Extract the TLD (last label) and the second-level label from a hostname.
 *
 * @param {string} hostname
 * @returns {{ sld: string, tld: string, labels: string[] }}
 */
function splitHostname(hostname) {
  const labels = hostname.toLowerCase().split(".");
  const tld    = labels.length >= 1 ? "." + labels[labels.length - 1] : "";
  const sld    = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  return { sld, tld, labels };
}

/**
 * Test whether a label looks like it was randomly generated (DGA pattern).
 * Criteria:
 *   - More than 4 digit characters in the label
 *   - Longest consonant cluster exceeds 5 characters
 *   - Shannon entropy > 3.5 bits/char (very high randomness)
 *
 * @param {string} label
 * @returns {{ match: boolean, reason: string }}
 */
function isRandomLookingLabel(label) {
  const digitCount = (label.match(/\d/g) || []).length;
  // Lowered from >4 to >2: even 3 digits in a short domain is suspicious
  if (digitCount > 2) {
    return { match: true, reason: `contains ${digitCount} digit characters` };
  }

  const cluster = longestConsonantCluster(label);
  if (cluster > 5) {
    return { match: true, reason: `consonant cluster of ${cluster} characters` };
  }

  const entropy = shannonEntropy(label);
  // Lowered from 3.5 to 3.0: catches more DGA-style labels
  if (entropy > 3.0) {
    return { match: true, reason: `high character entropy (${entropy.toFixed(2)} bits)` };
  }

  return { match: false, reason: "" };
}

/**
 * Test whether the label looks like a freshly-registered phishing domain via
 * length and mixed character composition:
 *   - Length between 20 and 50 characters
 *   - Contains both digits and hyphens
 *
 * @param {string} label
 * @returns {boolean}
 */
function isSuspiciousLengthLabel(label) {
  return (
    label.length >= 20 &&
    label.length <= 50 &&
    /\d/.test(label) &&
    label.includes("-")
  );
}

/**
 * Test whether the label follows the "brand-keyword-action" pattern common
 * in phishing domains (e.g. "paypal-secure-login", "amazon-update-account").
 *
 * @param {string} label
 * @returns {{ match: boolean, brand: string }}
 */
function isBrandKeywordCombo(label) {
  // Suspicious action/trust keywords frequently appended to brands
  const PHISHING_KEYWORDS = [
    "secure", "login", "signin", "verify", "update", "account",
    "support", "help", "confirm", "auth", "password", "recovery",
    "service", "official", "safe", "protect", "alert", "warning",
  ];

  const lower = label.toLowerCase();
  for (const brand of KNOWN_BRANDS) {
    if (brand.length < 4) continue;
    if (!lower.includes(brand)) continue;
    // At least one phishing keyword must also appear, joined by a hyphen.
    for (const kw of PHISHING_KEYWORDS) {
      // Pattern: brand-keyword or keyword-brand (with a hyphen separator)
      if (
        lower.includes(`${brand}-${kw}`) ||
        lower.includes(`${kw}-${brand}`)
      ) {
        return { match: true, brand };
      }
    }
  }
  return { match: false, brand: "" };
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Analyse a hostname for domain-level phishing risk signals.
 *
 * IMPORTANT: This module does NOT perform live WHOIS, DNS, or SSL lookups.
 * Scores reflect static heuristics only.
 *
 * @param {string} hostname — the hostname to analyse (e.g. "evil.netlify.app")
 * @returns {Promise<{ signals: Array<{id,label,weight,detail}>, score: number }>}
 */
export async function analyseDomain(hostname) {
  const signals = [];

  if (!hostname || typeof hostname !== "string") {
    return { signals: [], score: 0 };
  }

  const lower           = hostname.toLowerCase();
  const { sld, tld }    = splitHostname(lower);

  // ── Signal: FREE_SUBDOMAIN_SERVICE ───────────────────────────────────────
  // Phishing pages commonly abused free hosting services (netlify, vercel, …)
  // to avoid the cost and traceability of domain registration.
  for (const service of FREE_SUBDOMAIN_SERVICES) {
    if (lower === service || lower.endsWith("." + service)) {
      signals.push({
        id:     "FREE_SUBDOMAIN_SERVICE",
        label:  "Free subdomain/hosting service",
        weight: SIGNAL_WEIGHTS.FREE_SUBDOMAIN_SERVICE,
        detail: `"${hostname}" is hosted on the free platform "${service}".`,
      });
      break;
    }
  }

  // ── Signal: SUSPICIOUS_TLD ────────────────────────────────────────────────
  if (tld && SUSPICIOUS_TLDS.has(tld)) {
    signals.push({
      id:     "SUSPICIOUS_TLD",
      label:  "Suspicious top-level domain",
      weight: SIGNAL_WEIGHTS.SUSPICIOUS_TLD,
      detail: `The TLD "${tld}" is frequently used in phishing campaigns.`,
    });
  }

  // ── Signal: NEW_DOMAIN_PATTERN ────────────────────────────────────────────
  // Three independent sub-checks; only the first matching one fires to avoid
  // stacking the same signal weight for overlapping criteria.
  {
    let newDomainDetail = "";

    // Sub-check A: Random / DGA-like label
    const randomCheck = isRandomLookingLabel(sld);
    if (randomCheck.match) {
      newDomainDetail = `Second-level label "${sld}" ${randomCheck.reason}, consistent with algorithmically generated domains.`;
    }

    // Sub-check B: Long label with mixed digits and hyphens
    if (!newDomainDetail && isSuspiciousLengthLabel(sld)) {
      newDomainDetail = `Second-level label "${sld}" (${sld.length} chars) contains digits and hyphens — typical of freshly-registered phishing domains.`;
    }

    // Sub-check C: Brand + action keyword combination separated by hyphens
    if (!newDomainDetail) {
      const brandCombo = isBrandKeywordCombo(lower);
      if (brandCombo.match) {
        newDomainDetail = `Domain "${lower}" matches the brand-keyword pattern (brand: "${brandCombo.brand}"), common in targeted phishing campaigns.`;
      }
    }

    if (newDomainDetail) {
      signals.push({
        id:     "NEW_DOMAIN_PATTERN",
        label:  "Newly-registered domain pattern",
        weight: SIGNAL_WEIGHTS.NEW_DOMAIN_PATTERN,
        detail: newDomainDetail,
      });
    }
  }

  // ── Score aggregation ─────────────────────────────────────────────────────
  const score = Math.min(
    100,
    signals.reduce((sum, sig) => sum + sig.weight, 0)
  );

  return { signals, score };
}
