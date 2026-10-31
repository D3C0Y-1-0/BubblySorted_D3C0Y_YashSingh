/**
 * url-checker.js — URL heuristic analysis for Hedwig Shield.
 *
 * Analyses a URL string for structural and lexical phishing signals without
 * making any network requests. All detection is purely static / heuristic.
 *
 * @module detection/url-checker
 */

import {
  SIGNAL_WEIGHTS,
  KNOWN_BRANDS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
  FREE_SUBDOMAIN_SERVICES,
  PHISHING_QUERY_PARAMS,
  PROTECTED_BRANDS_STRICT,
  LEGITIMATE_DOMAINS,
  SIMULATION_URL_PATTERNS,
} from "../utils/constants.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Compute the Levenshtein edit distance between two strings.
 * Used for typosquatting detection against known brand names.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} minimum edit distance
 */
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;

  // Use a single-row DP to keep memory O(n).
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1,        // insertion
        prev[j] + 1,             // deletion
        prev[j - 1] + cost       // substitution
      );
    }
    // Swap rows to avoid allocating a new array each iteration.
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

/**
 * Extract structured parts from a URL string.
 *
 * Returns:
 *   hostname        — e.g. "sub.evil.com"          (lowercased)
 *   tld             — e.g. ".com"                  (with leading dot)
 *   registeredDomain— e.g. "evil.com"              (eTLD+1, best-effort)
 *   subdomains      — e.g. ["sub"]                 (labels before eTLD+1)
 *   path            — e.g. "/login/paypal"
 *   query           — e.g. "token=abc&verify=1"
 *   scheme          — e.g. "https"
 *
 * NOTE: This does NOT use a public suffix list. It approximates eTLD+1 by
 * treating the last two labels as registeredDomain (covers ~95 % of cases).
 * Country-code second-level domains (co.uk, com.au …) are handled with a
 * simple known-patterns check.
 *
 * @param {URL} url — already-parsed URL object
 * @returns {{ hostname, tld, registeredDomain, subdomains, path, query, scheme }}
 */
function extractParts(url) {
  const hostname = url.hostname.toLowerCase();
  const path     = url.pathname;
  const query    = url.search.slice(1); // strip leading "?"
  const scheme   = url.protocol.replace(":", "");

  const labels = hostname.split(".");

  // Known second-level TLD patterns where the last TWO labels form the eTLD
  // (e.g. co.uk, com.au, org.uk, net.au, …).
  const SLD_TLDS = new Set([
    "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.in", "net.in", "org.in",
    "com.br", "net.br", "org.br",
    "co.jp", "co.nz", "co.za",
  ]);

  let tld, registeredDomain, subdomains;

  if (labels.length >= 3) {
    const possibleSld = labels.slice(-2).join(".");
    if (SLD_TLDS.has(possibleSld)) {
      // eTLD is 2 labels; registeredDomain is the 3 rightmost labels
      tld              = "." + possibleSld;
      registeredDomain = labels.slice(-3).join(".");
      subdomains       = labels.slice(0, -3);
    } else {
      tld              = "." + labels[labels.length - 1];
      registeredDomain = labels.slice(-2).join(".");
      subdomains       = labels.slice(0, -2);
    }
  } else if (labels.length === 2) {
    tld              = "." + labels[labels.length - 1];
    registeredDomain = hostname;
    subdomains       = [];
  } else {
    // Single label or IP — registeredDomain = hostname
    tld              = "";
    registeredDomain = hostname;
    subdomains       = [];
  }

  return { hostname, tld, registeredDomain, subdomains, path, query, scheme };
}

/**
 * Test whether a hostname string is a raw IPv4 or IPv6 address.
 * @param {string} hostname
 * @returns {boolean}
 */
function isIpAddress(hostname) {
  // IPv4: four 0-255 octets separated by dots
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/;
  // IPv6: enclosed in brackets by the browser, but URL.hostname strips them
  const ipv6 = /^[\da-f:]+$/i;
  return ipv4.test(hostname) || (hostname.includes(":") && ipv6.test(hostname));
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Analyse a URL string for phishing-related structural signals.
 *
 * @param {string} urlString — the raw URL to inspect
 * @returns {Promise<{ signals: Array<{id,label,weight,detail}>, score: number }>}
 */
export async function analyseUrl(urlString) {
  const signals = [];

  // Guard: parse the URL; if it's invalid return empty result.
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { signals: [], score: 0 };
  }

  // ── Signal 13: DATA_URI ───────────────────────────────────────────────────
  // data: URIs are a classic phishing vector — they render pages locally with
  // no browsable domain, making the origin completely opaque to users.
  if (url.protocol === "data:") {
    signals.push({
      id:     "DATA_URI",
      label:  "Data URI scheme",
      weight: SIGNAL_WEIGHTS.DATA_URI,
      detail: "URL uses the data: scheme, which hides the true origin.",
    });
    // A data: URI has no further URL structure to analyse.
    const score = Math.min(100, signals.reduce((s, sig) => s + sig.weight, 0));
    return { signals, score };
  }

  const { hostname, tld, registeredDomain, subdomains, path, query, scheme } =
    extractParts(url);

  // ── Signal 1: IP_ADDRESS_HOST ─────────────────────────────────────────────
  if (isIpAddress(hostname)) {
    signals.push({
      id:     "IP_ADDRESS_HOST",
      label:  "IP address used as hostname",
      weight: SIGNAL_WEIGHTS.IP_ADDRESS_HOST,
      detail: `The host is a raw IP address (${hostname}) rather than a domain name.`,
    });
  }

  // ── Signal 2: EXCESSIVE_SUBDOMAINS ───────────────────────────────────────
  // More than 3 subdomain labels is rare for legitimate sites and common in
  // phishing URLs designed to embed a brand name deep in the host.
  if (subdomains.length > 3) {
    signals.push({
      id:     "EXCESSIVE_SUBDOMAINS",
      label:  "Excessive subdomains",
      weight: SIGNAL_WEIGHTS.EXCESSIVE_SUBDOMAINS,
      detail: `${subdomains.length} subdomain labels detected (threshold: 3).`,
    });
  }

  // ── Signal 3: AT_SIGN_IN_URL ──────────────────────────────────────────────
  // The `@` character in a URL's authority causes browsers to treat everything
  // before `@` as credentials, effectively hiding the real destination from
  // unsophisticated users (e.g. http://paypal.com@evil.com/).
  if (url.username || url.password || urlString.includes("@")) {
    signals.push({
      id:     "AT_SIGN_IN_URL",
      label:  "@ sign in URL authority",
      weight: SIGNAL_WEIGHTS.AT_SIGN_IN_URL,
      detail: "The URL contains an @ in its authority section, a known misdirection technique.",
    });
  }

  // ── Signal 4: ENCODED_OBFUSCATION ────────────────────────────────────────
  // Double-encoding (%25xx) hides characters from naive URL parsers.
  // Multiple encoded sequences in the host itself are also suspicious.
  {
    const doubleEncoded = /%25[0-9a-fA-F]{2}/.test(urlString);
    // Count raw %xx sequences in the hostname portion of the original string
    const encodedInHost = (hostname.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (doubleEncoded || encodedInHost > 3) {
      signals.push({
        id:     "ENCODED_OBFUSCATION",
        label:  "Encoded/obfuscated URL",
        weight: SIGNAL_WEIGHTS.ENCODED_OBFUSCATION,
        detail: doubleEncoded
          ? "URL contains double-encoded characters (%25xx)."
          : `Host contains ${encodedInHost} percent-encoded sequences.`,
      });
    }
  }

  // ── Signal 5: LONG_DOMAIN ─────────────────────────────────────────────────
  // Extremely long registered-domain labels are typical of algorithmically
  // generated phishing domains.
  if (registeredDomain.length > 40) {
    signals.push({
      id:     "LONG_DOMAIN",
      label:  "Excessively long domain",
      weight: SIGNAL_WEIGHTS.LONG_DOMAIN,
      detail: `Registered domain "${registeredDomain}" is ${registeredDomain.length} characters long (threshold: 40).`,
    });
  }

  // ── Signal 6: SUSPICIOUS_TLD ─────────────────────────────────────────────
  if (tld && SUSPICIOUS_TLDS.has(tld)) {
    signals.push({
      id:     "SUSPICIOUS_TLD",
      label:  "Suspicious top-level domain",
      weight: SIGNAL_WEIGHTS.SUSPICIOUS_TLD,
      detail: `The TLD "${tld}" is frequently used in phishing campaigns.`,
    });
  }

  // ── Signal 7: URL_SHORTENER ───────────────────────────────────────────────
  // URL shorteners are commonly used to hide the true destination.
  if (URL_SHORTENERS.has(registeredDomain)) {
    signals.push({
      id:     "URL_SHORTENER",
      label:  "URL shortener service",
      weight: SIGNAL_WEIGHTS.URL_SHORTENER,
      detail: `"${registeredDomain}" is a known URL shortening service.`,
    });
  }

  // ── Signal 8: TYPOSQUATTING ───────────────────────────────────────────────
  // Compare the registered domain label (without TLD) against every known
  // brand. Flag if edit distance is 1 or 2 and the domain is not legitimate.
  if (!LEGITIMATE_DOMAINS.has(registeredDomain)) {
    // Strip the TLD to get just the second-level label for comparison.
    const domainLabel = registeredDomain.replace(/\.[^.]+$/, "").toLowerCase();

    for (const brand of KNOWN_BRANDS) {
      // Skip very short brands (e.g. "x") to avoid spurious matches.
      if (brand.length < 4) continue;
      // Skip if the label IS the brand (that would be a legitimate match).
      if (domainLabel === brand) continue;

      const dist = levenshtein(domainLabel, brand);
      if (dist >= 1 && dist <= 2) {
        signals.push({
          id:     "TYPOSQUATTING",
          label:  "Possible typosquatting",
          weight: SIGNAL_WEIGHTS.TYPOSQUATTING,
          detail: `"${domainLabel}" is ${dist} edit(s) away from the brand "${brand}".`,
        });
        break; // One typosquatting signal is enough.
      }
    }
  }

  // ── Signal 9: BRAND_IN_SUBDOMAIN ─────────────────────────────────────────
  // Phishers often craft URLs like "paypal.verify.evil.com" — a protected
  // brand appears in the subdomain, not in the registeredDomain.
  if (!LEGITIMATE_DOMAINS.has(registeredDomain) && subdomains.length > 0) {
    const subdomainString = subdomains.join(".").toLowerCase();
    for (const brand of PROTECTED_BRANDS_STRICT) {
      if (subdomainString.includes(brand)) {
        signals.push({
          id:     "BRAND_IN_SUBDOMAIN",
          label:  "Protected brand in subdomain",
          weight: SIGNAL_WEIGHTS.BRAND_IN_SUBDOMAIN,
          detail: `Brand "${brand}" appears in the subdomain of a non-legitimate domain.`,
        });
        break;
      }
    }
  }

  // ── Signal 10: MISLEADING_PATH ────────────────────────────────────────────
  // A brand name appearing only in the path (e.g. evil.com/paypal/login) is
  // a common trick to make URLs look legitimate in previews.
  if (!LEGITIMATE_DOMAINS.has(registeredDomain)) {
    const pathLower = path.toLowerCase();
    for (const brand of KNOWN_BRANDS) {
      if (brand.length < 4) continue; // Ignore very short tokens
      if (pathLower.includes(brand)) {
        signals.push({
          id:     "MISLEADING_PATH",
          label:  "Brand name in path",
          weight: SIGNAL_WEIGHTS.MISLEADING_PATH,
          detail: `Brand "${brand}" appears in the URL path of a non-legitimate domain.`,
        });
        break;
      }
    }
  }

  // ── Signal 11: SUSPICIOUS_QUERY_PARAMS ───────────────────────────────────
  // Query parameter keys that are typical in phishing (e.g. ?verify=1&token=x)
  if (query) {
    const params = new URLSearchParams(query);
    const matched = [];
    for (const key of params.keys()) {
      if (PHISHING_QUERY_PARAMS.has(key.toLowerCase())) {
        matched.push(key);
      }
    }
    if (matched.length > 0) {
      signals.push({
        id:     "SUSPICIOUS_QUERY_PARAMS",
        label:  "Suspicious query parameters",
        weight: SIGNAL_WEIGHTS.SUSPICIOUS_QUERY_PARAMS,
        detail: `Query parameter(s) matching phishing patterns: ${matched.join(", ")}.`,
      });
    }
  }

  // ── Signal 12: HOMOGRAPH_CHARS ────────────────────────────────────────────
  // Non-ASCII characters in the hostname suggest an IDN homograph attack
  // (e.g. "pаypal.com" where 'а' is Cyrillic, not Latin).
  // URL.hostname for an IDN will be punycode (xn--...) if the browser
  // normalises it; but the raw string may still contain Unicode.
  if (/[^\x00-\x7F]/.test(hostname) || hostname.includes("xn--")) {
    signals.push({
      id:     "HOMOGRAPH_CHARS",
      label:  "Possible IDN homograph attack",
      weight: SIGNAL_WEIGHTS.HOMOGRAPH_CHARS,
      detail: "The hostname contains non-ASCII or punycode characters, which may visually mimic a legitimate domain.",
    });
  }

  // ── Signal 14: FREE_SUBDOMAIN_SERVICE ────────────────────────────────────
  // Hosting on free platforms is commonly used to bypass domain purchase costs
  // in phishing kits (e.g. paypal-login.netlify.app).
  for (const service of FREE_SUBDOMAIN_SERVICES) {
    if (hostname === service || hostname.endsWith("." + service)) {
      signals.push({
        id:     "FREE_SUBDOMAIN_SERVICE",
        label:  "Free subdomain/hosting service",
        weight: SIGNAL_WEIGHTS.FREE_SUBDOMAIN_SERVICE,
        detail: `"${hostname}" is hosted on the free platform "${service}".`,
      });
      break;
    }
  }

  // ── Signal 15: SECURITY_TEST_URL ─────────────────────────────────────────
  // URLs associated with security research, browser test suites, or phishing
  // demonstration harnesses (e.g. testsafebrowsing.appspot.com/s/phishing.html).
  for (const pattern of SIMULATION_URL_PATTERNS) {
    if (pattern.test(urlString)) {
      signals.push({
        id:     "SECURITY_TEST_URL",
        label:  "Security testing or simulation URL",
        weight: SIGNAL_WEIGHTS.SECURITY_TEST_URL,
        detail: `URL matches security testing/simulation pattern ${pattern}.`,
      });
      break;
    }
  }

  // ── Score aggregation ─────────────────────────────────────────────────────
  const score = Math.min(
    100,
    signals.reduce((sum, sig) => sum + sig.weight, 0)
  );

  return { signals, score };
}
