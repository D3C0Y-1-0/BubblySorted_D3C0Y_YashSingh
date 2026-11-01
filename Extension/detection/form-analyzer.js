/**
 * form-analyzer.js — Page structure and form analysis for Hedwig Shield.
 *
 * Processes the `pageAnalysis` object sent from the content script and
 * returns risk signals based on structural properties of the page (form
 * targets, HTTP usage, hidden fields, iframes, redirects, etc.).
 *
 * No DOM access occurs here — this module runs in the service worker context
 * and works only with the serialised data sent over chrome.runtime messaging.
 *
 * @module detection/form-analyzer
 */

import {
  SIGNAL_WEIGHTS,
  IMPERSONATION_TEXT_PATTERNS,
  LEGITIMATE_DOMAINS,
  KNOWN_BRANDS,
  PROTECTED_BRANDS_STRICT,
  SIMULATION_PATTERNS,
  SIMULATION_URL_PATTERNS,
  SOCIAL_ENGINEERING_URGENCY_PATTERNS,
} from "../utils/constants.js";

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Extract an approximate eTLD+1 from a URL string.
 * Returns an empty string if the URL cannot be parsed.
 *
 * This is an intentionally lightweight helper; for full eTLD+1 resolution see
 * url-checker.js. Here we only need to compare domain origins.
 *
 * @param {string} urlString
 * @returns {string}
 */
function getRegisteredDomain(urlString) {
  try {
    const { hostname } = new URL(urlString);
    const labels = hostname.toLowerCase().split(".");
    // Return the last two labels as a best-effort eTLD+1.
    return labels.length >= 2 ? labels.slice(-2).join(".") : hostname;
  } catch {
    return "";
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Analyse page-level form and content signals for phishing risk.
 *
 * @param {object} pageAnalysis — data collected by the content script:
 *   {
 *     url:                string,
 *     hasPasswordField:   boolean,
 *     hasLoginForm:       boolean,
 *     formTargets:        string[],   // resolved action URLs of all forms
 *     hasSensitiveFields: boolean,
 *     hiddenFieldCount:   number,
 *     pageTitle:          string,
 *     bodyText:           string,     // first 2000 chars of page body text
 *     isHttp:             boolean,
 *     metaRefreshTarget:  string|null,
 *     iframeCount:        number,
 *     crossOriginIframes: number,
 *   }
 * @param {string} currentUrl — the URL of the page being assessed
 * @returns {{ signals: Array<{id,label,weight,detail}>, score: number }}
 */
export function analyseForms(pageAnalysis, currentUrl) {
  const signals = [];

  // Guard: if no page analysis data is available return empty result.
  if (!pageAnalysis || typeof pageAnalysis !== "object") {
    return { signals: [], score: 0 };
  }

  const {
    hasPasswordField,
    hasLoginForm,
    formTargets      = [],
    hasSensitiveFields,
    hiddenFieldCount  = 0,
    pageTitle         = "",
    bodyText          = "",
    headings          = "",
    hasCredentialFields = false,
    isHttp,
    metaRefreshTarget,
    iframeCount       = 0,
    crossOriginIframes = 0,
  } = pageAnalysis;

  const currentDomain = getRegisteredDomain(currentUrl);
  const combinedContent = `${pageTitle} ${headings} ${bodyText} ${currentUrl}`;

  // ── Signal 1: PASSWORD_FIELD_NO_HTTPS ─────────────────────────────────────
  // Submitting a password over plain HTTP exposes it to network interception.
  // This is a critical phishing indicator and also flagged by browsers, but
  // we record it to contribute to the overall risk score.
  if (hasPasswordField && isHttp) {
    signals.push({
      id:     "PASSWORD_FIELD_NO_HTTPS",
      label:  "Password field on HTTP page",
      weight: SIGNAL_WEIGHTS.PASSWORD_FIELD_NO_HTTPS,
      detail: "This page requests a password but is served over unencrypted HTTP.",
    });
  }

  // ── Signal 2: SENSITIVE_FORM_HTTP ─────────────────────────────────────────
  // Any form collecting sensitive PII (credit card, SSN, OTP, etc.) over HTTP.
  if (hasSensitiveFields && isHttp) {
    signals.push({
      id:     "SENSITIVE_FORM_HTTP",
      label:  "Sensitive form on HTTP page",
      weight: SIGNAL_WEIGHTS.SENSITIVE_FORM_HTTP,
      detail: "This page collects sensitive information (PII, financial data) over unencrypted HTTP.",
    });
  }

  // ── Signal 3: LOGIN_FORM_MISMATCH ─────────────────────────────────────────
  // A login form that submits credentials to a different eTLD+1 than the page
  // hosting it is a textbook phishing pattern (the real domain harvests creds).
  if (hasLoginForm && formTargets.length > 0) {
    const currentDomain = getRegisteredDomain(currentUrl);
    const mismatchedTargets = formTargets.filter((target) => {
      const targetDomain = getRegisteredDomain(target);
      return (
        targetDomain &&                          // target must be parseable
        targetDomain !== currentDomain &&        // different eTLD+1
        !LEGITIMATE_DOMAINS.has(targetDomain)   // not a known-good domain
      );
    });

    if (mismatchedTargets.length > 0) {
      signals.push({
        id:     "LOGIN_FORM_MISMATCH",
        label:  "Login form posts to different domain",
        weight: SIGNAL_WEIGHTS.LOGIN_FORM_MISMATCH,
        detail: `Login form submits to: ${mismatchedTargets.slice(0, 2).join(", ")}` +
                (mismatchedTargets.length > 2 ? ` (+${mismatchedTargets.length - 2} more)` : "") +
                `, which differs from the page domain "${currentDomain}".`,
      });
    }
  }

  // ── Signal 4: BRAND_IMPERSONATION ────────────────────────────────────────
  // Account-threat wording phishing pages use to rush the victim
  // ("your account has been suspended", "verify your identity").
  // The detail quotes the exact text found, so the claim can be checked.
  {
    const textToCheck = `${pageTitle} ${bodyText}`;
    const quotes = IMPERSONATION_TEXT_PATTERNS
      .map((pattern) => (textToCheck.match(pattern) || [])[0])
      .filter(Boolean);

    if (quotes.length > 0) {
      signals.push({
        id:     "BRAND_IMPERSONATION",
        label:  "Account-threat wording",
        weight: SIGNAL_WEIGHTS.BRAND_IMPERSONATION,
        detail: `Page says: ${quotes.slice(0, 2).map((q) => `"${q}"`).join(", ")}.`,
      });
    }
  }

  // ── Signal 5: HIDDEN_FORM_FIELDS ─────────────────────────────────────────
  // Phishing kits often pre-fill many hidden fields with tracking tokens,
  // victim identifiers, or harvested values. More than 5 is suspicious.
  if (hiddenFieldCount > 5) {
    signals.push({
      id:     "HIDDEN_FORM_FIELDS",
      label:  "Excessive hidden form fields",
      weight: SIGNAL_WEIGHTS.HIDDEN_FORM_FIELDS,
      detail: `${hiddenFieldCount} hidden input fields detected (threshold: 5). May indicate data-harvesting behaviour.`,
    });
  }

  // ── Signal 6: RAPID_REDIRECT ─────────────────────────────────────────────
  // A <meta http-equiv="refresh"> tag redirects the user automatically,
  // often used to bounce from a parked / legitimate-looking URL to a
  // phishing payload.
  if (metaRefreshTarget !== null && metaRefreshTarget !== undefined) {
    signals.push({
      id:     "RAPID_REDIRECT",
      label:  "Automatic meta-refresh redirect",
      weight: SIGNAL_WEIGHTS.RAPID_REDIRECT,
      detail: `Page contains a <meta http-equiv="refresh"> directing to: "${String(metaRefreshTarget).slice(0, 100)}".`,
    });
  }

  // ── Signal 7: IFRAME_CREDENTIAL_FORM ─────────────────────────────────────
  // A login or password form embedded inside a cross-origin iframe is a strong
  // indicator of a clickjacking or phishing overlay attack.
  if (crossOriginIframes > 0 && (hasPasswordField || hasLoginForm)) {
    signals.push({
      id:     "IFRAME_CREDENTIAL_FORM",
      label:  "Credential form in cross-origin iframe",
      weight: SIGNAL_WEIGHTS.IFRAME_CREDENTIAL_FORM,
      detail: `${crossOriginIframes} cross-origin iframe(s) present alongside a login or password form.`,
    });
  }

  // ── Signal 8: BRAND_IN_PAGE_TITLE ────────────────────────────────────────
  // A page title naming a protected brand (e.g. "PayPal - Log In") on a domain
  // that is NOT that brand's legitimate domain is a strong impersonation signal.
  // This catches HTTPS phishing pages that score too low on URL signals alone.
  let brandInTitle = false;
  if (pageTitle && (hasPasswordField || hasLoginForm)) {
    const titleLower    = pageTitle.toLowerCase();
    const currentDomain = getRegisteredDomain(currentUrl);
    if (!LEGITIMATE_DOMAINS.has(currentDomain)) {
      for (const brand of PROTECTED_BRANDS_STRICT) {
        if (titleLower.includes(brand)) {
          brandInTitle = true;
          signals.push({
            id:     "BRAND_IN_PAGE_TITLE",
            label:  `Brand "${brand}" impersonated in page title`,
            weight: SIGNAL_WEIGHTS.BRAND_IN_PAGE_TITLE,
            detail: `Page title contains "${brand}" with a login form, ` +
                    `but "${currentDomain}" is not the legitimate ${brand} domain.`,
          });
          break;
        }
      }
    }
  }

  // ── Signal 9: PHISHING_SIMULATION (known phishing test page) ────────────
  // A published test harness URL (e.g. testsafebrowsing.appspot.com/s/phishing.html)
  // counts on its own. Test wording ("example of a phishing page") only counts
  // when the page also asks for credentials: an article *about* phishing uses
  // the same words and has no login form.
  const hasCredentialForm = !!(hasPasswordField || hasLoginForm || hasCredentialFields);
  const isTestUrl = SIMULATION_URL_PATTERNS.some((p) => p.test(currentUrl));
  const testWording = hasCredentialForm
    ? SIMULATION_PATTERNS.map((p) => (combinedContent.match(p) || [])[0]).find(Boolean)
    : undefined;
  const isSimulationContent = isTestUrl || !!testWording;

  if (isSimulationContent) {
    signals.push({
      id:     "PHISHING_SIMULATION",
      label:  "Known phishing test page",
      weight: SIGNAL_WEIGHTS.PHISHING_SIMULATION,
      detail: isTestUrl
        ? "The address is a published phishing test page."
        : `Login form next to the wording "${testWording}".`,
    });
  }

  // ── Signal 10: SOCIAL_ENGINEERING_URGENCY ────────────────────────────────
  // Fake update warnings, browser outdated alerts, or deceptive urgency prompts.
  const urgencyQuotes = SOCIAL_ENGINEERING_URGENCY_PATTERNS
    .map((p) => (combinedContent.match(p) || [])[0])
    .filter(Boolean);
  if (urgencyQuotes.length > 0) {
    signals.push({
      id:     "SOCIAL_ENGINEERING_URGENCY",
      label:  "Fake update or infection warning",
      weight: SIGNAL_WEIGHTS.SOCIAL_ENGINEERING_URGENCY,
      detail: `Page says: ${urgencyQuotes.slice(0, 2).map((q) => `"${q}"`).join(", ")}.`,
    });
  }

  // ── Signal 11: CREDENTIAL_HARVESTING_FIELDS ──────────────────────────────
  // A password field on its own is just a login page: every site has one.
  // It only counts when the same page also shows a phishing indicator.
  const hasAnyPassword = hasPasswordField || hasCredentialFields;
  const corroboration = [
    isSimulationContent && "it is a known phishing test page",
    urgencyQuotes.length > 0 && "it shows a fake update or infection warning",
    brandInTitle && "its title names a brand this domain does not belong to",
    signals.some((s) => s.id === "LOGIN_FORM_MISMATCH") && "the form posts to another domain",
    signals.some((s) => s.id === "BRAND_IMPERSONATION") && "it uses account-threat wording",
  ].filter(Boolean);
  if (hasAnyPassword && corroboration.length > 0) {
    signals.push({
      id:     "CREDENTIAL_HARVESTING_FIELDS",
      label:  "Password requested on a suspicious page",
      weight: SIGNAL_WEIGHTS.CREDENTIAL_HARVESTING_FIELDS,
      detail: `Asks for a password, and ${corroboration.join("; ")}.`,
    });
  }

  // ── Score aggregation ─────────────────────────────────────────────────────
  const score = Math.min(
    100,
    signals.reduce((sum, sig) => sum + sig.weight, 0)
  );

  return { signals, score };
}
