/**
 * page-analyzer.js — Content script for Hedwig Shield.
 *
 * Runs at document_idle in the main frame of every HTTP/HTTPS page.
 * Collects structural properties of the page (forms, fields, iframes, etc.)
 * WITHOUT reading any user-entered values, and sends them to the background
 * service worker for risk assessment.
 *
 * PRIVACY GUARANTEE: This script never reads, logs, or transmits the value
 * of any form field. It only observes structural/layout properties.
 *
 * NOTE: This is a plain content script — no ES module syntax. It is injected
 * directly by the browser according to the manifest's content_scripts entry.
 */

(function hedwigPageAnalyzer() {
  "use strict";

  // ── Collect page data ───────────────────────────────────────────────────────

  /**
   * Gather all structural page signals and return them as a plain object.
   * Wrapped in try/catch so that CSP-restricted or edge-case pages cannot
   * crash the content script.
   *
   * @returns {object} pageAnalysis
   */
  function collectPageData() {
    try {
      const allInputs   = Array.from(document.querySelectorAll("input"));
      const allForms    = Array.from(document.querySelectorAll("form"));
      const allIframes  = Array.from(document.querySelectorAll("iframe"));

      // ── Password field detection ────────────────────────────────────────
      const passwordInputs = allInputs.filter(
        (el) => el.type && el.type.toLowerCase() === "password"
      );
      const hasPasswordField = passwordInputs.length > 0;

      // ── Login form detection ────────────────────────────────────────────
      // A form is considered a "login form" when it contains at least one
      // password input element.
      const hasLoginForm = allForms.some((form) =>
        form.querySelector('input[type="password"]') !== null
      );

      // ── Form action targets ─────────────────────────────────────────────
      // Resolve relative `action` URLs against document.baseURI so that
      // the background script can compare domains accurately.
      const formTargets = allForms
        .map((form) => {
          const action = form.getAttribute("action");
          if (!action) return null;
          try {
            // Resolve relative URLs; absolute URLs pass through unchanged.
            return new URL(action, document.baseURI).href;
          } catch {
            return null;
          }
        })
        .filter(Boolean); // Remove nulls

      // ── Sensitive field detection ───────────────────────────────────────
      // Check name, id, and placeholder attributes for sensitive-data patterns.
      // We deliberately do NOT read .value — structural attributes only.
      const SENSITIVE_PATTERN =
        /password|passwd|pass\b|\bpin\b|\botp\b|\b2fa\b|\bmfa\b|credit.?card|card.?num|\bccn\b|\bcvc\b|\bcvv\b|social.?sec|\bssn\b|bank.?account|routing|secret|private.?key/i;

      const hasSensitiveFields = allInputs.some((el) => {
        const name        = el.getAttribute("name")        || "";
        const id          = el.getAttribute("id")          || "";
        const placeholder = el.getAttribute("placeholder") || "";
        return (
          SENSITIVE_PATTERN.test(name) ||
          SENSITIVE_PATTERN.test(id)   ||
          SENSITIVE_PATTERN.test(placeholder)
        );
      });

      // ── Hidden field count ──────────────────────────────────────────────
      const hiddenFieldCount = allInputs.filter(
        (el) => el.type && el.type.toLowerCase() === "hidden"
      ).length;

      // ── Body text (structural overview, first 2000 chars) ───────────────
      // innerText respects CSS visibility — it's what the user actually sees.
      let bodyText = "";
      try {
        bodyText = (document.body.innerText || "").slice(0, 2000);
      } catch {
        // document.body may be null on edge-case pages.
      }

      // ── HTTP detection ──────────────────────────────────────────────────
      const isHttp = window.location.protocol === "http:";

      // ── Meta refresh target ─────────────────────────────────────────────
      // Look for <meta http-equiv="refresh" content="N; url=…">
      let metaRefreshTarget = null;
      try {
        const metas = Array.from(
          document.querySelectorAll('meta[http-equiv="refresh" i]')
        );
        for (const meta of metas) {
          const content = meta.getAttribute("content") || "";
          // Format is "delay" or "delay; url=TARGET"
          const urlMatch = content.match(/;\s*url\s*=\s*(.+)/i);
          if (urlMatch) {
            metaRefreshTarget = urlMatch[1].trim();
            break;
          }
        }
      } catch {
        // Ignore CSP-restricted meta access.
      }

      // ── Headings (H1, H2, H3 text for intent detection) ─────────────────
      let headings = "";
      try {
        headings = Array.from(document.querySelectorAll("h1, h2, h3"))
          .map((h) => (h.innerText || "").trim())
          .filter(Boolean)
          .join(" | ")
          .slice(0, 500);
      } catch (_) {}

      // ── Credential input detection (including forms & standalone inputs) ─
      const textInputs = allInputs.filter((el) => {
        const type = (el.type || "").toLowerCase();
        return type === "text" || type === "email" || type === "tel";
      });
      const hasCredentialFields = hasPasswordField || (hasLoginForm && textInputs.length > 0);

      // ── iframe analysis ─────────────────────────────────────────────────
      const iframeCount = allIframes.length;

      // A cross-origin iframe is one whose src host differs from the page host.
      // We check the src attribute directly (not contentWindow, which is
      // cross-origin blocked anyway).
      const pageHost = window.location.hostname;
      const crossOriginIframes = allIframes.filter((iframe) => {
        const src = iframe.getAttribute("src") || "";
        if (!src || src.startsWith("javascript:") || src.startsWith("about:")) {
          return false;
        }
        try {
          const iframeHost = new URL(src, document.baseURI).hostname;
          return iframeHost !== pageHost;
        } catch {
          return false;
        }
      }).length;

      return {
        url:               window.location.href,
        hasPasswordField,
        hasLoginForm,
        formTargets,
        hasSensitiveFields,
        hiddenFieldCount,
        pageTitle:         document.title || "",
        bodyText,
        isHttp,
        metaRefreshTarget,
        iframeCount,
        crossOriginIframes,
        headings,
        hasCredentialFields,
      };
    } catch (err) {
      // If anything fails (e.g. on a CSP-locked page), return a minimal safe
      // object so the background script is never left without a response.
      console.warn("[Hedwig] page-analyzer collection error:", err);
      return {
        url:               window.location.href,
        hasPasswordField:  false,
        hasLoginForm:      false,
        formTargets:       [],
        hasSensitiveFields: false,
        hiddenFieldCount:  0,
        pageTitle:         "",
        bodyText:          "",
        isHttp:            window.location.protocol === "http:",
        metaRefreshTarget: null,
        iframeCount:       0,
        crossOriginIframes: 0,
        headings:          "",
        hasCredentialFields: false,
      };
    }
  }

  // ── Send initial analysis to background ─────────────────────────────────────

  console.log("[HEDWIG] Content script injected:", window.location.href);
  const pageData = collectPageData();
  console.log("[HEDWIG] Page analysis completed:", {
    url: pageData.url,
    hasPasswordField: pageData.hasPasswordField,
    hasLoginForm: pageData.hasLoginForm,
    hasCredentialFields: pageData.hasCredentialFields,
    headings: pageData.headings,
    isHttp: pageData.isHttp
  });

  function sendAnalysis() {
    chrome.runtime.sendMessage(
      { type: "PAGE_ANALYSIS_RESULT", data: pageData },
      (response) => {
        if (chrome.runtime.lastError) {
          // SW may be waking up — retry once after 600ms
          setTimeout(() => {
            chrome.runtime.sendMessage(
              { type: "PAGE_ANALYSIS_RESULT", data: pageData },
              () => { /* ignore */ }
            );
          }, 600);
        }
      }
    );
  }
  sendAnalysis();

  // ── On-demand analysis listener ─────────────────────────────────────────────
  // The popup can request a fresh snapshot at any time via GET_PAGE_ANALYSIS.

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === "GET_PAGE_ANALYSIS") {
      try {
        sendResponse({ data: collectPageData() });
      } catch (err) {
        sendResponse({ data: null, error: String(err) });
      }
      // Return false — response is synchronous.
      return false;
    }
  });
})();
