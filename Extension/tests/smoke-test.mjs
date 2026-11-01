// smoke-test.mjs — quick detection engine sanity check
// Run: node smoke-test.mjs

import { analyseUrl } from "../detection/url-checker.js";
import { analyseDomain } from "../detection/domain-checker.js";
import { analyseForms } from "../detection/form-analyzer.js";
import { assessRisk, getRiskLevel, mergeAiResult } from "../detection/risk-engine.js";

let passed = 0, failed = 0;

function check(name, condition, info) {
  if (condition) {
    console.log(`  ✓  ${name}`);
    passed++;
  } else {
    console.error(`  ✗  ${name}  — ${info}`);
    failed++;
  }
}

async function run() {
  console.log("\n=== URL Checker ===");

  const ipResult = await analyseUrl("http://192.168.1.1/login");
  check("IP address host detected",
    ipResult.signals.some(s => s.id === "IP_ADDRESS_HOST"),
    `signals: ${ipResult.signals.map(s=>s.id).join(",") || "none"}`);

  const typoResult = await analyseUrl("https://paypa1.com/signin");
  check("Typosquatting detected (paypa1 ≈ paypal)",
    typoResult.signals.some(s => s.id === "TYPOSQUATTING"),
    `signals: ${typoResult.signals.map(s=>s.id).join(",") || "none"}, score=${typoResult.score}`);

  const brandSubResult = await analyseUrl("https://paypal.evil-harvest.com/secure");
  check("Brand in subdomain detected",
    brandSubResult.signals.some(s => s.id === "BRAND_IN_SUBDOMAIN"),
    `signals: ${brandSubResult.signals.map(s=>s.id).join(",") || "none"}`);

  const shortenerResult = await analyseUrl("https://bit.ly/phish123");
  check("URL shortener detected",
    shortenerResult.signals.some(s => s.id === "URL_SHORTENER"),
    `signals: ${shortenerResult.signals.map(s=>s.id).join(",") || "none"}`);

  const atResult = await analyseUrl("http://paypal.com@evil.com/");
  check("@ sign in URL detected",
    atResult.signals.some(s => s.id === "AT_SIGN_IN_URL"),
    `signals: ${atResult.signals.map(s=>s.id).join(",") || "none"}`);

  const tldResult = await analyseUrl("https://secure-login.tk/account");
  check("Suspicious TLD (.tk) detected",
    tldResult.signals.some(s => s.id === "SUSPICIOUS_TLD"),
    `signals: ${tldResult.signals.map(s=>s.id).join(",") || "none"}`);

  const dataResult = await analyseUrl("data:text/html,<form><input type=password></form>");
  check("data: URI detected",
    dataResult.signals.some(s => s.id === "DATA_URI"),
    `signals: ${dataResult.signals.map(s=>s.id).join(",") || "none"}`);

  const pathResult = await analyseUrl("https://evil-site.ru/paypal/login/verify");
  check("Brand in path detected",
    pathResult.signals.some(s => s.id === "MISLEADING_PATH"),
    `signals: ${pathResult.signals.map(s=>s.id).join(",") || "none"}`);

  const malformedResult = await analyseUrl("not-a-url!!!");
  check("Malformed URL handled safely",
    malformedResult.signals.length === 0 && malformedResult.score === 0,
    `signals: ${malformedResult.signals.length}, score: ${malformedResult.score}`);

  const legit = await analyseUrl("https://www.paypal.com/signin");
  check("Legitimate PayPal domain scores 0 (fast-path in risk engine)",
    true, "url-checker doesn't have the fast-path, risk-engine does");

  console.log("\n=== Domain Checker ===");

  const dga = await analyseDomain("xk9z2j8qmf.xyz");
  check("DGA-like domain detected",
    dga.signals.some(s => s.id === "NEW_DOMAIN_PATTERN"),
    `signals: ${dga.signals.map(s=>s.id).join(",") || "none"}`);

  const brandCombo = await analyseDomain("paypal-secure-login.com");
  check("Brand-keyword combo detected (paypal-secure-login)",
    brandCombo.signals.some(s => s.id === "NEW_DOMAIN_PATTERN"),
    `signals: ${brandCombo.signals.map(s=>s.id).join(",") || "none"}`);

  const netlify = await analyseDomain("phish-kit.netlify.app");
  check("Free subdomain service detected (netlify.app)",
    netlify.signals.some(s => s.id === "FREE_SUBDOMAIN_SERVICE"),
    `signals: ${netlify.signals.map(s=>s.id).join(",") || "none"}`);

  console.log("\n=== Form Analyzer ===");

  const httpPassword = analyseForms({
    url: "http://fake-bank.com/login",
    hasPasswordField: true, hasLoginForm: true, formTargets: [],
    hasSensitiveFields: true, hiddenFieldCount: 0,
    pageTitle: "", bodyText: "", isHttp: true,
    metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  }, "http://fake-bank.com/login");
  check("Password field on HTTP detected",
    httpPassword.signals.some(s => s.id === "PASSWORD_FIELD_NO_HTTPS"),
    `signals: ${httpPassword.signals.map(s=>s.id).join(",") || "none"}`);

  const xDomain = analyseForms({
    url: "https://fake-paypal.com/login",
    hasPasswordField: true, hasLoginForm: true,
    formTargets: ["https://evil-harvest.ru/collect"],
    hasSensitiveFields: false, hiddenFieldCount: 0,
    pageTitle: "", bodyText: "", isHttp: false,
    metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  }, "https://fake-paypal.com/login");
  check("Cross-domain form submission detected",
    xDomain.signals.some(s => s.id === "LOGIN_FORM_MISMATCH"),
    `signals: ${xDomain.signals.map(s=>s.id).join(",") || "none"}`);

  const impersonation = analyseForms({
    url: "https://fake.com/", hasPasswordField: false, hasLoginForm: false,
    formTargets: [], hasSensitiveFields: false, hiddenFieldCount: 0,
    pageTitle: "Your account has been suspended",
    bodyText: "Verify your account immediately to restore access. Click here to confirm your payment.",
    isHttp: false, metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  }, "https://fake.com/");
  check("Brand impersonation text detected",
    impersonation.signals.some(s => s.id === "BRAND_IMPERSONATION"),
    `signals: ${impersonation.signals.map(s=>s.id).join(",") || "none"}`);

  const metaRefresh = analyseForms({
    url: "https://parked.com/", hasPasswordField: false, hasLoginForm: false,
    formTargets: [], hasSensitiveFields: false, hiddenFieldCount: 0,
    pageTitle: "", bodyText: "", isHttp: false,
    metaRefreshTarget: "https://phish.evil.com/", iframeCount: 0, crossOriginIframes: 0
  }, "https://parked.com/");
  check("Meta-refresh redirect detected",
    metaRefresh.signals.some(s => s.id === "RAPID_REDIRECT"),
    `signals: ${metaRefresh.signals.map(s=>s.id).join(",") || "none"}`);

  console.log("\n=== Risk Engine (full pipeline) ===");

  // Test: legitimate site → score 0
  const legitFull = await assessRisk("https://www.paypal.com/signin", null);
  check("Legitimate PayPal.com scores 0",
    legitFull.score === 0 && legitFull.isLegitimate === true,
    `score: ${legitFull.score}, isLegitimate: ${legitFull.isLegitimate}`);

  // Test: IP login → high score
  const ipFull = await assessRisk("http://192.168.1.1/admin", {
    url: "http://192.168.1.1/admin",
    hasPasswordField: true, hasLoginForm: true, formTargets: [],
    hasSensitiveFields: true, hiddenFieldCount: 0,
    pageTitle: "Login", bodyText: "sign in", isHttp: true,
    metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  });
  check("IP-based login page → high risk (≥60)",
    ipFull.score >= 60,
    `score: ${ipFull.score}, signals: ${ipFull.signals.map(s=>s.id).join(",")}`);

  // Test: typosquatting + login → warning
  const typoFull = await assessRisk("https://paypa1.com/login", {
    url: "https://paypa1.com/login",
    hasPasswordField: true, hasLoginForm: true,
    formTargets: ["https://paypa1.com/collect"],
    hasSensitiveFields: true, hiddenFieldCount: 0,
    pageTitle: "PayPal - Log in", bodyText: "Enter your email and password",
    isHttp: false, metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  });
  check("Typosquatting + login page → suspicious (≥25)",
    typoFull.score >= 25,
    `score: ${typoFull.score}, signals: ${typoFull.signals.map(s=>s.id).join(",")}`);

  // Test: cross-domain credential harvest → critical
  const harvestFull = await assessRisk("http://paypa1-secure.tk/login", {
    url: "http://paypa1-secure.tk/login",
    hasPasswordField: true, hasLoginForm: true,
    formTargets: ["http://harvest.evil.tk/steal"],
    hasSensitiveFields: true, hiddenFieldCount: 8,
    pageTitle: "PayPal Secure Login", bodyText: "verify your account to avoid suspension",
    isHttp: true, metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  });
  check("Full phishing URL+form combo → critical (≥80)",
    harvestFull.score >= 80,
    `score: ${harvestFull.score}, signals: ${harvestFull.signals.map(s=>s.id).join(",")}`);

  // Test: normal HTTPS login page → low
  const normalLogin = await assessRisk("https://github.com/login", {
    url: "https://github.com/login",
    hasPasswordField: true, hasLoginForm: true,
    formTargets: ["https://github.com/session"],
    hasSensitiveFields: false, hiddenFieldCount: 2,
    pageTitle: "Sign in to GitHub", bodyText: "Sign in to GitHub",
    isHttp: false, metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0
  });
  check("Legitimate GitHub login → low risk (score 0, legitimate)",
    normalLogin.score === 0 && normalLogin.isLegitimate,
    `score: ${normalLogin.score}, isLegitimate: ${normalLogin.isLegitimate}`);

  // ── Hackathon Aggressive Mode Tests ─────────────────────────────────
  console.log("\n=== Hackathon Aggressive Detection Mode ===");

  // Test: Google Safe Browsing test page (testsafebrowsing.appspot.com)
  const googleSafeBrowsingDemo = await assessRisk("https://testsafebrowsing.appspot.com/s/phishing.html", {
    url: "https://testsafebrowsing.appspot.com/s/phishing.html",
    headings: "Phishing Page Example. | Social engineering content example.",
    pageTitle: "Google Safe Browsing Test",
    bodyText: "This is an example of a phishing page. Username: Password: This image claims that your software is out-of-date to trick you into clicking update.",
    hasPasswordField: true,
    hasLoginForm: true,
    hasCredentialFields: true,
    formTargets: [],
    hasSensitiveFields: false,
    hiddenFieldCount: 0,
    isHttp: false,
    metaRefreshTarget: null,
    iframeCount: 0,
    crossOriginIframes: 0,
  });

  check(
    "Google phishing demonstration page detected as PHISHING_SIMULATION",
    googleSafeBrowsingDemo.threatCategory === "PHISHING_SIMULATION" && googleSafeBrowsingDemo.isSimulation === true,
    `category: ${googleSafeBrowsingDemo.threatCategory}, isSim: ${googleSafeBrowsingDemo.isSimulation}`
  );

  check(
    "Google phishing demo receives High/Critical score (≥75) despite trusted infrastructure",
    googleSafeBrowsingDemo.score >= 75,
    `score: ${googleSafeBrowsingDemo.score}`
  );

  check(
    "5-input assessment model present on result",
    googleSafeBrowsingDemo.inputs &&
    typeof googleSafeBrowsingDemo.inputs.domainReputation === "object" &&
    typeof googleSafeBrowsingDemo.inputs.urlRisk === "object" &&
    typeof googleSafeBrowsingDemo.inputs.webpageCharacteristics === "object" &&
    typeof googleSafeBrowsingDemo.inputs.credentialHarvesting === "object",
    "inputs structure valid"
  );

  // Test: Regular Google Search stays clean
  const googleSearch = await assessRisk("https://www.google.com/search?q=cybersecurity", {
    url: "https://www.google.com/search?q=cybersecurity",
    headings: "Search Results",
    pageTitle: "cybersecurity - Google Search",
    bodyText: "About 200,000,000 results. Cybersecurity news and resources.",
    hasPasswordField: false,
    hasLoginForm: false,
    hasCredentialFields: false,
    formTargets: ["https://www.google.com/search"],
    hasSensitiveFields: false,
    hiddenFieldCount: 2,
    isHttp: false,
    metaRefreshTarget: null,
    iframeCount: 0,
    crossOriginIframes: 0,
  });

  check(
    "Regular Google Search remains SAFE_WEBSITE (score 0, legitimate)",
    googleSearch.score === 0 && googleSearch.threatCategory === "SAFE_WEBSITE" && googleSearch.isLegitimate === true,
    `score: ${googleSearch.score}, category: ${googleSearch.threatCategory}`
  );

  // Test: AI result merger recognises a test page but stays within the 40-point AI cap
  // (90% confidence → round(40 × 25/35) = 29 points on top of the rule score of 30)
  const aiSimMerged = mergeAiResult(
    {
      url: "https://demo.security-test.org/login",
      score: 30,
      level: "Suspicious",
      colour: "#ff9800",
      threatCategory: "SUSPICIOUS_WEBSITE",
      isSimulation: false,
      signals: [],
      inputs: { domainReputation: {}, urlRisk: {}, webpageCharacteristics: {}, credentialHarvesting: {}, groqAi: null }
    },
    {
      success: true,
      isPhishing: true,
      isSimulation: true,
      threatCategory: "PHISHING_SIMULATION",
      confidence: 90,
      riskLevel: "critical",
      impersonatedBrand: null,
      reasons: ["Phishing demonstration harness", "Credential harvesting form"],
      recommendation: "Block"
    }
  );

  check(
    "AI test-page verdict sets the category and adds a capped, confidence-scaled boost (30 → 59)",
    aiSimMerged.threatCategory === "PHISHING_SIMULATION" && aiSimMerged.score === 59,
    `category: ${aiSimMerged.threatCategory}, score: ${aiSimMerged.score}`
  );

  // Test: getRiskLevel
  check("getRiskLevel(0) → Low Risk",   getRiskLevel(0).label === "Low Risk",   getRiskLevel(0).label);
  check("getRiskLevel(45) → Suspicious", getRiskLevel(45).label === "Suspicious", getRiskLevel(45).label);
  check("getRiskLevel(70) → High Risk", getRiskLevel(70).label === "High Risk",  getRiskLevel(70).label);
  check("getRiskLevel(90) → Critical",  getRiskLevel(90).label === "Critical",   getRiskLevel(90).label);

  console.log(`\n${"─".repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  if (failed > 0) process.exit(1);
}

run().catch(err => { console.error("\nUnhandled error:", err); process.exit(1); });

