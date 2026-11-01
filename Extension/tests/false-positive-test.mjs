/**
 * false-positive-test.mjs — Ordinary, legitimate pages must not be flagged.
 *
 * Each case is a real-world page shape (URL + what the content script would see).
 * A detector that warns on these is producing noise, not protection.
 *
 * Run: node --no-warnings tests/false-positive-test.mjs
 */

import { assessRisk, mergeAiResult } from "../detection/risk-engine.js";

let passed = 0;
let failed = 0;

function check(name, ok, info) {
  if (ok) { passed++; console.log(`  ✓  ${name}`); }
  else    { failed++; console.log(`  ✗  ${name}\n       ${info}`); }
}

function page(over) {
  return {
    hasPasswordField: false, hasLoginForm: false, hasCredentialFields: false,
    formTargets: [], hasSensitiveFields: false, hiddenFieldCount: 0,
    pageTitle: "", headings: "", bodyText: "", isHttp: false,
    metaRefreshTarget: null, iframeCount: 0, crossOriginIframes: 0,
    ...over,
  };
}

const SAFE = "SAFE_WEBSITE";
const describe = (r) => `score ${r.score}, ${r.threatCategory}; signals: ${r.signals.map((s) => s.id).join(", ") || "none"}`;

// ── Legitimate pages: must stay below the warning threshold and not be called phishing ──
const legit = [
  ["Wikipedia article about phishing",
    "https://en.wikipedia.org/wiki/Phishing",
    page({ pageTitle: "Phishing - Wikipedia", headings: "Phishing",
      bodyText: "Phishing is a form of social engineering. A phishing site may imitate a bank. Security testing teams run phishing tests on staff." })],
  ["Ordinary login page on a normal site (reddit)",
    "https://www.reddit.com/login/",
    page({ pageTitle: "Reddit - Log in", hasPasswordField: true, hasLoginForm: true, hasCredentialFields: true,
      formTargets: ["https://www.reddit.com/login"] })],
  ["Stack Overflow question",
    "https://stackoverflow.com/questions/12345/how-to-parse-json?ref=hn&next=1",
    page({ pageTitle: "How to parse JSON - Stack Overflow" })],
  ["Medium profile with @ in the path",
    "https://medium.com/@someauthor/my-post",
    page({ pageTitle: "My post | Medium" })],
  ["Steam store (one letter-swap from 'teams')",
    "https://steam.com/",
    page({ pageTitle: "Steam" })],
  ["Blog post that mentions Google in the path",
    "https://example-blog.com/how-to-use-google-sheets",
    page({ pageTitle: "How to use Google Sheets" })],
  ["Shop with a 'limited time' sale banner",
    "https://www.shop-example.com/sale",
    page({ pageTitle: "Summer sale", bodyText: "Limited time offer! Act now and save 20%." })],
  ["Maple (two edits from 'apple')",
    "https://maple.com/",
    page({ pageTitle: "Maple" })],
  ["OWASP security testing guide",
    "https://owasp.org/www-project-web-security-testing-guide/",
    page({ pageTitle: "OWASP Web Security Testing Guide", bodyText: "The guide covers security testing of web applications." })],
];

console.log("\nLegitimate pages");
for (const [name, url, pa] of legit) {
  const r = await assessRisk(url, pa);
  check(`${name} → rated safe`, r.threatCategory === SAFE && r.score < 30, describe(r));
}

// ── Real phishing shapes: must still be caught ──
console.log("\nPhishing pages (must still warn)");
const phish = [
  ["PayPal lookalike login on a typo domain",
    "https://paypa1.com/signin",
    page({ pageTitle: "PayPal - Log In", hasPasswordField: true, hasLoginForm: true, hasCredentialFields: true,
      bodyText: "Your account has been suspended. Verify your account to restore access.",
      formTargets: ["https://collect-data.xyz/post"] })],
  ["Brand in subdomain on a free host, HTTP password form",
    "http://paypal.secure-login.netlify.app/",
    page({ pageTitle: "PayPal Login", hasPasswordField: true, hasLoginForm: true, hasCredentialFields: true, isHttp: true })],
  ["Google Safe Browsing phishing test page",
    "https://testsafebrowsing.appspot.com/s/phishing.html",
    page({ pageTitle: "Phishing test page", hasPasswordField: true, hasLoginForm: true, hasCredentialFields: true,
      bodyText: "This is an example of a phishing page." })],
];
for (const [name, url, pa] of phish) {
  const r = await assessRisk(url, pa);
  check(`${name} → warned (score ≥ 60)`, r.score >= 60, describe(r));
}

// ── The AI must not override the rules on its own ──
console.log("\nAI verdict limits");
const clean = await assessRisk("https://example.com/", page({ pageTitle: "Example Domain" }));
const lowConf = mergeAiResult(clean, { success: true, isPhishing: true, isSimulation: true,
  threatCategory: "PHISHING_SIMULATION", confidence: 30, reasons: ["looks like a test"] });
check("Low-confidence AI verdict does not change the score", lowConf.score === clean.score,
  `score ${clean.score} → ${lowConf.score}`);
const noReasons = mergeAiResult(clean, { success: true, isPhishing: true, isSimulation: false,
  threatCategory: "ACTIVE_PHISHING", confidence: 95, reasons: [] });
check("AI verdict with no stated reasons does not change the score", noReasons.score === clean.score,
  `score ${clean.score} → ${noReasons.score}`);
const highConf = mergeAiResult(clean, { success: true, isPhishing: true, isSimulation: false,
  threatCategory: "ACTIVE_PHISHING", confidence: 100, reasons: ["form posts to unrelated domain"] });
check("AI alone adds at most 40 points (cannot warn by itself)", highConf.score - clean.score <= 40 && highConf.score < 60,
  `score ${clean.score} → ${highConf.score}`);

console.log("─".repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
process.exit(failed ? 1 : 0);
