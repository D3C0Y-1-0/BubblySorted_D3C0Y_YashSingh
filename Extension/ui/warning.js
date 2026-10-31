// warning.js — Hedwig Shield warning page controller
// MV3 compliant: no inline event handlers, no eval

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/**
 * Returns the hex colour for a given risk score.
 * @param {number} score
 * @returns {string}
 */
function getLevelColour(score) {
  if (score >= 80) return "#ef5350";
  if (score >= 60) return "#ef5350";
  if (score >= 30) return "#ffb74d";
  return "#4caf50";
}

/**
 * Returns the badge class string for a given score.
 * @param {number} score
 * @returns {string}
 */
function getBadgeClass(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "moderate";
  return "moderate";
}

/**
 * Returns the badge label text for a given score.
 * @param {number} score
 * @returns {string}
 */
function getBadgeLabel(score) {
  if (score >= 80) return "CRITICAL THREAT";
  if (score >= 60) return "HIGH RISK";
  return "SUSPICIOUS SITE";
}

/**
 * Returns the bar fill colour for a given score.
 * @param {number} score
 * @returns {string}
 */
function getBarColour(score) {
  if (score >= 80) return "#b71c1c";
  if (score >= 60) return "#f44336";
  if (score >= 30) return "#ff9800";
  return "#4caf50";
}

/* ── DOM refs ─────────────────────────────────────────────────────────────── */
const urlValueEl    = document.getElementById("url-value");
const scoreValEl    = document.getElementById("score-val");
const scoreBarFill  = document.getElementById("score-bar-fill");
const threatIcon    = document.getElementById("threat-icon");
const threatBadge   = document.getElementById("threat-badge");
const warningTitle  = document.getElementById("warning-title");
const warningSubtitle = document.getElementById("warning-subtitle");
const signalsWrap   = document.getElementById("signals-wrap");
const warningSignal = document.getElementById("warning-signals");
const goBackBtn     = document.getElementById("go-back-btn");
const proceedBtn    = document.getElementById("proceed-btn");

/* ── URL param parsing & validation ───────────────────────────────────────── */
const params        = new URLSearchParams(window.location.search);
const flaggedUrl    = params.get("url")      || "";
const score         = parseInt(params.get("score") || "0", 10);
const levelParam    = params.get("level")    || "";
const categoryParam = params.get("category") || "";
const simParam      = params.get("sim") === "1";

let destinationUrl  = flaggedUrl;

/**
 * Validate that a string is a well-formed HTTP or HTTPS URL.
 * Strictly rejects empty strings, javascript:, data:, and malformed values.
 * @param {string} urlString
 * @returns {boolean}
 */
function isValidHttpUrl(urlString) {
  if (!urlString || typeof urlString !== "string") return false;
  try {
    const u = new URL(urlString);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch (_) {
    return false;
  }
}

/* ── Initial render from URL params ──────────────────────────────────────── */


function applyThreatCategory(category, scoreVal, isSim) {
  if (category === "PHISHING_SIMULATION" || isSim) {
    threatBadge.className = "critical simulation";
    threatBadge.textContent = "PHISHING SIMULATION DETECTED";
    threatIcon.textContent = "🧪";
    if (warningTitle) warningTitle.textContent = "Phishing Simulation Detected";
    if (warningSubtitle) {
      warningSubtitle.textContent =
        "This page demonstrates phishing behaviour and has been blocked by Hedwig's hackathon protection mode.";
    }
  } else if (category === "ACTIVE_PHISHING") {
    threatBadge.className = "critical";
    threatBadge.textContent = "ACTIVE PHISHING";
    threatIcon.textContent = "☠";
    if (warningTitle) warningTitle.textContent = "This website may be dangerous";
    if (warningSubtitle) {
      warningSubtitle.textContent =
        "Hedwig Shield has detected strong active phishing or credential harvesting patterns on this website.";
    }
  } else if (category === "SUSPICIOUS_WEBSITE") {
    threatBadge.className = "moderate";
    threatBadge.textContent = "SUSPICIOUS WEBSITE";
    threatIcon.textContent = "⚠";
    if (warningTitle) warningTitle.textContent = "Suspicious Website Warning";
    if (warningSubtitle) {
      warningSubtitle.textContent =
        "Hedwig Shield identified deceptive or suspicious indicators on this page.";
    }
  } else if (scoreVal >= 80) {
    threatBadge.className = "critical";
    threatBadge.textContent = "CRITICAL THREAT";
    threatIcon.textContent = "☠";
  } else if (scoreVal >= 60) {
    threatBadge.className = "high";
    threatBadge.textContent = "HIGH RISK";
    threatIcon.textContent = "⚠";
  } else {
    threatBadge.className = "moderate";
    threatBadge.textContent = "SUSPICIOUS SITE";
    threatIcon.textContent = "⚠";
  }
}

function applyScoreAndLevel(scoreVal) {
  // Score number
  scoreValEl.textContent  = scoreVal;
  scoreValEl.style.color  = getLevelColour(scoreVal);

  // Score bar
  scoreBarFill.style.width      = scoreVal + "%";
  scoreBarFill.style.background = getBarColour(scoreVal);

  // Apply category or level-based badge and title
  applyThreatCategory(categoryParam, scoreVal, simParam);
}

function applyFlaggedUrl(url) {
  if (url && isValidHttpUrl(url)) {
    destinationUrl = url;
  }
  urlValueEl.textContent = destinationUrl || "(unknown)";
}

/* ── Signals rendering ───────────────────────────────────────────────────── */

/**
 * Populates warning signals list and shows the section.
 * @param {Array<{label:string, detail:string, weight:number}>} signals
 */
function renderWarningSignals(signals) {
  if (!signals || signals.length === 0) {
    signalsWrap.classList.add("hidden");
    return;
  }

  warningSignal.innerHTML = "";

  signals.forEach(function (signal) {
    const weight = signal.weight || 0;
    let weightClass = "ws-low";
    if (weight >= 25)      weightClass = "ws-high";
    else if (weight >= 15) weightClass = "ws-medium";

    const li = document.createElement("li");
    li.className = "warning-signal " + weightClass;

    const labelDiv = document.createElement("div");
    labelDiv.className   = "ws-label";
    labelDiv.textContent = signal.label || "Unknown signal";

    const detailDiv = document.createElement("div");
    detailDiv.className   = "ws-detail";
    detailDiv.textContent = signal.detail || "";

    li.appendChild(labelDiv);
    li.appendChild(detailDiv);
    warningSignal.appendChild(li);
  });

  signalsWrap.classList.remove("hidden");
}

/* ── Load full risk data from background ─────────────────────────────────── */

function loadRiskFromBackground() {
  chrome.tabs.getCurrent(function (tab) {
    if (!tab) return;
    chrome.runtime.sendMessage(
      { type: "GET_TAB_RISK", tabId: tab.id },
      function (result) {
        if (result && result.signals && result.signals.length > 0) {
          renderWarningSignals(result.signals);
        }
        // If background has a fresher score or category, use it
        if (result) {
          const freshScore = result.score || score;
          const freshCat = result.threatCategory || categoryParam;
          const freshSim = result.isSimulation || simParam;
          applyScoreAndLevel(freshScore);
          applyThreatCategory(freshCat, freshScore, freshSim);
          if (result.url) {
            applyFlaggedUrl(result.url);
          }
        }
      }
    );
  });
}

/* ── Action: Go Back ──────────────────────────────────────────────────────── */

function goBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    // No history — close tab
    chrome.tabs.getCurrent(function (tab) {
      if (tab) {
        chrome.tabs.remove(tab.id);
      }
    });
  }
}

/* ── Action: Proceed ──────────────────────────────────────────────────────── */

function proceed() {
  const target = destinationUrl || flaggedUrl || (urlValueEl ? urlValueEl.textContent : "") || "";

  // Strictly validate HTTP/HTTPS protocol before navigating
  if (!target || !isValidHttpUrl(target)) {
    console.warn("[Hedwig] Cannot proceed: invalid or non-HTTP/HTTPS destination URL:", target);
    return;
  }

  // Disable button to prevent duplicate triggers
  if (proceedBtn) {
    proceedBtn.disabled = true;
    proceedBtn.textContent = "Proceeding…";
  }

  let navigated = false;
  function navigateToDestination() {
    if (!navigated) {
      navigated = true;
      window.location.href = target;
    }
  }

  // Register temporary bypass with background service worker before navigating
  try {
    chrome.runtime.sendMessage(
      { type: "SET_TEMPORARY_BYPASS", url: target },
      function () {
        navigateToDestination();
      }
    );
  } catch (_) {
    navigateToDestination();
  }

  // Safety fallback in case background response is delayed
  setTimeout(navigateToDestination, 350);
}

/* ── Init ─────────────────────────────────────────────────────────────────── */

function init() {
  // Apply URL param data immediately (no flicker)
  applyFlaggedUrl(flaggedUrl);
  applyScoreAndLevel(score);

  // Attempt to enrich with full stored risk (signals etc.)
  try {
    loadRiskFromBackground();
  } catch (_) {
    // Background not available (e.g., during dev preview) — ignore
  }

  // Button listeners
  if (goBackBtn)  goBackBtn.addEventListener("click", goBack);
  if (proceedBtn) proceedBtn.addEventListener("click", proceed);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
