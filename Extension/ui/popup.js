// popup.js — Hedwig Shield popup controller
// MV3 compliant: no inline event handlers, no eval

/* ── Constants ─────────────────────────────────────────────────────────────── */
const CIRCUMFERENCE = 251.3; // 2π × 40

const MSG = {
  GET_TAB_RISK:       "GET_TAB_RISK",
  GET_TAB_AI_RESULT:  "GET_TAB_AI_RESULT",
  GET_HISTORY:        "GET_HISTORY",
  GET_SETTINGS:       "GET_SETTINGS",
  SET_SETTINGS:       "SET_SETTINGS",
  CLEAR_HISTORY:      "CLEAR_HISTORY",
  TOGGLE_PROTECTION:  "TOGGLE_PROTECTION",
  GET_AI_SETTINGS:    "GET_AI_SETTINGS",
  SET_AI_SETTINGS:    "SET_AI_SETTINGS",
  SAVE_AI_KEY:        "SAVE_AI_KEY",
  GET_AI_KEY_STATUS:  "GET_AI_KEY_STATUS",
  CLEAR_AI_KEY:       "CLEAR_AI_KEY",
  TEST_AI_CONNECTION: "TEST_AI_CONNECTION",
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

function relativeTime(timestamp) {
  if (!timestamp) return "";
  const diff = Math.floor((Date.now() - timestamp) / 1000);
  if (diff < 60)  return "just now";
  const m = Math.floor(diff / 60);
  if (m < 60)    return m + " min ago";
  const h = Math.floor(m / 60);
  if (h < 24)    return h + " hr ago";
  const d = Math.floor(h / 24);
  return d + " day" + (d !== 1 ? "s" : "") + " ago";
}

function getLevelClass(score) {
  if (score >= 80) return "risk-critical";
  if (score >= 60) return "risk-high";
  if (score >= 30) return "risk-moderate";
  return "risk-low";
}

function getLevelColour(score) {
  if (score >= 80) return "#b71c1c";
  if (score >= 60) return "#f44336";
  if (score >= 30) return "#ff9800";
  return "#4caf50";
}

function getLevelLabel(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High Risk";
  if (score >= 30) return "Suspicious";
  return "Safe";
}

function getThreatCategoryLabel(result) {
  if (!result) return "SAFE WEBSITE";
  if (result.threatCategory === "PHISHING_SIMULATION" || result.isSimulation) {
    return "PHISHING SIMULATION";
  }
  if (result.threatCategory === "ACTIVE_PHISHING" || result.score >= 60) {
    return "ACTIVE PHISHING";
  }
  if (result.threatCategory === "SUSPICIOUS_WEBSITE" || result.score >= 30) {
    return "SUSPICIOUS WEBSITE";
  }
  return "SAFE WEBSITE";
}

function hostnameOf(url) {
  try { return new URL(url).hostname; }
  catch (_) { return url || ""; }
}

function send(type, extra) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...extra }, resolve);
  });
}

/* ── DOM refs ─────────────────────────────────────────────────────────────── */
const scoreNumber    = document.getElementById("score-number");
const scoreLabel     = document.getElementById("score-label");
const scoreFill      = document.getElementById("score-fill");
const riskLevel      = document.getElementById("risk-level");
const riskUrl        = document.getElementById("risk-url");
const riskAssessed   = document.getElementById("risk-assessed");
const signalsSection = document.getElementById("signals-section");
const signalsList    = document.getElementById("signals-list");
const historyList    = document.getElementById("history-list");
const toggleInput    = document.getElementById("protection-toggle");
const toggleTrack    = document.getElementById("toggle-track");
const settingsPanel  = document.getElementById("settings-panel");

// AI elements
const aiSection       = document.getElementById("ai-section");
const aiStatusBadge   = document.getElementById("ai-status-badge");
const aiModelTag      = document.getElementById("ai-model-tag");
const aiLoading       = document.getElementById("ai-loading");
const aiResults       = document.getElementById("ai-results");
const aiDisabled      = document.getElementById("ai-disabled");
const aiErrorEl       = document.getElementById("ai-error");
const aiErrorText     = document.getElementById("ai-error-text");
const aiConfBar       = document.getElementById("ai-conf-bar");
const aiConfValue     = document.getElementById("ai-conf-value");
const aiBrandRow      = document.getElementById("ai-brand-row");
const aiBrandValue    = document.getElementById("ai-brand-value");
const aiReasonsList   = document.getElementById("ai-reasons-list");
const aiRecRow        = document.getElementById("ai-recommendation-row");
const aiRecValue      = document.getElementById("ai-recommendation-value");
const aiConnStatus    = document.getElementById("ai-connection-status");
const aiKeyStatusRow  = document.getElementById("ai-key-status-row");
const aiKeyStatusLbl  = document.getElementById("ai-key-status-label");
const aiEnabledToggle = document.getElementById("ai-enabled-toggle");
const aiMiniTrack     = aiEnabledToggle ? aiEnabledToggle.closest(".mini-toggle").querySelector(".mini-track") : null;

/* ── Render: Risk ─────────────────────────────────────────────────────────── */

function renderRisk(result, tab) {
  const url = (result && result.url) ? result.url : (tab ? tab.url : "");

  if (!result || !result.score) {
    scoreNumber.textContent           = "--";
    scoreLabel.textContent            = "Safe";
    scoreFill.style.strokeDashoffset  = CIRCUMFERENCE.toString();
    scoreFill.style.stroke            = "#4caf50";
    riskLevel.textContent             = "SAFE WEBSITE";
    riskLevel.className               = "risk-low";
    riskUrl.textContent               = hostnameOf(url);
    riskUrl.title                     = url;
    riskAssessed.textContent          = "";
    signalsSection.classList.add("hidden");
    return;
  }

  const score  = result.score;
  const colour = (result.isSimulation || result.threatCategory === "PHISHING_SIMULATION") ? "#ff5252" : getLevelColour(score);
  const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;

  scoreNumber.textContent             = score;
  scoreLabel.textContent              = getLevelLabel(score);
  scoreFill.style.strokeDashoffset    = offset.toFixed(2);
  scoreFill.style.stroke              = colour;
  const catLabel                      = getThreatCategoryLabel(result);
  riskLevel.textContent               = catLabel;
  riskLevel.className                 = (catLabel === "PHISHING_SIMULATION") ? "risk-simulation" : getLevelClass(score);
  riskUrl.textContent                 = hostnameOf(url);
  riskUrl.title                       = url;
  riskAssessed.textContent            = result.assessedAt ? "Assessed " + relativeTime(result.assessedAt) : "";

  // Render detected threat signals
  const displaySignals = result.signals || [];
  if (displaySignals.length > 0) {
    renderSignals(displaySignals);
    signalsSection.classList.remove("hidden");
  } else {
    signalsSection.classList.add("hidden");
  }
}

/* ── Render: Signals ──────────────────────────────────────────────────────── */

function renderSignals(signals) {
  signalsList.innerHTML = "";
  signals.forEach(function (signal) {
    const weight = signal.weight || 0;
    let wc = "weight-low";
    if (weight >= 25) wc = "weight-high";
    else if (weight >= 15) wc = "weight-medium";

    const li = document.createElement("li");
    li.className = "signal-item " + wc;

    const ld = document.createElement("div");
    ld.className   = "signal-label";
    ld.textContent = signal.label || "Unknown signal";

    const dd = document.createElement("div");
    dd.className   = "signal-detail";
    dd.textContent = signal.detail || "";

    li.appendChild(ld);
    li.appendChild(dd);
    signalsList.appendChild(li);
  });
}

/* ── Render: AI Section ───────────────────────────────────────────────────── */

function setAiBadge(cls, text) {
  if (aiStatusBadge) {
    aiStatusBadge.className = "ai-badge " + cls;
    aiStatusBadge.textContent = text;
  }
}

function showAiState(state) {
  if (!aiSection) return;
  if (aiLoading)    aiLoading.classList.add("hidden");
  if (aiResults)    aiResults.classList.add("hidden");
  if (aiDisabled)   aiDisabled.classList.add("hidden");
  if (aiErrorEl)    aiErrorEl.classList.add("hidden");

  if (state === "loading"  && aiLoading)  { aiLoading.classList.remove("hidden");  aiSection.classList.remove("hidden"); }
  if (state === "results"  && aiResults)  { aiResults.classList.remove("hidden");  aiSection.classList.remove("hidden"); }
  if (state === "disabled" && aiDisabled) { aiDisabled.classList.remove("hidden"); aiSection.classList.remove("hidden"); }
  if (state === "error"    && aiErrorEl)  { aiErrorEl.classList.remove("hidden");  aiSection.classList.remove("hidden"); }
  if (state === "hidden"   && aiSection)  { aiSection.classList.add("hidden"); }
}

/**
 * Handle background analysis completion.
 * Front-end displays unified threat intelligence without external service mentions.
 */
function renderAiResult(aiResult, aiSettings) {
  // Main popup presents a unified threat evaluation dashboard.
}

/* ── Render: History ──────────────────────────────────────────────────────── */

function renderHistory(history) {
  historyList.innerHTML = "";
  if (!history || history.length === 0) {
    const li = document.createElement("li");
    li.className   = "empty-state";
    li.textContent = "No detections yet";
    historyList.appendChild(li);
    return;
  }
  history.slice(0, 5).forEach(function (entry) {
    const score  = entry.score || 0;
    const colour = getLevelColour(score);
    const li = document.createElement("li");
    li.className = "history-item";

    const ss = document.createElement("span");
    ss.className   = "history-score";
    ss.style.color = colour;
    ss.textContent = score;


    const us = document.createElement("span");
    us.className   = "history-url";
    us.textContent = hostnameOf(entry.url || "");
    us.title       = entry.url || "";

    const ts = document.createElement("span");
    ts.className   = "history-time";
    ts.textContent = relativeTime(entry.timestamp || entry.assessedAt);

    li.appendChild(ss); li.appendChild(us); li.appendChild(ts);
    historyList.appendChild(li);
  });
}

/* ── Toggle helpers ───────────────────────────────────────────────────────── */

function setToggleState(enabled) {
  toggleInput.checked = enabled;
  if (enabled) toggleTrack.classList.add("active");
  else          toggleTrack.classList.remove("active");
}

function setAiToggleState(enabled) {
  if (!aiEnabledToggle) return;
  aiEnabledToggle.checked = enabled;
  if (enabled) aiMiniTrack.classList.add("active");
  else          aiMiniTrack.classList.remove("active");
}

/* ── Settings ─────────────────────────────────────────────────────────────── */

function populateSettings(settings, aiSettings) {
  if (settings) {
    const wt = document.getElementById("warning-threshold");
    const bt = document.getElementById("block-threshold");
    const hl = document.getElementById("history-limit");
    if (wt && settings.warningThreshold !== undefined) wt.value = settings.warningThreshold;
    if (bt && settings.blockThreshold   !== undefined) bt.value = settings.blockThreshold;
    if (hl && settings.historyLimit     !== undefined) hl.value = settings.historyLimit;
  }
  if (aiSettings) {
    setAiToggleState(!!aiSettings.aiEnabled);
    const mi = document.getElementById("ai-model-input");
    if (mi && aiSettings.aiModel) {
      let found = false;
      for (let i = 0; i < mi.options.length; i++) {
        if (mi.options[i].value === aiSettings.aiModel) {
          mi.selectedIndex = i;
          found = true;
          break;
        }
      }
      if (!found) {
        const opt = document.createElement("option");
        opt.value = aiSettings.aiModel;
        opt.textContent = aiSettings.aiModel;
        mi.appendChild(opt);
        mi.value = aiSettings.aiModel;
      }
    }

    // Show key status row if a key is already stored
    if (aiSettings.hasKey) {
      aiKeyStatusLbl.textContent = "✓ Configured (Key saved)";
      aiKeyStatusRow.classList.remove("hidden");
    }
  }
}

/* ── AI Settings UI helpers ───────────────────────────────────────────────── */

function showConnStatus(text, cls) {
  aiConnStatus.textContent  = text;
  aiConnStatus.className    = "ai-conn-status " + cls;
  aiConnStatus.classList.remove("hidden");
}

/* ── Main: DOMContentLoaded ──────────────────────────────────────────────── */

document.addEventListener("DOMContentLoaded", function () {

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const tab = tabs && tabs.length > 0 ? tabs[0] : null;

    // Load all data in parallel
    Promise.all([
      tab ? send(MSG.GET_TAB_RISK,      { tabId: tab.id }) : Promise.resolve(null),
      tab ? send(MSG.GET_TAB_AI_RESULT, { tabId: tab.id }) : Promise.resolve(null),
      send(MSG.GET_SETTINGS),
      send(MSG.GET_AI_SETTINGS),
      send(MSG.GET_HISTORY),
    ]).then(function ([riskResult, aiResult, settings, aiSettings, history]) {
      renderRisk(riskResult || null, tab);
      renderHistory(history || []);

      if (settings) {
        setToggleState(settings.enabled !== false);
        populateSettings(settings, aiSettings || {});
      }

      renderAiResult(aiResult, aiSettings || {});
    });
  });

  /* ── Protection toggle ────────────────────────────────────────────────── */
  toggleInput.addEventListener("change", function () {
    send(MSG.TOGGLE_PROTECTION);
    if (toggleInput.checked) toggleTrack.classList.add("active");
    else                      toggleTrack.classList.remove("active");
  });

  /* ── Settings open/close ──────────────────────────────────────────────── */
  document.getElementById("open-settings-btn").addEventListener("click", function () {
    settingsPanel.classList.toggle("hidden");
  });

  document.getElementById("cancel-settings-btn").addEventListener("click", function () {
    settingsPanel.classList.add("hidden");
  });

  /* ── Protection & Analysis settings save ──────────────────────────────── */
  document.getElementById("save-settings-btn").addEventListener("click", function () {
    const wt = parseInt(document.getElementById("warning-threshold").value, 10);
    const bt = parseInt(document.getElementById("block-threshold").value, 10);
    const hl = parseInt(document.getElementById("history-limit").value, 10);
    const mi = document.getElementById("ai-model-input") ? document.getElementById("ai-model-input").value.trim() : "";
    const key = aiApiKeyEl ? aiApiKeyEl.value.trim() : "";
    const aiEnabled = aiEnabledToggle ? aiEnabledToggle.checked : false;

    const p1 = send(MSG.SET_SETTINGS, {
      settings: { warningThreshold: wt, blockThreshold: bt, historyLimit: hl },
    });
    const p2 = send(MSG.SET_AI_SETTINGS, {
      settings: { aiModel: mi || undefined, aiEnabled },
    });
    const p3 = key ? send(MSG.SAVE_AI_KEY, { key }) : Promise.resolve();

    Promise.all([p1, p2, p3]).then(function () {
      if (key) {
        aiApiKeyEl.value = "";
        aiKeyStatusLbl.textContent = "✓ Configured (Key saved)";
        aiKeyStatusRow.classList.remove("hidden");
      }
      showConnStatus("Settings saved successfully.", "ai-conn-ok");
      setTimeout(function () {
        settingsPanel.classList.add("hidden");
      }, 500);
    });
  });

  /* ── Clear history ────────────────────────────────────────────────────── */
  document.getElementById("clear-history-btn").addEventListener("click", function () {
    send(MSG.CLEAR_HISTORY).then(function () {
      renderHistory([]);
    });
  });

  /* ── AI enable toggle ─────────────────────────────────────────────────── */
  if (aiEnabledToggle) {
    aiEnabledToggle.addEventListener("change", function () {
      const enabled = aiEnabledToggle.checked;
      if (enabled) aiMiniTrack.classList.add("active");
      else          aiMiniTrack.classList.remove("active");
      send(MSG.SET_AI_SETTINGS, { settings: { aiEnabled: enabled } });
    });
  }

  /* ── Show/hide API key ────────────────────────────────────────────────── */
  const showKeyBtn  = document.getElementById("show-key-btn");
  const aiApiKeyEl  = document.getElementById("ai-api-key");
  if (showKeyBtn && aiApiKeyEl) {
    showKeyBtn.addEventListener("click", function () {
      const isPass = aiApiKeyEl.type === "password";
      aiApiKeyEl.type       = isPass ? "text" : "password";
      showKeyBtn.textContent = isPass ? "🙈" : "👁";
    });
  }

  /* ── Save API key ─────────────────────────────────────────────────────── */
  const saveKeyBtn = document.getElementById("save-ai-key-btn");
  if (saveKeyBtn && aiApiKeyEl) {
    saveKeyBtn.addEventListener("click", function () {
      const key = aiApiKeyEl.value.trim();
      if (!key) {
        showConnStatus("Enter an API key first.", "ai-conn-fail");
        return;
      }
      saveKeyBtn.disabled   = true;
      saveKeyBtn.textContent = "Saving…";
      send(MSG.SAVE_AI_KEY, { key }).then(function (res) {
        saveKeyBtn.disabled   = false;
        saveKeyBtn.textContent = "Save Key";
        if (res && res.ok) {
          aiApiKeyEl.value = "";
          aiApiKeyEl.type  = "password";
          aiKeyStatusLbl.textContent = "✓ Configured (Key saved)";
          aiKeyStatusRow.classList.remove("hidden");
          showConnStatus("Configuration saved. Click Verify Configuration to test.", "ai-conn-info");
        } else {
          showConnStatus("Failed to save key.", "ai-conn-fail");
        }
      });
    });
  }

  /* ── Clear API key ────────────────────────────────────────────────────── */
  const clearKeyBtn = document.getElementById("clear-key-btn");
  if (clearKeyBtn) {
    clearKeyBtn.addEventListener("click", function () {
      send(MSG.CLEAR_AI_KEY).then(function () {
        aiKeyStatusRow.classList.add("hidden");
        aiKeyStatusLbl.textContent = "";
        showConnStatus("Configuration cleared.", "ai-conn-info");
      });
    });
  }

  /* ── Save model selection ─────────────────────────────────────────────── */
  const aiModelInput = document.getElementById("ai-model-input");
  if (aiModelInput) {
    aiModelInput.addEventListener("change", function () {
      const model = aiModelInput.value.trim();
      if (model) send(MSG.SET_AI_SETTINGS, { settings: { aiModel: model } });
    });
  }

  /* ── Verify configuration ─────────────────────────────────────────────── */
  const testBtn = document.getElementById("test-connection-btn");
  if (testBtn) {
    testBtn.addEventListener("click", function () {
      testBtn.disabled   = true;
      testBtn.textContent = "Verifying…";
      showConnStatus("Verifying configuration…", "ai-conn-info");

      send(MSG.TEST_AI_CONNECTION).then(function (result) {
        testBtn.disabled   = false;
        testBtn.textContent = "Verify Configuration";
        if (!result) {
          showConnStatus("No response from background service.", "ai-conn-fail");
          return;
        }
        if (result.ok) {
          showConnStatus("✓ Configuration verified successfully.", "ai-conn-ok");
        } else {
          const errMap = {
            "INVALID_KEY":  "Invalid API key.",
            "RATE_LIMITED": "Service busy. Try again shortly.",
            "MODEL_ERROR":  "Selected model unavailable.",
            "TIMEOUT":      "Request timed out.",
            "NETWORK":      "Network connection error.",
          };
          const msg = errMap[result.kind] || (result.error || "Verification failed.");
          showConnStatus("✗ " + msg, "ai-conn-fail");
        }
      });
    });
  }
});
