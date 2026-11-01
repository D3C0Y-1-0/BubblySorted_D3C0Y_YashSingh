/**
 * service-worker.js — Background service worker for Hedwig Shield (MV3).
 *
 * Detection pipeline:
 *   1. webNavigation.onCommitted → URL-only risk assessment → badge + optional redirect.
 *   2. PAGE_ANALYSIS_RESULT from content script → full deterministic assessment.
 *   3. If AI enabled and key present → Groq AI analysis → merge → badge + optional redirect.
 *
 * AI note: MV3 cannot block navigation synchronously with async JS.
 * AI analysis runs after the page loads; if AI raises the score above the
 * warning threshold, the tab is redirected to warning.html (same as deterministic).
 */

import { assessRisk, getRiskLevel, mergeAiResult } from "../detection/risk-engine.js";
import { analyzeWithGroq }                          from "../ai/phishing-analyzer.js";
import { testConnection }                           from "../ai/groq-client.js";
import {
  getSettings,
  updateSettings,
  getTabRisk,
  setTabRisk,
  clearTabRisk,
  appendHistory,
  getHistory,
  clearHistory,
  getAiSettings,
  updateAiSettings,
  getAiKey,
  saveAiKey,
  clearAiKey,
  hasAiKey,
  getCachedAiResult,
  cacheAiResult,
  setTabAiResult,
  getTabAiResult,
  clearTabAiResult,
  setTemporaryBypass,
  isUrlBypassed,
} from "../utils/storage.js";
import {
  MSG,
  WARNING_THRESHOLD,
  BLOCK_THRESHOLD,
} from "../utils/constants.js";

// ── Badge ─────────────────────────────────────────────────────────────────────

function updateBadge(tabId, result) {
  const text = result.score > 0 ? String(result.score) : "";
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: text ? result.colour : "#888888",
  });
}

// ── Warning redirect ──────────────────────────────────────────────────────────

function redirectToWarning(tabId, url, result) {
  const warningUrl =
    chrome.runtime.getURL("ui/warning.html") +
    "?url="      + encodeURIComponent(url)                           +
    "&score="    + encodeURIComponent(result.score)                  +
    "&level="    + encodeURIComponent(result.level)                  +
    "&category=" + encodeURIComponent(result.threatCategory || "")   +
    "&sim="      + encodeURIComponent(result.isSimulation ? "1" : "0");
  console.log("[HEDWIG] Blocking action executed: redirecting to warning.html");
  chrome.tabs.update(tabId, { url: warningUrl });
}

// ── AI analysis helper ────────────────────────────────────────────────────────

/**
 * Run AI analysis for a tab, merge with deterministic result, persist, update badge.
 * Called from PAGE_ANALYSIS_RESULT handler after deterministic assessment.
 *
 * @param {number} tabId
 * @param {object} pageData    — page-analyzer payload
 * @param {object} detResult   — full deterministic assessRisk result
 * @param {object} settings    — user settings
 */
async function runAiAnalysis(tabId, pageData, detResult, settings) {
  const aiSettings = await getAiSettings();
  if (!aiSettings.aiEnabled) return;

  const apiKey = await getAiKey();
  if (!apiKey) return;

  const url = pageData.url || detResult.url;

  // If this URL was temporarily bypassed by the user, do not redirect
  if (await isUrlBypassed(url)) {
    console.log("[HEDWIG] Temporary bypass active — skipping AI redirect for:", url);
    return;
  }

  // Check cache first — avoid repeating analysis for the same URL
  const cached = await getCachedAiResult(url);
  if (cached) {
    const combined = mergeAiResult(detResult, cached);
    await setTabRisk(tabId, combined);
    await setTabAiResult(tabId, cached);
    updateBadge(tabId, combined);
    // Re-check warning threshold with combined score
    const warnThreshold = settings.warningThreshold ?? WARNING_THRESHOLD;
    if (combined.score >= warnThreshold && detResult.score < warnThreshold) {
      redirectToWarning(tabId, url, combined);
    }
    return;
  }

  console.log("[HEDWIG] Groq analysis started");
  let aiResult;
  try {
    aiResult = await analyzeWithGroq({
      pageData,
      deterministicSignals: detResult.signals ?? [],
      apiKey,
      model: aiSettings.aiModel,
    });
    console.log("[HEDWIG] Groq analysis completed:", {
      isPhishing: aiResult.isPhishing,
      isSimulation: aiResult.isSimulation,
      confidence: aiResult.confidence,
      threatCategory: aiResult.threatCategory
    });
  } catch (err) {
    console.error("[HEDWIG ERROR] Groq analysis failed:", err);
    return; // Graceful fallback — deterministic result stands
  }

  // Cache result (cache both successes and soft failures for TTL)
  await cacheAiResult(url, aiResult);
  await setTabAiResult(tabId, aiResult);

  // Merge into final result
  const combined = mergeAiResult(detResult, aiResult);
  await setTabRisk(tabId, combined);
  updateBadge(tabId, combined);

  console.log("[HEDWIG] Risk score calculated:", {
    finalScore: combined.score,
    level: combined.level,
    category: combined.threatCategory
  });

  const warnThreshold = settings.warningThreshold ?? WARNING_THRESHOLD;
  const shouldWarn = combined.score >= warnThreshold;
  console.log("[HEDWIG] Protection decision:", {
    score: combined.score,
    category: combined.threatCategory,
    threshold: warnThreshold,
    action: shouldWarn ? "block/warn" : "allow"
  });

  // Append to history if AI raised significance
  if (aiResult.success && (aiResult.isPhishing || aiResult.isSimulation) && combined.score >= 30) {
    await appendHistory({
      url,
      score:     combined.score,
      level:     combined.level,
      category:  combined.threatCategory,
      signals:   combined.signals.map(s => ({ id: s.id, label: s.label })),
      timestamp: combined.assessedAt,
      aiFlag:    true,
    });
  }

  // Redirect if the AI pushed the combined score over the warning threshold
  if (shouldWarn && detResult.score < warnThreshold) {
    redirectToWarning(tabId, url, combined);
  }
}

// ── Navigation listener ───────────────────────────────────────────────────────

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (
    url.startsWith("chrome-extension://") ||
    url.startsWith("chrome://")           ||
    url.startsWith("about:")              ||
    url.startsWith("data:")               ||
    url.startsWith("javascript:")
  ) return;

  try {
    console.log("[HEDWIG] Navigation detected:", url);

    // Check if the user chose to proceed past the warning for this specific URL
    if (await isUrlBypassed(url)) {
      console.log("[HEDWIG] Temporary user bypass active — allowing navigation to:", url);
      await setTabRisk(details.tabId, {
        url,
        score: 0,
        level: "Allowed",
        colour: "#4caf50",
        threatCategory: "SAFE_WEBSITE",
        isSimulation: false,
        isBypassed: true,
        signals: [{
          id: "USER_BYPASS",
          label: "Temporary user bypass active",
          weight: 0,
          detail: "Proceeded past warning page by user confirmation."
        }],
        assessedAt: Date.now()
      });
      chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
      return;
    }

    const settings = await getSettings();
    if (!settings.enabled) {
      console.log("[HEDWIG] Protection disabled in settings — skipping");
      return;
    }

    console.log("[HEDWIG] URL analysis started");
    const result = await assessRisk(url, null);
    console.log("[HEDWIG] Domain analysis completed: score=" + (result.inputs?.domainReputation?.score ?? 0));
    console.log("[HEDWIG] Risk score calculated: initial=" + result.score + ", category=" + result.threatCategory);

    await setTabRisk(details.tabId, result);
    updateBadge(details.tabId, result);

    const warnThreshold = settings.warningThreshold ?? WARNING_THRESHOLD;
    const shouldWarn = result.score >= warnThreshold;
    console.log("[HEDWIG] Protection decision:", {
      score: result.score,
      category: result.threatCategory,
      threshold: warnThreshold,
      action: shouldWarn ? "block/warn" : "allow"
    });

    if (shouldWarn) {
      await appendHistory({
        url,
        score:     result.score,
        level:     result.level,
        category:  result.threatCategory,
        signals:   result.signals.map(s => ({ id: s.id, label: s.label })),
        timestamp: result.assessedAt,
      });
      redirectToWarning(details.tabId, url, result);
    }
  } catch (err) {
    console.error("[HEDWIG ERROR] Navigation assessment error:", err);
  }
});

// ── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  // ── PAGE_ANALYSIS_RESULT ──────────────────────────────────────────────────
  if (message.type === MSG.PAGE_ANALYSIS_RESULT) {
    (async () => {
      try {
        const tabId = sender.tab?.id;
        if (!tabId) { sendResponse({ ok: false }); return; }

        const settings = await getSettings();
        if (!settings.enabled) { sendResponse({ ok: true }); return; }

        const data = message.data;
        const url  = data?.url || sender.tab?.url;
        if (!url)  { sendResponse({ ok: false }); return; }

        // If URL has active user bypass, acknowledge content analysis without re-blocking
        if (await isUrlBypassed(url)) {
          console.log("[HEDWIG] Temporary bypass active — skipping page analysis redirect for:", url);
          sendResponse({ ok: true, bypassed: true });
          return;
        }

        console.log("[HEDWIG] Content script injected (PAGE_ANALYSIS_RESULT received)");
        const result         = await assessRisk(url, data);
        const previousResult = await getTabRisk(tabId);
        const previousScore  = previousResult?.score ?? 0;

        console.log("[HEDWIG] Page analysis completed: score=" + result.score + ", category=" + result.threatCategory);
        await setTabRisk(tabId, result);
        updateBadge(tabId, result);

        const warnThreshold = settings.warningThreshold ?? WARNING_THRESHOLD;
        const shouldWarn = result.score >= warnThreshold;
        console.log("[HEDWIG] Protection decision:", {
          score: result.score,
          category: result.threatCategory,
          threshold: warnThreshold,
          action: shouldWarn ? "block/warn" : "allow"
        });

        if (shouldWarn && previousScore < warnThreshold) {
          redirectToWarning(tabId, url, result);
        }
        if (result.score >= 30 || result.threatCategory === "PHISHING_SIMULATION") {
          await appendHistory({
            url,
            score:     result.score,
            level:     result.level,
            category:  result.threatCategory,
            signals:   result.signals.map(s => ({ id: s.id, label: s.label })),
            timestamp: result.assessedAt,
          });
        }

        sendResponse({ ok: true });

        // Kick off AI analysis in background (non-blocking — sendResponse already called)
        runAiAnalysis(tabId, data, result, settings).catch(e =>
          console.error("[Hedwig AI] background analysis error:", e)
        );
      } catch (err) {
        console.error("[Hedwig] PAGE_ANALYSIS_RESULT error:", err);
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  // ── GET_TAB_RISK ──────────────────────────────────────────────────────────
  if (message.type === MSG.GET_TAB_RISK) {
    (async () => {
      try { sendResponse(await getTabRisk(message.tabId)); }
      catch (_) { sendResponse(null); }
    })();
    return true;
  }

  // ── GET_TAB_AI_RESULT ─────────────────────────────────────────────────────
  if (message.type === MSG.GET_TAB_AI_RESULT) {
    (async () => {
      try { sendResponse(await getTabAiResult(message.tabId)); }
      catch (_) { sendResponse(null); }
    })();
    return true;
  }

  // ── GET_HISTORY ───────────────────────────────────────────────────────────
  if (message.type === MSG.GET_HISTORY) {
    (async () => {
      try { sendResponse(await getHistory()); }
      catch (_) { sendResponse([]); }
    })();
    return true;
  }

  // ── GET_SETTINGS ──────────────────────────────────────────────────────────
  if (message.type === MSG.GET_SETTINGS) {
    (async () => {
      try { sendResponse(await getSettings()); }
      catch (_) { sendResponse(null); }
    })();
    return true;
  }

  // ── SET_SETTINGS ──────────────────────────────────────────────────────────
  if (message.type === MSG.SET_SETTINGS) {
    (async () => {
      try { await updateSettings(message.settings ?? {}); sendResponse({ ok: true }); }
      catch (err) { sendResponse({ ok: false, error: String(err) }); }
    })();
    return true;
  }

  // ── CLEAR_HISTORY ─────────────────────────────────────────────────────────
  if (message.type === MSG.CLEAR_HISTORY) {
    (async () => {
      try { await clearHistory(); sendResponse({ ok: true }); }
      catch (err) { sendResponse({ ok: false }); }
    })();
    return true;
  }

  // ── TOGGLE_PROTECTION ─────────────────────────────────────────────────────
  if (message.type === MSG.TOGGLE_PROTECTION) {
    (async () => {
      try {
        const current  = await getSettings();
        const newValue = !current.enabled;
        await updateSettings({ enabled: newValue });
        sendResponse({ ok: true, enabled: newValue });
      } catch (err) { sendResponse({ ok: false }); }
    })();
    return true;
  }

  // ── GET_AI_SETTINGS ───────────────────────────────────────────────────────
  if (message.type === MSG.GET_AI_SETTINGS) {
    (async () => {
      try {
        const [aiSettings, keyPresent] = await Promise.all([getAiSettings(), hasAiKey()]);
        sendResponse({ ...aiSettings, hasKey: keyPresent });
      } catch (_) { sendResponse(null); }
    })();
    return true;
  }

  // ── SET_AI_SETTINGS ───────────────────────────────────────────────────────
  if (message.type === MSG.SET_AI_SETTINGS) {
    (async () => {
      try { await updateAiSettings(message.settings ?? {}); sendResponse({ ok: true }); }
      catch (err) { sendResponse({ ok: false }); }
    })();
    return true;
  }

  // ── SAVE_AI_KEY ───────────────────────────────────────────────────────────
  if (message.type === MSG.SAVE_AI_KEY) {
    (async () => {
      try {
        if (!message.key || typeof message.key !== "string") {
          sendResponse({ ok: false, error: "Invalid key" });
          return;
        }
        await saveAiKey(message.key.trim());
        sendResponse({ ok: true });
      } catch (err) { sendResponse({ ok: false }); }
    })();
    return true;
  }

  // ── GET_AI_KEY_STATUS ─────────────────────────────────────────────────────
  if (message.type === MSG.GET_AI_KEY_STATUS) {
    (async () => {
      try { sendResponse({ hasKey: await hasAiKey() }); }
      catch (_) { sendResponse({ hasKey: false }); }
    })();
    return true;
  }

  // ── CLEAR_AI_KEY ──────────────────────────────────────────────────────────
  if (message.type === MSG.CLEAR_AI_KEY) {
    (async () => {
      try { await clearAiKey(); sendResponse({ ok: true }); }
      catch (_) { sendResponse({ ok: false }); }
    })();
    return true;
  }

  // ── TEST_AI_CONNECTION ────────────────────────────────────────────────────
  if (message.type === MSG.TEST_AI_CONNECTION) {
    (async () => {
      try {
        const apiKey     = await getAiKey();
        const aiSettings = await getAiSettings();
        const result     = await testConnection(apiKey, aiSettings.aiModel);
        sendResponse(result);
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  // ── SET_TEMPORARY_BYPASS ──────────────────────────────────────────────────
  if (message.type === MSG.SET_TEMPORARY_BYPASS) {
    (async () => {
      try {
        const targetUrl = message.url;
        if (targetUrl) {
          await setTemporaryBypass(targetUrl);
          console.log("[HEDWIG] Registered temporary bypass for URL:", targetUrl);
          sendResponse({ ok: true });
        } else {
          sendResponse({ ok: false, error: "Missing destination URL" });
        }
      } catch (err) {
        console.error("[HEDWIG ERROR] Failed to set bypass:", err);
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  // ── IS_URL_BYPASSED ───────────────────────────────────────────────────────
  if (message.type === MSG.IS_URL_BYPASSED) {
    (async () => {
      try {
        const bypassed = await isUrlBypassed(message.url);
        sendResponse({ bypassed });
      } catch (_) {
        sendResponse({ bypassed: false });
      }
    })();
    return true;
  }

  return false;
});

// ── Tab cleanup ───────────────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabRisk(tabId).catch(() => {});
  clearTabAiResult(tabId);
});

// ── Active tab change ─────────────────────────────────────────────────────────

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const result = await getTabRisk(tabId);
    if (result) {
      updateBadge(tabId, result);
    } else {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch (_) { /* ignore */ }
});
