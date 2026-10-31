/**
 * storage.js — Typed wrappers around chrome.storage.local for Hedwig Shield.
 *
 * All persistent state goes through this module so the rest of the codebase
 * never calls chrome.storage directly.
 */

import { STORAGE_KEYS, DEFAULT_SETTINGS, DEFAULT_AI_SETTINGS, AI_CACHE_TTL_MS, BYPASS_TTL_MS } from "./constants.js";

// ── Settings ─────────────────────────────────────────────────────────────────

/**
 * Load user settings, merging with defaults so new keys are always present.
 * @returns {Promise<object>}
 */
export async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.SETTINGS, (result) => {
      resolve({ ...DEFAULT_SETTINGS, ...(result[STORAGE_KEYS.SETTINGS] ?? {}) });
    });
  });
}

/**
 * Persist a partial settings update (merges with existing values).
 * @param {object} patch
 * @returns {Promise<void>}
 */
export async function updateSettings(patch) {
  const current = await getSettings();
  const merged = { ...current, ...patch };
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: merged }, resolve);
  });
}

// ── Per-tab risk cache ────────────────────────────────────────────────────────

/**
 * Retrieve the stored risk result for a specific tab.
 * @param {number} tabId
 * @returns {Promise<object|null>}
 */
export async function getTabRisk(tabId) {
  const key = `${STORAGE_KEYS.TAB_RISK}_${tabId}`;
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (result) => {
      resolve(result[key] ?? null);
    });
  });
}

/**
 * Store the risk result for a specific tab.
 * @param {number} tabId
 * @param {object} riskResult  — full output from risk-engine.js
 * @returns {Promise<void>}
 */
export async function setTabRisk(tabId, riskResult) {
  const key = `${STORAGE_KEYS.TAB_RISK}_${tabId}`;
  return new Promise((resolve) => {
    chrome.storage.local.set({ [key]: riskResult }, resolve);
  });
}

/**
 * Remove stored risk data for a tab (called on tab close / navigate away).
 * @param {number} tabId
 * @returns {Promise<void>}
 */
export async function clearTabRisk(tabId) {
  const key = `${STORAGE_KEYS.TAB_RISK}_${tabId}`;
  return new Promise((resolve) => {
    chrome.storage.local.remove(key, resolve);
  });
}

// ── Detection history ─────────────────────────────────────────────────────────

/**
 * Load the full detection history array (newest first).
 * @returns {Promise<object[]>}
 */
export async function getHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.HISTORY, (result) => {
      resolve(result[STORAGE_KEYS.HISTORY] ?? []);
    });
  });
}

/**
 * Prepend a detection event to history, respecting the configured limit.
 * @param {object} entry  — { url, score, level, signals, timestamp }
 * @returns {Promise<void>}
 */
export async function appendHistory(entry) {
  const [history, settings] = await Promise.all([getHistory(), getSettings()]);
  const limit = settings.historyLimit ?? 50;
  const updated = [entry, ...history].slice(0, limit);
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: updated }, resolve);
  });
}

/**
 * Wipe all detection history.
 * @returns {Promise<void>}
 */
export async function clearHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.remove(STORAGE_KEYS.HISTORY, resolve);
  });
}

// ── AI Settings ───────────────────────────────────────────────────────────────

/**
 * Load AI settings, merged with defaults.
 * @returns {Promise<object>}
 */
export async function getAiSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.AI_SETTINGS, (result) => {
      resolve({ ...DEFAULT_AI_SETTINGS, ...(result[STORAGE_KEYS.AI_SETTINGS] ?? {}) });
    });
  });
}

/**
 * Persist AI settings patch.
 * @param {object} patch
 * @returns {Promise<void>}
 */
export async function updateAiSettings(patch) {
  const current = await getAiSettings();
  const merged  = { ...current, ...patch };
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.AI_SETTINGS]: merged }, resolve);
  });
}

// ── AI API Key ────────────────────────────────────────────────────────────────

/**
 * Retrieve the stored Groq API key, or null if none.
 * SECURITY: Never log this value.
 * @returns {Promise<string|null>}
 */
export async function getAiKey() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.AI_KEY, (result) => {
      resolve(result[STORAGE_KEYS.AI_KEY] ?? null);
    });
  });
}

/**
 * Store the Groq API key.
 * SECURITY: Never log or display the raw key after this point.
 * @param {string} key
 * @returns {Promise<void>}
 */
export async function saveAiKey(key) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.AI_KEY]: key }, resolve);
  });
}

/**
 * Remove the stored API key.
 * @returns {Promise<void>}
 */
export async function clearAiKey() {
  return new Promise((resolve) => {
    chrome.storage.local.remove(STORAGE_KEYS.AI_KEY, resolve);
  });
}

/**
 * Check if an API key is stored (without exposing it).
 * @returns {Promise<boolean>}
 */
export async function hasAiKey() {
  const key = await getAiKey();
  return !!key && key.trim().length > 0;
}

// ── AI Result Cache ───────────────────────────────────────────────────────────

/**
 * Retrieve cached AI result for a URL.
 * Returns null if not cached or if TTL has expired.
 * @param {string} url
 * @returns {Promise<object|null>}
 */
export async function getCachedAiResult(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.AI_CACHE, (result) => {
      const cache = result[STORAGE_KEYS.AI_CACHE] ?? {};
      const cacheKey = urlToCacheKey(url);
      const entry = cache[cacheKey];
      if (!entry) { resolve(null); return; }
      // Check TTL
      if (Date.now() - entry.timestamp > AI_CACHE_TTL_MS) {
        // Expired — clean up asynchronously
        delete cache[cacheKey];
        chrome.storage.local.set({ [STORAGE_KEYS.AI_CACHE]: cache }, () => {});
        resolve(null);
        return;
      }
      resolve({ ...entry.result, fromCache: true });
    });
  });
}

/**
 * Cache an AI result for a URL.
 * @param {string} url
 * @param {object} result — AiAnalysisResult
 * @returns {Promise<void>}
 */
export async function cacheAiResult(url, result) {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.AI_CACHE, (data) => {
      const cache = data[STORAGE_KEYS.AI_CACHE] ?? {};
      const cacheKey = urlToCacheKey(url);

      // Evict old entries if cache grows too large (keep last 30)
      const keys = Object.keys(cache);
      if (keys.length >= 30) {
        const sorted = keys.sort((a, b) => (cache[a].timestamp ?? 0) - (cache[b].timestamp ?? 0));
        sorted.slice(0, keys.length - 29).forEach(k => delete cache[k]);
      }

      cache[cacheKey] = { result, timestamp: Date.now() };
      chrome.storage.local.set({ [STORAGE_KEYS.AI_CACHE]: cache }, resolve);
    });
  });
}

// ── Per-tab AI result ─────────────────────────────────────────────────────────

/**
 * Store the AI result for a specific tab.
 * @param {number} tabId
 * @param {object} aiResult
 * @returns {Promise<void>}
 */
export async function setTabAiResult(tabId, aiResult) {
  const key = `${STORAGE_KEYS.TAB_AI_RESULT}_${tabId}`;
  return new Promise((resolve) => {
    chrome.storage.local.set({ [key]: aiResult }, resolve);
  });
}

/**
 * Retrieve stored AI result for a tab.
 * @param {number} tabId
 * @returns {Promise<object|null>}
 */
export async function getTabAiResult(tabId) {
  const key = `${STORAGE_KEYS.TAB_AI_RESULT}_${tabId}`;
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (result) => {
      resolve(result[key] ?? null);
    });
  });
}

/**
 * Remove AI result for a tab.
 * @param {number} tabId
 */
export function clearTabAiResult(tabId) {
  const key = `${STORAGE_KEYS.TAB_AI_RESULT}_${tabId}`;
  chrome.storage.local.remove(key);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Normalise a URL to a consistent cache key (hostname + path, no query/hash). */
function urlToCacheKey(urlString) {
  try {
    const u = new URL(urlString);
    return (u.hostname + u.pathname).toLowerCase().replace(/\/$/, "");
  } catch (_) {
    return urlString.slice(0, 200).toLowerCase();
  }
}


// ── Temporary User Bypass (Warning Page "Proceed Anyway") ───────────────────

/**
 * Normalise a URL for bypass matching (origin + pathname without trailing slash).
 * Matches the page path while ignoring query differences, ensuring that sub-requests
 * or slightly altered query params on the allowed page do not trigger a redirect loop.
 * @param {string} urlString
 * @returns {string}
 */
export function normalizeBypassUrl(urlString) {
  if (!urlString || typeof urlString !== "string") return "";
  try {
    const u = new URL(urlString);
    return (u.origin + u.pathname).toLowerCase().replace(/\/+$/, "");
  } catch (_) {
    return urlString.toLowerCase().trim().replace(/\/+$/, "");
  }
}

/**
 * Register a temporary bypass for a specific URL with an expiration TTL.
 * @param {string} url
 * @param {number} [ttlMs=BYPASS_TTL_MS]
 * @returns {Promise<void>}
 */
export async function setTemporaryBypass(url, ttlMs = BYPASS_TTL_MS) {
  if (!url) return;
  const normalized = normalizeBypassUrl(url);
  const now = Date.now();
  const expiresAt = now + ttlMs;

  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.BYPASS_URLS, (data) => {
      const bypasses = data[STORAGE_KEYS.BYPASS_URLS] ?? {};
      // Prune expired entries
      for (const [k, v] of Object.entries(bypasses)) {
        if (!v || (v.expiresAt && v.expiresAt < now)) {
          delete bypasses[k];
        }
      }
      bypasses[normalized] = {
        url,
        normalized,
        timestamp: now,
        expiresAt,
      };
      chrome.storage.local.set({ [STORAGE_KEYS.BYPASS_URLS]: bypasses }, resolve);
    });
  });
}

/**
 * Test whether a URL has an active, unexpired temporary bypass.
 * @param {string} url
 * @returns {Promise<boolean>}
 */
export async function isUrlBypassed(url) {
  if (!url) return false;
  const normalized = normalizeBypassUrl(url);
  const now = Date.now();

  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.BYPASS_URLS, (data) => {
      const bypasses = data[STORAGE_KEYS.BYPASS_URLS] ?? {};
      const entry = bypasses[normalized];
      if (entry && entry.expiresAt > now) {
        resolve(true);
      } else {
        resolve(false);
      }
    });
  });
}
