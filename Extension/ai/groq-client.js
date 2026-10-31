/**
 * groq-client.js — Low-level Groq API client for Hedwig Shield.
 *
 * Handles all HTTP communication with Groq's OpenAI-compatible endpoint.
 * No business logic lives here — only transport, error classification, and
 * response parsing.
 *
 * Security note: The API key is passed in at call time from chrome.storage.local.
 * It is never logged, never embedded in source, and never exposed in the UI
 * after initial entry. A browser-extension API key is not a server-side secret —
 * anyone with access to the extension's local storage can read it. This is
 * documented and accepted for the hackathon prototype.
 */

import { GROQ_ENDPOINT, GROQ_TIMEOUT_MS } from "../utils/constants.js";

// ── Error types ───────────────────────────────────────────────────────────────

export const GroqErrorKind = Object.freeze({
  INVALID_KEY:    "INVALID_KEY",     // 401 Unauthorized
  RATE_LIMITED:   "RATE_LIMITED",    // 429 Too Many Requests
  MODEL_ERROR:    "MODEL_ERROR",     // 400 / bad model name
  SERVER_ERROR:   "SERVER_ERROR",    // 5xx
  TIMEOUT:        "TIMEOUT",         // fetch timed out
  NETWORK:        "NETWORK",         // fetch threw (offline / DNS)
  PARSE_ERROR:    "PARSE_ERROR",     // response body not valid JSON
  UNKNOWN:        "UNKNOWN",
});

export class GroqError extends Error {
  /**
   * @param {string} kind    — one of GroqErrorKind
   * @param {string} message — human-readable explanation
   * @param {number} [status] — HTTP status code if available
   */
  constructor(kind, message, status) {
    super(message);
    this.name   = "GroqError";
    this.kind   = kind;
    this.status = status ?? null;
  }
}

// ── Core request ──────────────────────────────────────────────────────────────

/**
 * Send a chat completions request to Groq.
 *
 * @param {object} opts
 * @param {string}   opts.apiKey    — user-supplied Groq API key
 * @param {string}   opts.model     — Groq model identifier
 * @param {object[]} opts.messages  — OpenAI-format messages array
 * @param {number}  [opts.maxTokens]  — response token limit (default 512)
 * @param {number}  [opts.temperature] — 0–1 (default 0.1 for deterministic output)
 * @param {number}  [opts.timeoutMs] — override default timeout
 * @returns {Promise<object>}  — parsed chat completion response object
 * @throws  {GroqError}
 */
export async function callGroq({
  apiKey,
  model,
  messages,
  maxTokens   = 512,
  temperature = 0.1,
  timeoutMs   = GROQ_TIMEOUT_MS,
}) {
  if (!apiKey || typeof apiKey !== "string" || !apiKey.trim()) {
    throw new GroqError(GroqErrorKind.INVALID_KEY, "No API key provided.");
  }

  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), timeoutMs);

  let response;
  try {
    response = await fetch(GROQ_ENDPOINT, {
      method:  "POST",
      signal:  controller.signal,
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages,
        max_tokens:  maxTokens,
        temperature,
        // Ask for JSON output when the model supports it.
        // We also instruct via the system prompt for compatibility.
        response_format: { type: "json_object" },
      }),
    });
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      throw new GroqError(GroqErrorKind.TIMEOUT, `Request timed out after ${timeoutMs}ms.`);
    }
    throw new GroqError(GroqErrorKind.NETWORK, `Network error: ${err.message}`);
  }

  clearTimeout(timer);

  // ── HTTP error classification ─────────────────────────────────────────────
  if (!response.ok) {
    let body = "";
    try { body = await response.text(); } catch (_) { /* ignore */ }

    switch (response.status) {
      case 401:
        throw new GroqError(GroqErrorKind.INVALID_KEY, "Invalid or expired API key.", 401);
      case 429:
        throw new GroqError(GroqErrorKind.RATE_LIMITED, "Rate limit reached. Try again later.", 429);
      case 400:
        throw new GroqError(
          GroqErrorKind.MODEL_ERROR,
          `Bad request (${response.status}). Check the model name. Details: ${body.slice(0, 200)}`,
          400
        );
      default:
        if (response.status >= 500) {
          throw new GroqError(GroqErrorKind.SERVER_ERROR, `Groq server error (${response.status}).`, response.status);
        }
        throw new GroqError(GroqErrorKind.UNKNOWN, `Unexpected HTTP ${response.status}: ${body.slice(0, 200)}`, response.status);
    }
  }

  // ── Parse response ────────────────────────────────────────────────────────
  let parsed;
  try {
    parsed = await response.json();
  } catch (err) {
    throw new GroqError(GroqErrorKind.PARSE_ERROR, `Failed to parse API response: ${err.message}`);
  }

  return parsed;
}

// ── Connection test ───────────────────────────────────────────────────────────

/**
 * Send a minimal request to verify the API key and model are valid.
 *
 * @param {string} apiKey
 * @param {string} model
 * @returns {Promise<{ ok: true, model: string } | { ok: false, error: string, kind: string }>}
 */
export async function testConnection(apiKey, model) {
  try {
    const result = await callGroq({
      apiKey,
      model,
      messages:    [{ role: "user", content: "Reply with: {\"status\":\"ok\"}" }],
      maxTokens:   20,
      temperature: 0,
      timeoutMs:   10_000,
    });
    const content = result?.choices?.[0]?.message?.content ?? "";
    return { ok: true, model, preview: content.slice(0, 60) };
  } catch (err) {
    return {
      ok:    false,
      error: err.message,
      kind:  err instanceof GroqError ? err.kind : GroqErrorKind.UNKNOWN,
    };
  }
}

/**
 * Extract the assistant message text from a chat completion response.
 *
 * @param {object} response — raw Groq API response
 * @returns {string}
 */
export function extractContent(response) {
  return response?.choices?.[0]?.message?.content ?? "";
}

