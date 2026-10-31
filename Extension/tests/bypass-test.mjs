import assert from "node:assert";

// Mock chrome.storage.local for tests
const storage = {};
globalThis.chrome = {
  storage: {
    local: {
      get: (keys, cb) => {
        const res = {};
        if (Array.isArray(keys)) {
          for (const k of keys) res[k] = storage[k];
        } else if (typeof keys === "string") {
          res[keys] = storage[keys];
        } else if (typeof keys === "object" && keys !== null) {
          for (const k of Object.keys(keys)) {
            res[k] = storage[k] !== undefined ? storage[k] : keys[k];
          }
        }
        if (cb) cb(res);
        return Promise.resolve(res);
      },
      set: (obj, cb) => {
        Object.assign(storage, obj);
        if (cb) cb();
        return Promise.resolve();
      },
      remove: (keys, cb) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        for (const k of arr) delete storage[k];
        if (cb) cb();
        return Promise.resolve();
      }
    }
  }
};

async function runBypassTests() {
  const {
    normalizeBypassUrl,
    setTemporaryBypass,
    isUrlBypassed
  } = await import("../utils/storage.js");

  console.log("=== Testing Temporary Bypass Flow ===");

  // 1. Normalization
  assert.strictEqual(
    normalizeBypassUrl("https://testsafebrowsing.appspot.com/s/phishing.html/"),
    "https://testsafebrowsing.appspot.com/s/phishing.html"
  );
  assert.strictEqual(
    normalizeBypassUrl("https://TestSafeBrowsing.Appspot.Com/s/phishing.html?param=1"),
    "https://testsafebrowsing.appspot.com/s/phishing.html"
  );
  console.log("  ✓ URL normalization functions correctly");

  // 2. Initial state: URL not bypassed
  const testUrl1 = "https://testsafebrowsing.appspot.com/s/phishing.html";
  const testUrl2 = "https://malicious-phishing-site.tk/login";

  assert.strictEqual(await isUrlBypassed(testUrl1), false);
  assert.strictEqual(await isUrlBypassed(testUrl2), false);
  console.log("  ✓ Unregistered URLs are not bypassed");

  // 3. Register bypass for testUrl1
  await setTemporaryBypass(testUrl1, 5 * 60 * 1000); // 5 min TTL
  assert.strictEqual(await isUrlBypassed(testUrl1), true);
  assert.strictEqual(await isUrlBypassed("https://testsafebrowsing.appspot.com/s/phishing.html/"), true);
  console.log("  ✓ Target URL is bypassed after user confirmation");

  // 4. Other URLs MUST NOT be bypassed (no global disable)
  assert.strictEqual(await isUrlBypassed(testUrl2), false);
  assert.strictEqual(await isUrlBypassed("https://different-phishing.org"), false);
  console.log("  ✓ Other websites remain strictly protected (no global bypass)");

  // 5. Expiration / TTL handling
  const expiringUrl = "https://short-ttl-test.com/login";
  await setTemporaryBypass(expiringUrl, -1000); // Already expired
  assert.strictEqual(await isUrlBypassed(expiringUrl), false);
  console.log("  ✓ Expired bypasses are ignored and return false");

  // 6. Non-HTTP protocols are rejected safely
  assert.strictEqual(normalizeBypassUrl(""), "");
  assert.strictEqual(await isUrlBypassed(""), false);
  assert.strictEqual(await isUrlBypassed("javascript:alert(1)"), false);
  console.log("  ✓ Malformed and non-HTTP URLs handled safely");

  console.log("\n──────────────────────────────────────────────────");
  console.log("All 6 bypass regression tests passed successfully!");
}

runBypassTests().catch(err => {
  console.error("Bypass tests failed:", err);
  process.exit(1);
});

