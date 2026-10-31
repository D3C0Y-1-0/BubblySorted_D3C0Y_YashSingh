import assert from "node:assert";

// Mock chrome.storage.local
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

async function testStorage() {
  const {
    getSettings, updateSettings,
    getAiSettings, updateAiSettings,
    saveAiKey, getAiKey, hasAiKey, clearAiKey
  } = await import("../utils/storage.js");

  // 1. Initial settings
  const initialSettings = await getSettings();
  assert.strictEqual(initialSettings.enabled, true);

  // 2. Save settings
  await updateSettings({ warningThreshold: 65, blockThreshold: 88, historyLimit: 60 });
  const updatedSettings = await getSettings();
  assert.strictEqual(updatedSettings.warningThreshold, 65);
  assert.strictEqual(updatedSettings.blockThreshold, 88);
  assert.strictEqual(updatedSettings.historyLimit, 60);

  // 3. API Key & Model
  assert.strictEqual(await hasAiKey(), false);
  await saveAiKey("test-api-key-12345");
  assert.strictEqual(await hasAiKey(), true);
  assert.strictEqual(await getAiKey(), "test-api-key-12345");

  await updateAiSettings({ aiEnabled: true, aiModel: "llama-3.3-70b-versatile" });
  const aiSettings = await getAiSettings();
  assert.strictEqual(aiSettings.aiEnabled, true);
  assert.strictEqual(aiSettings.aiModel, "llama-3.3-70b-versatile");

  // 4. Clear key
  await clearAiKey();
  assert.strictEqual(await hasAiKey(), false);
  assert.strictEqual(await getAiKey(), null);

  console.log("✓ Settings storage & persistence verification passed!");
}

testStorage().catch(err => {
  console.error("Storage test failed:", err);
  process.exit(1);
});
