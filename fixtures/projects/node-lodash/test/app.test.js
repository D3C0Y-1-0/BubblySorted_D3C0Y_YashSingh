const test = require("node:test");
const assert = require("node:assert");
const { createApp } = require("../src/app");

test("health, capitalize and sum respond", async () => {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const health = await (await fetch(`${base}/health`)).json();
    assert.deepStrictEqual(health, { status: "ok" });
    const cap = await (await fetch(`${base}/capitalize?text=owl`)).json();
    assert.strictEqual(cap.result, "Owl");
    const sum = await (await fetch(`${base}/sum`)).json();
    assert.strictEqual(sum.result, 6);
  } finally {
    server.close();
  }
});
