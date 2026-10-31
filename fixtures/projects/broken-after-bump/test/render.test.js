const test = require("node:test");
const assert = require("node:assert");
const { renderGreeting } = require("../src/render");

test("renders a greeting", () => {
  assert.strictEqual(renderGreeting("owl"), "Hello owl!");
});
