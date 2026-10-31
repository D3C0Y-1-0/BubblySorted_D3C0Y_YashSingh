"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { createApp } = require("../src/app");

function serve() {
  return new Promise((resolve) => {
    const server = createApp().listen(0, () => resolve(server));
  });
}

async function get(server, path) {
  const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`);
  return { status: res.status, body: await res.json() };
}

test("health is ok", async () => {
  const server = await serve();
  try {
    const { status, body } = await get(server, "/health");
    assert.strictEqual(status, 200);
    assert.deepStrictEqual(body, { status: "ok" });
  } finally {
    server.close();
  }
});

test("offers uses lodash", async () => {
  const server = await serve();
  try {
    const { status, body } = await get(server, "/offers");
    assert.strictEqual(status, 200);
    assert.strictEqual(body.count, 3);
    assert.strictEqual(body.offers[0].id, 1);
  } finally {
    server.close();
  }
});

test("token and verify use jsonwebtoken", async () => {
  const server = await serve();
  try {
    const token = await get(server, "/token");
    assert.strictEqual(token.status, 200);
    assert.ok(token.body.token.split(".").length === 3);
    const verify = await get(server, "/verify");
    assert.strictEqual(verify.body.valid, true);
  } finally {
    server.close();
  }
});
