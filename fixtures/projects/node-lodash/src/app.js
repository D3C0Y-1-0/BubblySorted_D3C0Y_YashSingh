const express = require("express");
const _ = require("lodash");

function createApp() {
  const app = express();

  app.get("/health", (req, res) => res.json({ status: "ok" }));

  app.get("/capitalize", (req, res) => {
    res.json({ result: _.capitalize(String(req.query.text || "hello")) });
  });

  app.get("/sum", (req, res) => {
    res.json({ result: _.sum([1, 2, 3]) });
  });

  return app;
}

module.exports = { createApp };
