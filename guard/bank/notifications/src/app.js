"use strict";

const _ = require("lodash");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

// A fixed demo secret; no real accounts exist. Tokens are signed and verified over constants
// only, so no user input reaches a vulnerable code path.
const SECRET = "demo-notifications-secret";
const LOG = process.env.ACCESS_LOG || path.join(__dirname, "..", "logs", "access.log");

const OFFERS = [
  { id: 1, title: "Travel cashback", body: "2% back on travel this month." },
  { id: 2, title: "New savings rate", body: "Savings now at 1.8% p.a." },
  { id: 3, title: "Card upgrade", body: "You are eligible for the metal card." },
];

function accessLog(req, status) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "-").split(",")[0].trim();
  const line = `${new Date().toISOString()} ${ip} - "${req.method} ${req.originalUrl} HTTP/1.1" ${status}\n`;
  fs.appendFile(LOG, line, () => {});
}

function createApp() {
  const express = require("express");
  const app = express();
  app.use(express.json());

  app.use((req, res, next) => {
    res.on("finish", () => accessLog(req, res.statusCode));
    next();
  });

  app.get("/health", (req, res) => res.json({ status: "ok" }));

  // lodash is imported and called, on constant demo data only
  app.get("/offers", (req, res) => {
    res.json({ offers: _.sortBy(OFFERS, ["id"]), count: _.size(OFFERS) });
  });

  // jsonwebtoken is imported and called; the token is signed over a constant payload
  app.get("/token", (req, res) => {
    const token = jwt.sign({ sub: "demo", scope: "offers:read" }, SECRET, { expiresIn: "5m" });
    res.json({ token });
  });

  app.get("/verify", (req, res) => {
    try {
      const decoded = jwt.verify(jwt.sign({ sub: "demo" }, SECRET), SECRET);
      res.json({ valid: true, sub: decoded.sub });
    } catch (e) {
      res.status(401).json({ valid: false });
    }
  });

  return app;
}

module.exports = { createApp };
