const fs = require("fs");
const path = require("path");
const { createApp } = require("./app");

const logDir = path.join(__dirname, "..", "logs");
fs.mkdirSync(logDir, { recursive: true });
const log = fs.createWriteStream(path.join(logDir, "access.log"), { flags: "a" });

const app = createApp();
app.use((req, res, next) => {
  log.write(`${new Date().toISOString()} ${req.method} ${req.originalUrl}\n`);
  next();
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`node-lodash listening on ${port}`));
