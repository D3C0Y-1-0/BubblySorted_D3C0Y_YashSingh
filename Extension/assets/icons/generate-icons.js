/**
 * generate-icons.js — Node.js script to produce PNG icon files for Hedwig Shield.
 * Run once: node generate-icons.js
 * Requires: npm install canvas  (only for this generator, not for the extension)
 *
 * If canvas is unavailable, falls back to writing minimal valid 1x1 PNG placeholders
 * so the extension loads; replace with real icons before publishing.
 */

const fs   = require("fs");
const path = require("path");

const SIZES     = [16, 32, 48, 128];
const OUT_DIR   = __dirname;

/* ── Try to use the `canvas` package ───────────────────────────────────────── */

let Canvas;
try {
  Canvas = require("canvas");
} catch (_) {
  Canvas = null;
}

if (Canvas) {
  console.log("canvas package found — generating full icons.");
  SIZES.forEach(size => generateWithCanvas(size));
} else {
  console.log("canvas package not found — writing minimal placeholder PNGs.");
  console.log("Install via: npm install canvas   then re-run this script.");
  SIZES.forEach(size => writePlaceholderPng(size));
}

/* ── Canvas-based icon generation ──────────────────────────────────────────── */

function generateWithCanvas(size) {
  const { createCanvas } = Canvas;
  const canvas = createCanvas(size, size);
  const ctx    = canvas.getContext("2d");

  drawIcon(ctx, size);

  const outPath = path.join(OUT_DIR, `icon${size}.png`);
  fs.writeFileSync(outPath, canvas.toBuffer("image/png"));
  console.log(`  wrote ${outPath}`);
}

function drawIcon(ctx, s) {
  const cx = s / 2, cy = s / 2;

  // Transparent background
  ctx.clearRect(0, 0, s, s);

  // Shield body
  ctx.beginPath();
  const sw = s * 0.76, sh = s * 0.86;
  const sx = cx - sw / 2, sy = cy - sh / 2;
  ctx.moveTo(cx, sy + sh * 0.02);
  ctx.lineTo(sx + sw * 0.95, sy + sh * 0.24);
  ctx.quadraticCurveTo(sx + sw, sy + sh * 0.72, cx, sy + sh * 0.98);
  ctx.quadraticCurveTo(sx, sy + sh * 0.72, sx + sw * 0.05, sy + sh * 0.24);
  ctx.closePath();
  ctx.fillStyle   = "#1a1612";
  ctx.fill();
  ctx.strokeStyle = "#f5bd2a";
  ctx.lineWidth   = Math.max(1, s * 0.045);
  ctx.stroke();

  if (s >= 32) {
    // Owl eyes
    const eyeR = s * 0.09;
    const eyeY = cy - s * 0.05;
    const eyeX = s * 0.135;

    [[cx - eyeX, eyeY], [cx + eyeX, eyeY]].forEach(([ex, ey]) => {
      ctx.beginPath();
      ctx.arc(ex, ey, eyeR, 0, Math.PI * 2);
      ctx.fillStyle = "#f5bd2a";
      ctx.fill();
      ctx.beginPath();
      ctx.arc(ex, ey, eyeR * 0.45, 0, Math.PI * 2);
      ctx.fillStyle = "#0d0d0d";
      ctx.fill();
    });

    // Beak
    ctx.beginPath();
    ctx.moveTo(cx, eyeY + eyeR * 1.1);
    ctx.lineTo(cx - eyeR * 0.55, eyeY + eyeR * 2.1);
    ctx.lineTo(cx + eyeR * 0.55, eyeY + eyeR * 2.1);
    ctx.closePath();
    ctx.fillStyle = "#f5bd2a";
    ctx.fill();

    // "H" lettermark at the bottom of the shield
    if (s >= 48) {
      ctx.fillStyle = "#f5bd2a";
      ctx.font      = `bold ${Math.round(s * 0.18)}px monospace`;
      ctx.textAlign    = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("H", cx, cy + s * 0.3);
    }
  } else {
    // 16 px: just "H"
    ctx.fillStyle    = "#f5bd2a";
    ctx.font         = `bold ${Math.round(s * 0.52)}px monospace`;
    ctx.textAlign    = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("H", cx, cy + s * 0.04);
  }
}

/* ── Minimal placeholder PNG (1×1 golden pixel, scaled) ────────────────────── */
// A 16×16 golden PNG hand-encoded in base64.  Not beautiful, but loadable.

function writePlaceholderPng(size) {
  // Smallest valid PNG: 1×1 RGBA pixel (#f5bd2a, fully opaque)
  // Header + IHDR + IDAT + IEND
  const PX = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI6QAAAABJRU5ErkJggg==",
    "base64"
  );
  const outPath = path.join(OUT_DIR, `icon${size}.png`);
  fs.writeFileSync(outPath, PX);
  console.log(`  wrote placeholder ${outPath}  (replace with real icon)`);
}

