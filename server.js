// ============================================================
//  server.js - small Express web app
//  Serves the input page and an API that runs the checks.
// ============================================================

const express = require("express");
const path = require("path");
const { checkDomain, isValidDomain } = require("./lib/checks");
const { renderDomain } = require("./lib/render");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --- very simple in-memory rate limit (abuse protection) ---
// Max 20 requests per IP per minute. For real production use a
// dedicated rate-limit middleware / reverse proxy instead.
const hits = new Map();
function rateLimit(req, res, next) {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const windowMs = 60000;
  const limit = 20;
  const rec = hits.get(ip) || { count: 0, start: now };
  if (now - rec.start > windowMs) { rec.count = 0; rec.start = now; }
  rec.count++;
  hits.set(ip, rec);
  if (rec.count > limit) {
    return res.status(429).json({ error: "Too many requests. Please wait a moment." });
  }
  next();
}

// --- API: check a domain, return the rendered HTML block + raw data ---
app.post("/api/check", rateLimit, async (req, res) => {
  const domain = (req.body && req.body.domain ? String(req.body.domain) : "").trim().toLowerCase();

  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: "Please enter a valid domain (e.g. example.ch)." });
  }

  try {
    const data = await checkDomain(domain);
    const html = renderDomain(data);
    res.json({ html, data });
  } catch (err) {
    res.status(500).json({ error: "Check failed: " + err.message });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`DNS-Report web app running on http://localhost:${PORT}`);
});
