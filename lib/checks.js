// ============================================================
//  checks.js - core logic (ported from the PowerShell script)
//  Performs DNS, RDAP and SSL checks for a single domain.
//  All network work happens here, server-side.
// ============================================================

const dns = require("dns").promises;
const tls = require("tls");
const https = require("https");

// --- basic domain validation (defence against abuse/injection) ---
// Only allow plausible hostnames: letters, digits, hyphens and dots.
function isValidDomain(d) {
  if (typeof d !== "string") return false;
  if (d.length > 253) return false;
  return /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(d);
}

// --- pick the RDAP URL for a TLD (.ch/.li via SWITCH, rest via rdap.org) ---
function rdapUrl(domain) {
  const tld = domain.split(".").pop().toLowerCase();
  if (tld === "ch" || tld === "li") return `https://rdap.nic.ch/domain/${domain}`;
  return `https://rdap.org/domain/${domain}`;
}

// --- small helper: resolve a record type, return [] on error ---
async function safeResolve(name, type) {
  try {
    return await dns.resolve(name, type);
  } catch {
    return [];
  }
}

// --- fetch JSON over https with a timeout (for RDAP) ---
function fetchJson(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { Accept: "application/rdap+json" } }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error("HTTP " + res.statusCode));
      }
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
  });
}

// --- read the SSL certificate expiry via a direct TLS connection ---
function getSslInfo(domain, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (val) => { if (!settled) { settled = true; resolve(val); } };
    try {
      const socket = tls.connect(
        { host: domain, port: 443, servername: domain, rejectUnauthorized: false, timeout: timeoutMs },
        () => {
          const cert = socket.getPeerCertificate();
          if (cert && cert.valid_to) {
            const expiry = new Date(cert.valid_to);
            const days = Math.round((expiry - new Date()) / 86400000);
            const dd = String(expiry.getDate()).padStart(2, "0");
            const mm = String(expiry.getMonth() + 1).padStart(2, "0");
            const yyyy = expiry.getFullYear();
            done({ info: `valid until ${dd}.${mm}.${yyyy} (${days} days)`, days });
          } else {
            done({ info: "not determinable", days: null });
          }
          socket.end();
        }
      );
      socket.on("error", () => done({ info: "not determinable", days: null }));
      socket.on("timeout", () => { socket.destroy(); done({ info: "not determinable", days: null }); });
    } catch {
      done({ info: "not determinable", days: null });
    }
  });
}

// --- check HTTP(S) availability ---
function getHttpStatus(domain, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const req = https.get(`https://${domain}`, (res) => {
      resolve(`OK (HTTP ${res.statusCode})`);
      res.resume();
    });
    req.on("error", () => resolve("error / not reachable"));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve("error / not reachable"); });
  });
}

// --- main: gather all data for one domain ---
async function checkDomain(domain) {
  const d = domain.toLowerCase().trim();

  // DNS records
  const [ns, a, aaaa, mxRaw, txtRaw, soaRaw] = await Promise.all([
    safeResolve(d, "NS"),
    safeResolve(d, "A"),
    safeResolve(d, "AAAA"),
    safeResolve(d, "MX"),
    safeResolve(d, "TXT"),
    safeResolve(d, "SOA"),
  ]);
  const txt = txtRaw.map((r) => (Array.isArray(r) ? r.join("") : r));

  // Wildcard test first (needed for DKIM)
  const rand = "zzz" + Math.floor(Math.random() * 1e9);
  const wild = await safeResolve(`${rand}.${d}`, "A");
  const hasWildcard = wild.length > 0;

  // SPF
  const spf = txt.find((t) => t.toLowerCase().startsWith("v=spf1"));
  const hasSPF = !!spf;
  let spfQuality = "-";
  if (hasSPF) {
    if (spf.includes("-all")) spfQuality = "strict (-all)";
    else if (spf.includes("~all")) spfQuality = "soft (~all)";
    else spfQuality = "open (?all)";
  }

  // DMARC
  const dmarcTxtRaw = await safeResolve(`_dmarc.${d}`, "TXT");
  const dmarcTxt = dmarcTxtRaw.map((r) => (Array.isArray(r) ? r.join("") : r));
  const dmarc = dmarcTxt.find((t) => t.toLowerCase().startsWith("v=dmarc1"));
  const hasDMARC = !!dmarc;
  let dmarcPolicy = "-";
  if (hasDMARC) {
    if (dmarc.includes("p=reject")) dmarcPolicy = "reject (strong protection)";
    else if (dmarc.includes("p=quarantine")) dmarcPolicy = "quarantine (medium)";
    else if (dmarc.includes("p=none")) dmarcPolicy = "none (monitoring only)";
  }

  // DKIM: try common selectors (CNAME or TXT)
  const selectors = ["selector1", "selector2", "google", "k1", "default", "mail", "dkim", "s1", "s2", "mandrill"];
  const dkimFound = [];
  await Promise.all(
    selectors.map(async (sel) => {
      const name = `${sel}._domainkey.${d}`;
      const c = await safeResolve(name, "CNAME");
      const t = c.length ? c : await safeResolve(name, "TXT");
      if (t.length) dkimFound.push(sel);
    })
  );
  let dkimState;
  if (dkimFound.length) dkimState = "found";
  else if (hasWildcard) dkimState = "unknown";
  else dkimState = "none";

  // Autodiscover
  const autoRaw = await safeResolve(`autodiscover.${d}`, "CNAME");
  const autodiscover = autoRaw.length ? autoRaw[0] : null;

  // Website + SSL (parallel)
  const [httpStatus, ssl] = await Promise.all([getHttpStatus(d), getSslInfo(d)]);

  // Mail provider
  const mx = mxRaw.map((r) => ({ exchange: r.exchange, priority: r.priority }))
                  .sort((x, y) => x.priority - y.priority);
  let mailProvider = "unknown";
  if (mx.length) {
    const first = mx[0].exchange.toLowerCase();
    if (first.includes("outlook.com")) mailProvider = "Microsoft 365";
    else if (first.includes("google")) mailProvider = "Google Workspace";
    else mailProvider = mx[0].exchange;
  }

  // RDAP
  const rdap = {
    registrar: "not determinable", status: "-",
    created: "-", expires: "-", updated: "-", dnssec: "-",
  };
  try {
    const j = await fetchJson(rdapUrl(d));
    const reg = (j.entities || []).find((e) => (e.roles || []).includes("registrar"));
    if (reg && Array.isArray(reg.vcardArray) && reg.vcardArray[1]) {
      const fn = reg.vcardArray[1].find((f) => f[0] === "fn");
      if (fn) rdap.registrar = fn[3];
    }
    if (j.status) rdap.status = j.status.join(", ");
    const fmt = (s) => {
      const dt = new Date(s);
      return `${String(dt.getDate()).padStart(2, "0")}.${String(dt.getMonth() + 1).padStart(2, "0")}.${dt.getFullYear()}`;
    };
    for (const e of j.events || []) {
      if (e.eventAction === "registration") rdap.created = fmt(e.eventDate);
      else if (e.eventAction === "expiration") rdap.expires = fmt(e.eventDate);
      else if (e.eventAction === "last changed") rdap.updated = fmt(e.eventDate);
    }
    if (j.secureDNS && j.secureDNS.delegationSigned === true) rdap.dnssec = "active (signed)";
    else if (j.secureDNS && j.secureDNS.delegationSigned === false) rdap.dnssec = "not active";
  } catch {
    rdap.registrar = "RDAP not reachable";
  }

  // Score
  const tips = [];
  let score = 0;
  const max = 5;
  if (hasSPF) score++; else tips.push("Set up an SPF record (protection against email spoofing).");
  if (hasDMARC) score++; else tips.push("Set up DMARC (at least p=quarantine recommended).");
  if (dkimState === "found") score++;
  else if (dkimState === "unknown") tips.push("DKIM not clearly verifiable (wildcard active) - verify manually.");
  else tips.push("Enable DKIM (email signing).");
  if (rdap.dnssec.startsWith("active")) score++; else tips.push("Enable DNSSEC (protection against DNS manipulation).");
  if (!hasWildcard) score++; else tips.push("Review wildcard DNS (catches all subdomains).");
  if (hasSPF && spfQuality.startsWith("soft")) tips.push("Tighten SPF from ~all to -all.");
  if (hasDMARC && dmarcPolicy.startsWith("none")) tips.push("Raise DMARC policy from p=none to p=quarantine/reject.");
  if (ssl.days !== null && ssl.days < 30) tips.push("SSL certificate expires in under 30 days - renew it!");

  return {
    domain: d,
    ns, a, aaaa, mx, txt, soa: soaRaw[0] || null,
    hasWildcard,
    spf: spf || null, hasSPF, spfQuality,
    dmarc: dmarc || null, hasDMARC, dmarcPolicy,
    dkimState, dkimFound,
    autodiscover, httpStatus, sslInfo: ssl.info, sslDays: ssl.days,
    mailProvider, rdap,
    score, max, tips,
  };
}

module.exports = { checkDomain, isValidDomain };
