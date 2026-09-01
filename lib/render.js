// ============================================================
//  render.js - builds the HTML report block for one domain
//  Mirrors the layout of the PowerShell script's output.
// ============================================================

const COLOR_DARK = "#1f3a5f";
const COLOR_ACCENT = "#c8a24b";

// Escape HTML special characters
function enc(t) {
  if (t === null || t === undefined) return "";
  return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function scoreColor(s, m) {
  if (s === m) return "#1a7f37";
  if (s >= m / 2) return "#b06f00";
  return "#c0392b";
}

// Build the report block for one domain object (from checkDomain)
function renderDomain(data) {
  const sc = scoreColor(data.score, data.max);

  const badge = (ok, textOk, textNo) =>
    ok ? `<span class='ok'>OK - ${textOk}</span>` : `<span class='no'>MISSING - ${textNo}</span>`;

  const dkimBadge =
    data.dkimState === "found" ? "<span class='ok'>OK - DKIM</span>"
    : data.dkimState === "unknown" ? "<span class='warn'>DKIM unclear</span>"
    : "<span class='no'>MISSING - DKIM</span>";

  const tipsHtml = data.tips.length
    ? "<ul class='tips'>" + data.tips.map((t) => `<li>${enc(t)}</li>`).join("") + "</ul>"
    : "<p class='allok'>No open recommendations - excellent!</p>";

  const nsRows = data.ns.length
    ? data.ns.map((r) => `<tr><td colspan='2'>${enc(r)}</td></tr>`).join("")
    : "<tr><td class='muted'>no record</td></tr>";
  const aRows = data.a.length
    ? data.a.map((r) => `<tr><td colspan='2'>${enc(r)} <span class='pill'>IPv4</span></td></tr>`).join("")
    : "<tr><td class='muted'>no A record</td></tr>";
  const aaaaRows = data.aaaa.length
    ? data.aaaa.map((r) => `<tr><td colspan='2'>${enc(r)} <span class='pill'>IPv6</span></td></tr>`).join("")
    : "";
  const mxRows = data.mx.length
    ? data.mx.map((r) => `<tr><td colspan='2'>${enc(r.exchange)} <span class='pill'>Prio ${enc(r.priority)}</span></td></tr>`).join("")
    : "<tr><td class='muted'>no MX record</td></tr>";
  const soaRows = data.soa
    ? `<tr><td>Primary name server</td><td>${enc(data.soa.nsname)}</td></tr>` +
      `<tr><td>Administrator</td><td>${enc(data.soa.hostmaster)}</td></tr>` +
      `<tr><td>Version (serial)</td><td>${enc(data.soa.serial)}</td></tr>`
    : "<tr><td class='muted'>no SOA</td></tr>";

  const spfCell = data.hasSPF
    ? `${enc(data.spf)} &nbsp;<span class='pill'>${enc(data.spfQuality)}</span>`
    : "<span class='muted'>not set</span>";
  const dmarcCell = data.hasDMARC
    ? `<span class='pill'>${enc(data.dmarcPolicy)}</span>`
    : "<span class='muted'>not set - recommended!</span>";
  const dkimCell =
    data.dkimState === "found" ? `active (selectors: ${data.dkimFound.map(enc).join(", ")})`
    : data.dkimState === "unknown" ? "<span class='muted'>not clearly verifiable (wildcard active)</span>"
    : "<span class='muted'>no common selectors found</span>";
  const autoCell = data.autodiscover ? enc(data.autodiscover) : "<span class='muted'>not set</span>";

  return `
  <section class='domain'>
  <div class='card domainhead'>
    <div>
      <h2 class='dname'>${enc(data.domain)}</h2>
      <span class='provider'>${enc(data.mailProvider)}</span>
    </div>
    <div class='scorebox' style='background:${sc}'>
      ${data.score} / ${data.max}
      <small>points</small>
    </div>
  </div>

  <div class='card'>
    <h3>At a glance</h3>
    <div class='summary'>
      ${badge(data.hasSPF, "SPF", "SPF")}
      ${badge(data.hasDMARC, "DMARC", "DMARC")}
      ${dkimBadge}
      ${data.rdap.dnssec.startsWith("active") ? "<span class='ok'>DNSSEC</span>" : "<span class='warn'>DNSSEC</span>"}
      ${data.hasWildcard ? "<span class='warn'>Wildcard active</span>" : "<span class='ok'>no wildcard</span>"}
    </div>
    <h3 style='margin-top:16px'>Recommendations</h3>
    ${tipsHtml}
  </div>

  <div class='card'>
    <h3>Domain registration (WHOIS / RDAP)</h3>
    <p class='sub'>Holder details for .ch only visible with login (data protection)</p>
    <table>
      <tr><td>Registrar</td><td><b>${enc(data.rdap.registrar)}</b></td></tr>
      <tr><td>Registered on</td><td>${enc(data.rdap.created)}</td></tr>
      <tr><td>Expires on</td><td>${enc(data.rdap.expires)}</td></tr>
      <tr><td>Last changed</td><td>${enc(data.rdap.updated)}</td></tr>
      <tr><td>Status</td><td>${enc(data.rdap.status)}</td></tr>
      <tr><td>DNSSEC</td><td>${enc(data.rdap.dnssec)}</td></tr>
    </table>
  </div>

  <div class='card'>
    <h3>Name servers</h3>
    <table>${nsRows}</table>
  </div>

  <div class='card'>
    <h3>Website</h3>
    <table>
      ${aRows}
      ${aaaaRows}
      <tr><td>Status</td><td><b>${enc(data.httpStatus)}</b></td></tr>
      <tr><td>SSL certificate</td><td><b>${enc(data.sslInfo)}</b></td></tr>
    </table>
  </div>

  <div class='card'>
    <h3>Mail server</h3>
    <table>${mxRows}</table>
  </div>

  <div class='card'>
    <h3>Email security</h3>
    <table>
      <tr><td>SPF</td><td>${spfCell}</td></tr>
      <tr><td>DMARC</td><td>${dmarcCell}</td></tr>
      <tr><td>DKIM</td><td>${dkimCell}</td></tr>
      <tr><td>Autodiscover</td><td>${autoCell}</td></tr>
    </table>
  </div>

  <div class='card'>
    <h3>Zone administration (SOA)</h3>
    <table>${soaRows}</table>
  </div>
  </section>`;
}

module.exports = { renderDomain, enc, COLOR_DARK, COLOR_ACCENT };
