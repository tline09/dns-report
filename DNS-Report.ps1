<#
.SYNOPSIS
    Generates a DNS, email and WHOIS report as an HTML file for one or more
    domains. A lightweight tool for quick domain and security checks.

.DESCRIPTION
    For each given domain, the script queries the following information and
    combines it into a formatted HTML report (printable as PDF):

      - DNS records: NS, A, AAAA, MX, TXT, SOA
      - Email security: SPF (incl. quality), DMARC (incl. policy), DKIM
      - Website: HTTP availability and SSL certificate (expiry date)
      - WHOIS/RDAP: registrar, registration/expiry date, status, DNSSEC
      - An overall score per domain plus concrete recommendations

    Only publicly available DNS and RDAP data is used. For .ch domains the
    registry (SWITCH) does not disclose holder names or addresses anonymously
    for data-protection reasons.

.PARAMETER Domain
    One or more domains to check. Separate multiple domains with commas
    (no spaces). If omitted, the default domain defined in the script is used.

.PARAMETER Open
    If set, the finished HTML report is opened automatically in the default
    browser. Without this switch it is only saved.

.PARAMETER DnsServer
    DNS server used for all queries. Default is the public resolver 1.1.1.1
    (Cloudflare) so that inside a corporate network the PUBLIC view of a domain
    is checked and not the internal AD zone (split DNS). For internal company
    domains (.local) specify an internal DNS server, or "" (empty) for the
    system default.

.EXAMPLE
    .\DNS-Report.ps1
    Checks the default domain defined in the script and saves the report.

.EXAMPLE
    .\DNS-Report.ps1 -Domain example.ch -Open
    Checks a single domain and opens the report directly in the browser.

.EXAMPLE
    .\DNS-Report.ps1 -Domain "example.ch","example.com","example.org"
    Checks multiple domains and writes them into a single combined report.

.EXAMPLE
    .\DNS-Report.ps1 -Domain internal.company.local -DnsServer 10.45.25.5
    Uses an internal DNS server (e.g. for company-internal zones).

.NOTES
    Author  : YOUR-GITHUB-NAME
    Purpose : Helper tool; have results reviewed by a specialist.
    Tech    : RDAP instead of classic WHOIS (returns JSON, no extra tool needed).
#>

param(
    [string[]] $Domain    = @("example.ch"),       # Domain(s) to check
    [switch]   $Open,                               # Open report after creation?
    [string]   $DnsServer = "1.1.1.1"               # DNS server (empty = system default)
)

# ---- Settings (adjust as needed) -------------------------------
$Company     = "Your Company"   # Company name in the report header
$ColorDark   = "#1f3a5f"        # Primary color (header, headings)
$ColorAccent = "#c8a24b"        # Accent color (lines, button, score)
# $LogoUrl   = "https://..."    # Optional: logo URL for the header
# ----------------------------------------------------------------


# Builds the shared parameters for Resolve-DnsName. If a DnsServer is set,
# -Server is added - so ALL queries use the same resolver (important against
# split DNS in corporate networks). Applied everywhere via splatting (@dnsParams).
$script:dnsParams = @{ ErrorAction = "SilentlyContinue" }
if ($DnsServer -and $DnsServer.Trim() -ne "") {
    $script:dnsParams["Server"] = $DnsServer
}

# Queries a DNS record and filters for exactly the requested type. For some
# queries Resolve-DnsName also returns companion records (e.g. SOA on a failed
# A lookup) - the Where-Object filter ensures we only get the requested type.
function Resolve-Safe($name, $type) {
    Resolve-DnsName -Name $name -Type $type @script:dnsParams | Where-Object Type -eq $type
}

# Returns the matching RDAP server URL for the domain TLD. .ch/.li go directly
# via SWITCH; everything else via the IANA bootstrap rdap.org, which forwards
# the request to the correct registry server. This makes the WHOIS part work
# for any TLD.
function Get-RdapUrl($domain) {
    $tld = ($domain -split '\.')[-1].ToLower()
    switch ($tld) {
        "ch"  { return "https://rdap.nic.ch/domain/$domain" }
        "li"  { return "https://rdap.nic.ch/domain/$domain" }
        default {
            # generic IANA bootstrap via rdap.org (forwards to the correct server)
            return "https://rdap.org/domain/$domain"
        }
    }
}

# Collects ALL check data for a single domain and returns it as an ordered
# hashtable. One call per domain. Contains DNS records, email security,
# website/SSL status and the WHOIS/RDAP data.
function Get-DomainData($d) {
    $data = [ordered]@{}

    # --- DNS ---
    $data.ns    = Resolve-Safe $d "NS"
    $data.a     = Resolve-Safe $d "A"
    $data.aaaa  = Resolve-Safe $d "AAAA"
    $data.mx    = Resolve-Safe $d "MX"
    $data.txt   = Resolve-Safe $d "TXT"
    $data.soa   = Resolve-Safe $d "SOA"
    $dmarc      = Resolve-Safe "_dmarc.$d" "TXT"
    $data.auto  = Resolve-DnsName -Name "autodiscover.$d" -Type CNAME @script:dnsParams

    # Run the wildcard test first because the DKIM check needs the result.
    # We query a guaranteed non-existent random subdomain: if an IP still comes
    # back, a wildcard record (*.domain) exists that answers ANY subdomain -
    # in that case subdomain checks are unreliable.
    $rand = "zzz$(Get-Random)"
    $data.hasWildcard = [bool](Resolve-DnsName -Name "$rand.$d" -Type A @script:dnsParams | Where-Object Type -eq A)

    # --- SPF (protection against sender spoofing) ---
    # SPF is a TXT record starting with "v=spf1". The suffix defines strictness:
    # -all = hard (reject spoofed mail), ~all = soft (mark only), ?all = neutral.
    $data.spf     = $data.txt | Where-Object { ($_.Strings -join '') -like "v=spf1*" }
    $data.hasSPF  = [bool]$data.spf
    $data.spfQuality = "-"
    if ($data.hasSPF) {
        $spfVal = ($data.spf.Strings -join ' ')
        if     ($spfVal -like "*-all*") { $data.spfQuality = "streng (-all)" }
        elseif ($spfVal -like "*~all*") { $data.spfQuality = "weich (~all)" }
        else                            { $data.spfQuality = "offen (?all)" }
    }

    # --- DMARC (defines what happens to spoofed mail) ---
    # A TXT record under _dmarc.<domain>. The "p=" policy is key:
    # reject = reject (best protection), quarantine = to spam, none = monitor only.
    $dmarcRec      = $dmarc | Where-Object { ($_.Strings -join '') -like "v=DMARC1*" }
    $data.hasDMARC = [bool]$dmarcRec
    $data.dmarcPolicy = "-"
    if ($data.hasDMARC) {
        $dmarcVal = ($dmarcRec | Select-Object -First 1).Strings -join ' '
        if     ($dmarcVal -like "*p=reject*")     { $data.dmarcPolicy = "reject (starker Schutz)" }
        elseif ($dmarcVal -like "*p=quarantine*") { $data.dmarcPolicy = "quarantine (mittel)" }
        elseif ($dmarcVal -like "*p=none*")       { $data.dmarcPolicy = "none (nur Beobachtung)" }
    }

    # --- DKIM (email signing) ---
    # DKIM keys live under <selector>._domainkey.<domain>. The problem: the
    # selector name is chosen by each mail provider - there is no DNS way to
    # list all existing ones. So we can only try a list of common selectors
    # (M365, Google, Mailchimp, etc.). That is why the result is deliberately
    # THREE-VALUED instead of just yes/no:
    #   found   = at least one known selector found -> DKIM definitely active
    #   unknown = nothing found BUT wildcard active  -> no reliable statement
    #   none    = nothing found, no wildcard         -> probably no DKIM
    # This avoids a false "DKIM missing" for uncommon selectors.
    $dkimSelectors = @("selector1","selector2","google","k1","default","mail","dkim","s1","s2","mandrill")
    $dkimFound = @()
    foreach ($sel in $dkimSelectors) {
        # DKIM records are usually CNAME (M365) or TXT - check both.
        $hit = Resolve-DnsName -Name "$sel._domainkey.$d" -Type CNAME @script:dnsParams
        if (-not $hit) { $hit = Resolve-DnsName -Name "$sel._domainkey.$d" -Type TXT @script:dnsParams }
        if ($hit) { $dkimFound += $sel }
    }
    $data.dkimFound = $dkimFound
    if ($dkimFound.Count -gt 0) {
        $data.dkimState = "found"
    } elseif ($data.hasWildcard) {
        $data.dkimState = "unknown"
    } else {
        $data.dkimState = "none"
    }
    $data.hasDKIM = ($data.dkimState -eq "found")

    # --- Website availability ---
    # Requests the home page via HTTPS. Keep the timeout short so the script
    # does not hang on dead domains. Errors (timeout, DNS, 5xx) go to catch.
    $data.httpStatus = "not reachable"
    try {
        $resp = Invoke-WebRequest "https://$d" -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 5
        $data.httpStatus = "OK (HTTP $($resp.StatusCode))"
    } catch { $data.httpStatus = "error / not reachable" }

    # --- SSL certificate ---
    # We open a direct TLS connection on port 443 and read the certificate.
    # Important: the validation callback ({ $true }) is passed ONLY to this one
    # SslStream, not set globally. This lets us read the expiry date even from
    # expired/invalid certificates without disabling certificate validation
    # for the whole process.
    $data.sslInfo = "not determinable"
    $data.sslDays = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($d, 443)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ([System.Net.Security.RemoteCertificateValidationCallback]{ $true }))
        $ssl.AuthenticateAsClient($d)
        $cert = $ssl.RemoteCertificate
        $expiry = [datetime]::Parse($cert.GetExpirationDateString())
        $data.sslDays = ($expiry - (Get-Date)).Days     # days left until expiry
        $data.sslInfo = "valid until $($expiry.ToString('dd.MM.yyyy')) ($($data.sslDays) days)"
        $ssl.Close(); $tcp.Close()
    } catch { $data.sslInfo = "not determinable" }

    # --- Detect mail provider ---
    # Name the provider based on the MX target (purely cosmetic for the report).
    $data.mailProvider = "unknown"
    if ($data.mx) {
        $mxName = ($data.mx | Select-Object -First 1).NameExchange
        if     ($mxName -like "*outlook.com*") { $data.mailProvider = "Microsoft 365" }
        elseif ($mxName -like "*google*")      { $data.mailProvider = "Google Workspace" }
        else                                   { $data.mailProvider = $mxName }
    }

    # --- WHOIS / RDAP (domain registration data) ---
    # RDAP is the modern WHOIS successor and returns JSON. Initialize all fields
    # with "-" so the report is not empty when data is missing or the server is
    # unreachable.
    $data.rdapRegistrar = "not determinable"
    $data.rdapStatus = "-"; $data.rdapCreated = "-"; $data.rdapExpires = "-"
    $data.rdapUpdated = "-"; $data.rdapDnssec = "-"
    try {
        $url = Get-RdapUrl $d
        $rdap = Invoke-RestMethod $url -Headers @{ "Accept" = "application/rdap+json" } -TimeoutSec 15

        # Registrar: stored in RDAP as an "entity" with the role "registrar".
        # The name is in vCard format: vcardArray[1] is an array of fields, each
        # field itself an array [name, params, type, value]. We look for the
        # "fn" (full name) field and take its value [3].
        $reg = $rdap.entities | Where-Object { $_.roles -contains "registrar" } | Select-Object -First 1
        if ($reg) {
            $fn = $reg.vcardArray[1] | Where-Object { $_[0] -eq "fn" }
            if ($fn) { $data.rdapRegistrar = $fn[3] }
        }

        # Join status (e.g. "active", "clientTransferProhibited") into text.
        if ($rdap.status) { $data.rdapStatus = ($rdap.status -join ", ") }

        # Timestamps are "events" with an eventAction. Pick the relevant ones
        # and convert to day.month.year format.
        foreach ($e in $rdap.events) {
            switch ($e.eventAction) {
                "registration" { $data.rdapCreated = ([datetime]$e.eventDate).ToString('dd.MM.yyyy') }
                "expiration"   { $data.rdapExpires = ([datetime]$e.eventDate).ToString('dd.MM.yyyy') }
                "last changed" { $data.rdapUpdated = ([datetime]$e.eventDate).ToString('dd.MM.yyyy') }
            }
        }

        # DNSSEC status: delegationSigned = is the zone cryptographically signed?
        if     ($rdap.secureDNS.delegationSigned -eq $true)  { $data.rdapDnssec = "active (signed)" }
        elseif ($rdap.secureDNS.delegationSigned -eq $false) { $data.rdapDnssec = "not active" }
    } catch {
        $data.rdapRegistrar = "RDAP not reachable"
    }

    return $data
}

# ---- Scoring ----------------------------------------------------
# Awards one point per fulfilled security criterion (max. 5) and collects
# matching recommendations for everything missing or improvable.
# The 5 points: SPF, DMARC, DKIM, DNSSEC, no wildcard.
# Extra tips (no scoring): soft SPF, DMARC p=none, SSL expiring soon.
function Get-Score($data) {
    $score = 0; $max = 5; $tips = @()
    if ($data.hasSPF)   { $score++ } else { $tips += "Set up an SPF record (protection against email spoofing)." }
    if ($data.hasDMARC) { $score++ } else { $tips += "Set up DMARC (at least p=quarantine recommended)." }
    # DKIM three-valued: only "found" scores a point; "unknown" is reported
    # honestly as not verifiable instead of wrongly counted as a failure.
    if ($data.dkimState -eq "found") { $score++ }
    elseif ($data.dkimState -eq "unknown") { $tips += "DKIM not clearly verifiable (wildcard active) - verify manually." }
    else { $tips += "Enable DKIM (email signing)." }
    if ($data.rdapDnssec -like "aktiv*") { $score++ } else { $tips += "Enable DNSSEC (protection against DNS manipulation)." }
    if (-not $data.hasWildcard) { $score++ } else { $tips += "Review wildcard DNS (catches all subdomains)." }

    # Extra recommendations without scoring (fine-tuning hints):
    if ($data.hasSPF -and $data.spfQuality -like "weich*") { $tips += "Tighten SPF from ~all to -all." }
    if ($data.hasDMARC -and $data.dmarcPolicy -like "none*") { $tips += "Raise DMARC policy from p=none to p=quarantine/reject." }
    if ($data.sslDays -ne $null -and $data.sslDays -lt 30) { $tips += "SSL certificate expires in under 30 days - renew it!" }

    return @{ Score = $score; Max = $max; Tips = $tips }
}

# Picks the traffic-light color for the score box: green only at full score,
# orange from half, otherwise red.
function Get-ScoreColor($s, $m) {
    if ($s -eq $m)       { return "#1a7f37" }   # green  = all fulfilled
    if ($s -ge ($m / 2)) { return "#b06f00" }   # orange = at least half
    return "#c0392b"                             # red    = much open
}

# Escape HTML special characters (prevents broken layout on < > &).
# Applied to all dynamic values coming from DNS/RDAP.
function Enc($t) {
    if ($null -eq $t) { return "" }
    return ([string]$t).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
}

# ---- HTML for one domain ----------------------------------------
# Builds the complete HTML block for ONE domain (score header, assessment,
# recommendations, all record tables). Called once per domain; the returns
# are concatenated later.
function Get-DomainHtml($d, $data) {
    $sc = Get-Score $data
    $scoreColor = Get-ScoreColor $sc.Score $sc.Max

    # Small helper for the green/red badges in the overview.
    function Badge($ok, $textOk, $textNo) {
        if ($ok) { "<span class='ok'>OK - $textOk</span>" } else { "<span class='no'>MISSING - $textNo</span>" }
    }

    # Build the recommendation list - or a success note if nothing is open.
    $tipsHtml = ""
    if ($sc.Tips.Count -gt 0) {
        $tipsHtml = "<ul class='tips'>" + (($sc.Tips | ForEach-Object { "<li>$(Enc $_)</li>" }) -join "") + "</ul>"
    } else {
        $tipsHtml = "<p class='allok'>No open recommendations - excellent!</p>"
    }

    # Prepare table rows per record type. All values secured via Enc().
    $nsRows = if ($data.ns) { ($data.ns | ForEach-Object { "<tr><td colspan='2'>$(Enc $_.NameHost)</td></tr>" }) -join "" } else { "<tr><td class='muted'>no record</td></tr>" }
    $aRows  = if ($data.a)  { ($data.a  | ForEach-Object { "<tr><td colspan='2'>$(Enc $_.IPAddress) <span class='pill'>IPv4</span></td></tr>" }) -join "" } else { "<tr><td class='muted'>no A record</td></tr>" }
    $aaaaRows = if ($data.aaaa) { ($data.aaaa | ForEach-Object { "<tr><td colspan='2'>$(Enc $_.IPAddress) <span class='pill'>IPv6</span></td></tr>" }) -join "" } else { "" }
    $mxRows = if ($data.mx) { ($data.mx | ForEach-Object { "<tr><td colspan='2'>$(Enc $_.NameExchange) <span class='pill'>Prio $($_.Preference)</span></td></tr>" }) -join "" } else { "<tr><td class='muted'>no MX record</td></tr>" }
    $soaRows = if ($data.soa) { $s = $data.soa | Select-Object -First 1; "<tr><td>Primary name server</td><td>$(Enc $s.PrimaryServer)</td></tr><tr><td>Administrator</td><td>$(Enc $s.NameAdministrator)</td></tr><tr><td>Version (serial)</td><td>$(Enc $s.SerialNumber)</td></tr>" } else { "<tr><td class='muted'>no SOA</td></tr>" }

    $spfCell   = if ($data.hasSPF) { (Enc ($data.spf.Strings -join ' ')) + " &nbsp;<span class='pill'>$($data.spfQuality)</span>" } else { "<span class='muted'>not set</span>" }
    $dmarcCell = if ($data.hasDMARC) { "<span class='pill'>$($data.dmarcPolicy)</span>" } else { "<span class='muted'>not set - empfohlen!</span>" }
    $dkimCell  = switch ($data.dkimState) {
        "found"   { "active (selectors: " + (($data.dkimFound | ForEach-Object { Enc $_ }) -join ", ") + ")" }
        "unknown" { "<span class='muted'>not clearly verifiable (wildcard active)</span>" }
        default   { "<span class='muted'>no common selectors found</span>" }
    }
    $autoCell  = if ($data.auto) { Enc ($data.auto | Select-Object -First 1).NameHost } else { "<span class='muted'>not set</span>" }

@"
  <section class='domain'>
  <div class='card domainhead'>
    <div>
      <h2 class='dname'>$(Enc $d)</h2>
      <span class='provider'>$(Enc $data.mailProvider)</span>
    </div>
    <div class='scorebox' style='background:$scoreColor'>
      $($sc.Score) / $($sc.Max)
      <small>points</small>
    </div>
  </div>

  <div class='card'>
    <h3>At a glance</h3>
    <div class='summary'>
      $(Badge $data.hasSPF   "SPF"   "SPF")
      $(Badge $data.hasDMARC "DMARC" "DMARC")
      $(switch ($data.dkimState) {
          "found"   { "<span class='ok'>OK - DKIM</span>" }
          "unknown" { "<span class='warn'>DKIM unclear</span>" }
          default   { "<span class='no'>MISSING - DKIM</span>" }
        })
      $(if ($data.rdapDnssec -like "aktiv*") { "<span class='ok'>DNSSEC</span>" } else { "<span class='warn'>DNSSEC</span>" })
      $(if ($data.hasWildcard) { "<span class='warn'>Wildcard active</span>" } else { "<span class='ok'>no wildcard</span>" })
    </div>
    <h3 style='margin-top:16px'>Recommendations</h3>
    $tipsHtml
  </div>

  <div class='card'>
    <h3>Domain registration (WHOIS / RDAP)</h3>
    <p class='sub'>Holder details for .ch only visible with login (data protection)</p>
    <table>
      <tr><td>Registrar</td><td><b>$(Enc $data.rdapRegistrar)</b></td></tr>
      <tr><td>Registered on</td><td>$($data.rdapCreated)</td></tr>
      <tr><td>Expires on</td><td>$($data.rdapExpires)</td></tr>
      <tr><td>Last changed</td><td>$($data.rdapUpdated)</td></tr>
      <tr><td>Status</td><td>$(Enc $data.rdapStatus)</td></tr>
      <tr><td>DNSSEC</td><td>$($data.rdapDnssec)</td></tr>
    </table>
  </div>

  <div class='card'>
    <h3>Name servers</h3>
    <table>$nsRows</table>
  </div>

  <div class='card'>
    <h3>Website</h3>
    <table>
      $aRows
      $aaaaRows
      <tr><td>Status</td><td><b>$($data.httpStatus)</b></td></tr>
      <tr><td>SSL certificate</td><td><b>$($data.sslInfo)</b></td></tr>
    </table>
  </div>

  <div class='card'>
    <h3>Mail server</h3>
    <table>$mxRows</table>
  </div>

  <div class='card'>
    <h3>Email security</h3>
    <table>
      <tr><td>SPF</td><td>$spfCell</td></tr>
      <tr><td>DMARC</td><td>$dmarcCell</td></tr>
      <tr><td>DKIM</td><td>$dkimCell</td></tr>
      <tr><td>Autodiscover</td><td>$autoCell</td></tr>
    </table>
  </div>

  <div class='card'>
    <h3>Zone administration (SOA)</h3>
    <table>$soaRows</table>
  </div>
  </section>
"@
}

# ================================================================
#  MAIN
#  Check each domain in turn, collect HTML blocks, build the full
#  document and save it as a file.
# ================================================================
$domainSections = ""
$total = $Domain.Count
$i = 0
foreach ($d in $Domain) {
    $i++
    Write-Host "[$i/$total] Checking $d ..." -ForegroundColor Cyan  # progress
    $data = Get-DomainData $d                  # collect all data
    $domainSections += Get-DomainHtml $d $data  # append HTML block
}

# Build the file name: the domain name for one domain, a collective name for
# several. The date in the name keeps older reports from being overwritten.
$datum     = Get-Date -Format 'dd.MM.yyyy HH:mm'
$dateiTag  = Get-Date -Format 'yyyy-MM-dd'
$domainTag = if ($Domain.Count -eq 1) { $Domain[0] } else { "combined_$($Domain.Count)-domains" }
$OutFile   = "$PSScriptRoot\DNS-Report_${domainTag}_$dateiTag.html"

# Optional logo (only if $LogoUrl is set/uncommented above).
$logoHtml = ""
# if ($LogoUrl) { $logoHtml = "<img src='$LogoUrl' class='logo'>" }

# For the header: which DNS server was used? (transparency in the report)
$dnsServerInfo = if ($DnsServer -and $DnsServer.Trim() -ne "") { Enc $DnsServer } else { "system default" }

$html = @"
<!DOCTYPE html>
<html lang='de'>
<head>
<meta charset='UTF-8'>
<title>DNS-Report</title>
<style>
  * { box-sizing:border-box; }
  body { font-family:'Segoe UI',Arial,sans-serif; background:#f4f6f8; color:#1f2933; margin:0; padding:40px; }
  .wrap { max-width:840px; margin:0 auto; }
  header { background:$ColorDark; color:#fff; padding:26px 32px; border-radius:12px; display:flex; align-items:center; justify-content:space-between; margin-bottom:22px; }
  header h1 { margin:0; font-size:21px; letter-spacing:.5px; }
  header .meta { font-size:13px; opacity:.85; margin-top:4px; }
  header .firma { font-size:13px; font-weight:600; color:$ColorAccent; letter-spacing:1px; text-transform:uppercase; }
  .logo { height:40px; }
  section.domain { margin-bottom:34px; }
  .card { background:#fff; padding:20px 26px; border-bottom:1px solid #eceff1; }
  .card:first-of-type { border-radius:12px 12px 0 0; }
  .card:last-of-type { border-radius:0 0 12px 12px; border-bottom:none; }
  .domainhead { display:flex; align-items:center; justify-content:space-between; background:#fbfcfd; border-top:3px solid $ColorAccent; }
  .dname { margin:0; font-size:20px; color:$ColorDark; }
  .provider { font-size:12px; color:#7b8794; }
  .scorebox { color:#fff; padding:10px 16px; border-radius:10px; font-size:20px; font-weight:700; text-align:center; line-height:1.1; }
  .scorebox small { display:block; font-size:10px; font-weight:400; opacity:.85; }
  h2,h3 { color:$ColorDark; }
  h3 { font-size:13px; text-transform:uppercase; letter-spacing:1px; margin:0 0 10px; }
  .sub { font-size:12px; color:#7b8794; margin:0 0 12px; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  td { padding:6px 8px; border-bottom:1px solid #f0f2f4; }
  td:first-child { color:#52606d; width:180px; }
  .muted { color:#9aa5b1; font-style:italic; }
  .summary { display:flex; flex-wrap:wrap; gap:8px; }
  .summary span { padding:5px 12px; border-radius:20px; font-size:12px; font-weight:600; }
  .ok { background:#e3f6e8; color:#1a7f37; }
  .no { background:#fdeaea; color:#c0392b; }
  .warn { background:#fff4e0; color:#b06f00; }
  .pill { display:inline-block; background:#eef2f7; color:$ColorDark; padding:2px 10px; border-radius:12px; font-size:12px; }
  .tips { margin:0; padding-left:18px; font-size:13px; color:#52606d; }
  .tips li { margin:4px 0; }
  .allok { color:#1a7f37; font-size:13px; margin:0; }
  footer { text-align:center; font-size:12px; color:#9aa5b1; margin-top:10px; }
  @media print {
    @page { margin: 1cm; }
    body { background:#fff; padding:0; font-size:10pt; }
    .wrap { max-width:100%; }
    header { border-radius:0; padding:12px 18px; margin-bottom:10px;
             -webkit-print-color-adjust:exact; print-color-adjust:exact; }
    header h1 { font-size:16pt; }
    section.domain { margin-bottom:10px; }
    .card { border:1px solid #e5e9ec; padding:8px 14px; margin:0;
            page-break-inside:avoid; break-inside:avoid; }
    .card h3 { margin:0 0 6px; font-size:10pt; }
    td { padding:3px 8px; }
    .domainhead { page-break-after:avoid; break-after:avoid; }
    h2, h3 { page-break-after:avoid; break-after:avoid; }
    tr { page-break-inside:avoid; break-inside:avoid; }
    .ok, .no, .warn, .pill, .scorebox, .domainhead, .firma {
      -webkit-print-color-adjust:exact; print-color-adjust:exact; }
    .noprint { display:none !important; }
    footer { margin-top:4px; font-size:8pt; }
    .card:last-of-type { margin-bottom:0; }
  }
</style>
</head>
<body>
<div class='wrap'>
  <header>
    <div>
      <div class='firma'>$Company</div>
      <h1>DNS, Email &amp; WHOIS Report</h1>
      <div class='meta'>Created on $datum &middot; $total domain(s) checked &middot; DNS: $dnsServerInfo</div>
    </div>
    $logoHtml
    <button class='noprint' onclick='window.print()' style='background:$ColorAccent;color:#fff;border:none;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer'>Print as PDF</button>
  </header>

  $domainSections

  <footer>Automatically generated by $Company &middot; $datum</footer>
</div>
</body>
</html>
"@

# HTML als UTF-8 speichern und Pfad ausgeben.
$html | Out-File $OutFile -Encoding UTF8

Write-Host ""
Write-Host "Done! Report saved to:" -ForegroundColor Green
Write-Host "  $OutFile" -ForegroundColor Yellow

# Only open if the -Open switch was set.
if ($Open) { Start-Process $OutFile }
