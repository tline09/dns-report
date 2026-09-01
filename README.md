# DNS-Report

A PowerShell script that generates a clear **DNS, email and WHOIS report** as an
HTML file for one or more domains — ideal for quick domain and security checks.
The report can be viewed in the browser and printed to PDF with one click.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## What the report shows

- **DNS records:** NS, A, AAAA, MX, TXT, SOA
- **Email security:** SPF (incl. quality), DMARC (incl. policy), DKIM
- **Website:** HTTP availability and SSL certificate (expiry date)
- **WHOIS / RDAP:** registrar, registration and expiry date, status, DNSSEC
- **Overall score** per domain plus concrete recommendations

Only **publicly available** DNS and RDAP data is used. For `.ch` domains the
registry (SWITCH) does not disclose holder names or addresses anonymously for
data-protection reasons.

## Requirements

- Windows with **PowerShell 5.1** or later (pre-installed on Windows)
- Internet access (for RDAP and SSL queries)
- The `Resolve-DnsName` cmdlet (part of Windows)

## Usage

```powershell
# Check the default domain defined in the script
.\DNS-Report.ps1

# Check a specific domain and open the report immediately
.\DNS-Report.ps1 -Domain example.ch -Open

# Write multiple domains into one combined report
.\DNS-Report.ps1 -Domain "example.ch","example.com","example.org"

# Query via a specific DNS server (force the public view)
.\DNS-Report.ps1 -Domain example.ch -DnsServer 1.1.1.1
```

The finished HTML report is saved in the same folder as the script (file name
includes the date). In the browser it can be saved as PDF with **Ctrl + P** —
enable **"Background graphics"** in the print dialog so the colors are kept.

Help directly in PowerShell:

```powershell
Get-Help .\DNS-Report.ps1 -Full
```

## Parameters

| Parameter    | Description                                                       | Default       |
|--------------|-------------------------------------------------------------------|---------------|
| `-Domain`    | One or more domains (comma-separated, no spaces).                 | `example.ch`  |
| `-Open`      | Opens the report in the browser after it is created.             | (off)         |
| `-DnsServer` | DNS server for all queries. Empty = system default.              | `1.1.1.1`     |

## Note on corporate networks (split DNS)

In networks with their own Active Directory DNS, an internal zone may answer the
same domain differently than the public internet (e.g. missing MX records,
internal IP addresses). Therefore the script queries via the public resolver
`1.1.1.1` by default to show the **public view**. For internal zones an internal
server can be specified via `-DnsServer`.

## Execution policy

If PowerShell blocks execution, run the script once like this:

```powershell
powershell -ExecutionPolicy Bypass -File .\DNS-Report.ps1 -Domain example.ch
```

## Limitations

- The **DKIM check** tries a list of common selectors (Microsoft 365, Google,
  Mailchimp, etc.). If a domain uses an uncommon selector, DKIM may appear as
  "not found" even though it is active. With an active wildcard the report
  honestly reports this as "not clearly verifiable".
- The report is a **helper tool**; results should be reviewed by a specialist.

## Project page (GitHub Pages)

This repo contains an `index.html` as a project landing page. To publish it as a
website: in the repo under **Settings -> Pages** choose the `main` branch (folder
`/root`) as the source. The page will then be available at
`https://YOUR-GITHUB-NAME.github.io/dns-report/` and shows instructions and a
sample report.

## Repo contents

| File                  | Purpose                                     |
|-----------------------|---------------------------------------------|
| `DNS-Report.ps1`      | The main script                             |
| `index.html`          | Project landing page (for GitHub Pages)     |
| `sample-report.html`  | A sample report to view                     |
| `README.md`           | This file                                   |
| `LICENSE`             | MIT license                                 |

## License

Released under the [MIT License](LICENSE).

## Acknowledgements

- Domain registration data via [RDAP](https://about.rdap.org/) (incl. SWITCH for `.ch`/`.li`)
