# DNS-Report Web App

A small web tool with an input field: enter a domain, get a live DNS, email,
SSL and WHOIS report. The checks run **server-side** (Node.js), so the full
feature set of the PowerShell version is available – including the SSL check.

## How it works

```
Browser (input field)  ->  Node.js server  ->  DNS / RDAP / TLS queries
       ^                                                    |
       +-------------------  HTML report  <-----------------+
```

- `server.js` – Express web server + API endpoint (`/api/check`)
- `lib/checks.js` – the actual checks (DNS, RDAP, SSL, scoring)
- `lib/render.js` – builds the HTML report
- `public/index.html` – the input page

## Run locally

Requires [Node.js](https://nodejs.org/) 18 or newer.

```bash
npm install
npm start
```

Then open <http://localhost:3000> in your browser.

## Hosting

This app needs a host that runs Node.js (not a static host like GitHub Pages).
Common options:

| Host              | Notes                                                       |
|-------------------|-------------------------------------------------------------|
| **Render**        | Free tier available; connect the repo, it builds & runs.    |
| **Railway**       | Simple Node deploys; small free allowance.                  |
| **Azure App Service** | Fits a Microsoft-centric environment; has a free tier.  |
| **A VPS**         | Full control; run `npm start` behind a reverse proxy (nginx).|

Set the start command to `npm start`. The server listens on the port given by
the `PORT` environment variable (most hosts set this automatically), or 3000.

## Abuse protection

Because the tool queries arbitrary domains on request, it includes a **basic
in-memory rate limit** (20 requests per IP per minute in `server.js`). For real
public production use, put it behind a reverse proxy or a dedicated rate-limit
service, and consider adding a captcha if it will be publicly reachable.

## Security notes

- Domain input is validated against a strict pattern before any query runs.
- All output values are HTML-escaped.
- The SSL check accepts invalid/expired certificates **only to read the expiry
  date**; it does not trust them for anything else.
- No data is stored; each request is answered and forgotten.

## License

Released under the MIT License.
