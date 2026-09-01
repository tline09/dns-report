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

### Step-by-step: deploy on Render (easiest, free)

Render connects directly to a GitHub repo and runs the app for you – no server
administration needed.

1. **Put the code on GitHub.** Create a repo (e.g. `dns-report-webapp`) and
   upload all files *except* `node_modules/` (it is rebuilt automatically).
2. **Create a Render account** at <https://render.com> and sign in with GitHub.
3. In Render click **New → Web Service**.
4. **Connect your repository** (`dns-report-webapp`) and confirm access.
5. Fill in the settings:
   - **Environment:** `Node`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance Type:** Free
6. Click **Create Web Service**. Render installs the packages and starts the app.
7. After a minute you get a public URL like
   `https://dns-report-webapp.onrender.com` – that is your live tool.

Whenever you push a change to GitHub, Render redeploys automatically.

> **Note on the free tier:** free Render services "sleep" after a period of
> inactivity and take a few seconds to wake up on the next visit. For a rarely
> used internal tool that is usually fine.

### Deploy on other hosts

- **Railway** (<https://railway.app>): New Project → Deploy from GitHub repo →
  it auto-detects Node and runs `npm start`.
- **Azure App Service:** create a Web App (runtime *Node*), then deploy from
  GitHub via the Deployment Center. Fits a Microsoft-centric environment.
- **VPS:** `git clone`, `npm install`, then run `npm start` behind an nginx
  reverse proxy with HTTPS (e.g. via Let's Encrypt).

### Keep it internal (recommended)

For company use you usually do **not** want this reachable by the whole
internet. Options: restrict access at the host level (IP allowlist / access
rules), put it behind your VPN, or add a simple password. This keeps the abuse
surface small – see *Abuse protection* below.

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
