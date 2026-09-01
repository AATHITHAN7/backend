# TRACE — Backend (Phishing Attack Investigation Platform)

Node.js / Express API that analyses a suspicious email's sender, domain,
links, language, and attachments, scores the risk, and produces a
shareable, auto-generated incident report. **No database** — reports are
held in an in-memory store for the lifetime of the process (configurable
TTL) and can be exported to a self-contained HTML file for permanent
retention.

## Run locally

```bash
cd backend
cp .env.example .env
npm install
npm run dev      # nodemon, auto-reload
# or
npm start
```

Server starts on `http://localhost:5000` by default.

## API

### `POST /api/analyze`
Body:
```json
{
  "senderEmail": "security@paypa1-login.com",
  "senderName": "PayPal Security",
  "replyTo": "",
  "subject": "Your account will be suspended!",
  "body": "Dear Customer, verify your account immediately...",
  "urls": [{ "href": "http://paypa1-login.com/verify", "text": "www.paypal.com/verify" }],
  "attachments": ["invoice.pdf.exe"]
}
```
`urls` items may be plain strings or `{href, text}` objects (`text` = the
displayed link text, used to detect anchor/destination mismatches).
`attachments` items may be plain strings or `{name}` objects.

Returns `201` with the full report object (score, verdict, indicators,
IOCs, recommended actions, narrative, and a report `id`).

### `GET /api/report/:id`
Fetch a previously generated report — this is what the shareable link
resolves to on the frontend.

### `GET /api/report/:id/export`
Returns a self-contained, print-ready HTML version of the report.

### `GET /api/health`
Liveness probe.

## Deploying

Works on any Node host (Render, Railway, Fly.io, a plain VM, etc.):

1. Set `CORS_ORIGIN` to your deployed frontend's URL (comma-separate
   multiple origins).
2. Set `PORT` if your host requires a specific one (most platforms inject
   this automatically).
3. `npm install && npm start`.

No database, message queue, or external service is required.
