# PhishAlert — Active Deception & Infrastructure Intelligence
### Stage 1: Capture Endpoint + Event Schema + Traffic Classification Engine

## What this is

A small Cloudflare Worker that receives hits on canary artifacts (a 1×1
pixel and a decoy link) deployed against a specific phishing email, and
classifies the interacting traffic as automated infrastructure, likely
automated, indeterminate, suspicious interaction, or likely human-driven —
each with a confidence score, never a certainty claim.

It never tries to "identify the attacker." It reports on the infrastructure
that touched the bait. That distinction is deliberate — see the header
comment in `src/index.js`.

## Why Cloudflare Workers specifically

Every incoming request already carries `request.cf` — Cloudflare's own
edge-derived ASN, organization, country, region, and city for the request's
IP, at zero cost and zero added latency. No external IP-intelligence API,
no API key to manage, no rate limits to worry about for a student project.

## Deploy (one time, by the developer — users do nothing)

Easiest: double-click **DEPLOY-CANARY.bat** in the main PhishAlert folder
(needs Node.js and a free Cloudflare account). It deploys this worker and
writes the live URL into `background.js` and `manifest.json` for you.
Then reload the extension at `chrome://extensions`.

Manual alternative:

```bash
cd canary-server
npx wrangler login
npx wrangler deploy
# copy the printed https://phishalert-canary.<you>.workers.dev URL, then:
node deploy-canary.js --url https://phishalert-canary.<you>.workers.dev
```

The two KV namespaces are already bound in `wrangler.toml`. No secret is required.

## How users get a key (automatic)

On first "Deploy Bait" the extension calls `POST /api/register`. The worker
returns a private key (`pa_...`); the extension stores it encrypted. Only the
SHA-256 hash is kept server-side. A key can only read its own canaries.
Limits: 5 registrations/IP/day, 300 registrations/day total, 20 canaries per
install per day, 50 events per canary. Canaries and events auto-delete after
30 days.

Cloudflare's free KV plan allows ~1,000 writes/day across everything. If many
people use the feature, move the account to Workers Paid ($5/month).

Optional: `wrangler secret put API_KEY` sets an owner key that can read
`GET /api/campaign/:id` (cross-user correlation).

## API

### `POST /api/register` — get a private key (public, rate-limited)

No body. Returns `{ "apiKey": "pa_..." }`.

### `GET /api/canary/ping` — check a key (auth required)

### `POST /api/canary` — deploy a new canary (auth required)

Header: `X-API-Key: <your API_KEY>`

Body:
```json
{
  "campaignId": "PH-042",
  "emailId": "hash-of-the-flagged-email",
  "senderDomain": "paypa1-security.com",
  "riskScore": 96,
  "baitType": "pixel"
}
```

Response:
```json
{
  "canaryId": "CNR-8F31A92B1C4D",
  "campaignId": "PH-042",
  "pixelUrl": "https://phishalert-canary.<you>.workers.dev/t/CNR-8F31A92B1C4D",
  "linkUrl":  "https://phishalert-canary.<you>.workers.dev/c/CNR-8F31A92B1C4D",
  "createdAtIso": "2026-09-27T14:30:00.000Z"
}
```

`pixelUrl` and `linkUrl` are what Stage 2 (extension UI) embeds into
whatever decoy artifact the user chooses to deploy. That delivery
mechanism is intentionally out of scope for this stage — the endpoint
doesn't care how the URL reaches attacker infrastructure, only what
happens when something requests it.

### `GET /t/:canaryId` — pixel (public, no auth)

Returns a 1×1 transparent GIF unconditionally, whether or not the canary
ID is recognized — the response never leaks whether an ID is valid.
Logs a `pixel` event.

### `GET /c/:canaryId` — decoy link (public, no auth)

Logs a `link` event, then either 302-redirects to `SAFE_REDIRECT_URL`
(if you set that var) or returns a bland generic 404 page. It never
forwards the visitor to the real phishing destination, and never reveals
that the link was a honeypot.

### `GET /api/canary/:canaryId/events` — telemetry for one canary (auth required)

Returns the canary's metadata plus every classified event recorded
against it, oldest first.

### `GET /api/campaign/:campaignId` — cross-canary correlation (auth required)

Returns every canary tagged with that campaign ID, their combined event
list, and an `infrastructureOverlap` block flagging any IP or ASN that
touched more than one canary in the campaign — the hook Stage 3 (Phishing
DNA correlation) builds on.

## Event schema

```json
{
  "eventId": "uuid",
  "canaryId": "CNR-8F31A92B1C4D",
  "campaignId": "PH-042",
  "baitType": "pixel",
  "timestampMs": 1758987138000,
  "timestampIso": "2026-09-27T14:32:18.000Z",
  "elapsedSeconds": 138,
  "network": {
    "ip": "203.0.113.42",
    "asn": 12345,
    "asOrganization": "Example Hosting",
    "country": "DE",
    "region": "Hesse",
    "city": "Frankfurt"
  },
  "userAgent": "Mozilla/5.0 ...",
  "classification": "suspicious_interaction",
  "confidence": 0.78,
  "signals": ["deliberate_link_click", "hosting_or_datacenter_network", "human_plausible_timing"]
}
```

## Classification labels

| Label | Meaning |
|---|---|
| `automated_infrastructure` | Strong, multi-signal evidence of a scanner, mail-security proxy, or bot |
| `likely_automated` | Behavioral indicators lean automated, without full certainty |
| `indeterminate` | Signals don't clearly favor either side |
| `suspicious_interaction` | Deliberate-looking action, but from hosting/VPS infrastructure — consistent with an attacker operating from rented infra |
| `likely_human_driven` | Behavior consistent with a manual interaction from an ordinary network |

Confidence is a 0–1 float. The engine's full signal logic is in
`classifyEvent()` in `src/index.js` — every label is backed by named,
inspectable signals (`prefetch_timing_lt_5s`, `known_scanner_or_proxy_ua`,
`repeat_burst_pattern`, etc.), not a black-box score, so it holds up under
technical questioning.

## Privacy boundary (keep this in your project docs verbatim)

> PhishAlert sends telemetry only when a user explicitly deploys a canary
> against a specific flagged email. Normal email analysis stays entirely
> on-device and separate from canary telemetry. No passwords, session
> cookies, email contents, or real credentials are ever transmitted to or
> stored by the canary infrastructure — only synthetic canary identifiers
> and metadata about who interacted with them.

## Next stages (not built yet)

- **Stage 2** — extension-side "Deploy Bait" UI in the Investigation/Forensics
  tab: calls `POST /api/canary`, decides how the resulting URL reaches
  attacker infrastructure (decoy reply, decoy document, etc.), stores the
  returned `canaryId` against the email.
- **Stage 3** — background.js polls `GET /api/canary/:id/events` and
  `GET /api/campaign/:id`, feeds results into the forensic timeline and
  the existing Phishing DNA campaign correlation.
