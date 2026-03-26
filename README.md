# Echo Zoho Integration

Cloudflare Worker that bridges Zoho CRM and Zoho Mail with the Echo Prime intelligence platform. Provides bidirectional lead synchronization, AI-powered lead analysis, email management, and a Zoho CRM widget API.

## Features

- **OAuth 2.0 Flow** -- Full Zoho OAuth authorization with automatic token refresh (every 15 minutes via cron)
- **Bidirectional Lead Sync** -- Sync leads between Zoho CRM and Closer AI sales platform; push new leads to Zoho, pull Zoho contacts into Closer
- **Zoho Mail API** -- Read inbox, send emails, search messages, and manage folders through the Worker
- **AI Intelligence Analysis** -- Analyze leads using Echo Engine Runtime and SDK Gateway for domain detection, scoring, and enrichment
- **Lead Scoring** -- Multi-factor lead scoring (engagement, profile completeness, interaction recency) with automatic tier classification (hot/warm/cold)
- **Webhook Receiver** -- Accept Zoho CRM webhooks for real-time event processing (lead created, deal updated, contact modified)
- **Widget API** -- Serve data to a Zoho CRM extension widget embedded inside the Zoho CRM UI
- **Shared Brain Integration** -- Store all lead interactions and AI analysis results in Echo Shared Brain for cross-system memory
- **Structured JSON Logging** -- Every request and response logged with timestamps, latency, and context

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with dependency status |
| `GET` | `/auth/login` | Initiate Zoho OAuth 2.0 flow |
| `GET` | `/auth/callback` | OAuth callback handler, exchanges code for tokens |
| `GET` | `/auth/status` | Check current OAuth token status |
| `POST` | `/auth/refresh` | Force token refresh |
| `GET` | `/crm/leads` | List Zoho CRM leads |
| `GET` | `/crm/leads/:id` | Get specific lead details |
| `POST` | `/crm/leads` | Create a new lead in Zoho CRM |
| `PUT` | `/crm/leads/:id` | Update an existing lead |
| `POST` | `/crm/search` | Search Zoho CRM records |
| `GET` | `/mail/inbox` | Read Zoho Mail inbox |
| `POST` | `/mail/send` | Send email via Zoho Mail |
| `POST` | `/mail/search` | Search emails |
| `POST` | `/webhook` | Receive Zoho CRM webhook events |
| `POST` | `/sync/to-zoho` | Push Closer AI leads to Zoho CRM |
| `POST` | `/sync/from-zoho` | Pull Zoho contacts into Closer AI |
| `POST` | `/sync/full` | Full bidirectional sync |
| `POST` | `/analyze/:leadId` | AI analysis of a specific lead |
| `GET` | `/widget/lead/:id` | Widget API for Zoho CRM extension |

## Configuration

### Environment Variables (`wrangler.toml`)

```toml
[vars]
VERSION = "2.0.0"
```

### Secrets (set via `wrangler secret put`)

| Secret | Description |
|--------|-------------|
| `ZOHO_CLIENT_ID` | Zoho API OAuth Client ID |
| `ZOHO_CLIENT_SECRET` | Zoho API OAuth Client Secret |
| `ZOHO_REDIRECT_URI` | OAuth callback URL |
| `ECHO_API_KEY` | Echo Prime API key for service bindings |

### Bindings

| Type | Binding | Resource |
|------|---------|----------|
| D1 Database | `DB` | `echo-zoho-integration` (5d28e41d) |
| KV Namespace | `CACHE` | KV (c84a9392) |
| Service | `SHARED_BRAIN` | `echo-shared-brain` |
| Service | `ENGINE_RUNTIME` | `echo-engine-runtime` |
| Service | `SDK_GATEWAY` | `echo-sdk-gateway` |

### Cron Triggers

| Schedule | Purpose |
|----------|---------|
| `*/15 * * * *` | OAuth token refresh |
| `0 */6 * * *` | Full bidirectional lead sync |

## Deployment

```bash
cd O:\ECHO_OMEGA_PRIME\WORKERS\echo-zoho-integration
npx wrangler deploy

# Set secrets
echo "CLIENT_ID" | npx wrangler secret put ZOHO_CLIENT_ID
echo "CLIENT_SECRET" | npx wrangler secret put ZOHO_CLIENT_SECRET
echo "REDIRECT_URI" | npx wrangler secret put ZOHO_REDIRECT_URI
echo "API_KEY" | npx wrangler secret put ECHO_API_KEY

# Verify
curl -s https://echo-zoho-integration.bmcii1976.workers.dev/health
```

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Language**: TypeScript (Hono framework)
- **Database**: Cloudflare D1 (leads, sync history, webhook events)
- **Cache**: Cloudflare KV (OAuth tokens, rate limits)
- **Integrations**: Zoho CRM API v2, Zoho Mail API, Echo SDK Gateway, Echo Shared Brain, Echo Engine Runtime
- **Auth**: Zoho OAuth 2.0 with automatic token lifecycle management
- **Compatibility**: `nodejs_compat` flag enabled
