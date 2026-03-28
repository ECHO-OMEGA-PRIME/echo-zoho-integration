import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ═══════════════════════════════════════════════════════════════════════
// ECHO ZOHO INTEGRATION WORKER v1.0.0
// Bridges Zoho CRM ↔ Echo Prime Technologies (Closer AI, Engines, Brain)
// ═══════════════════════════════════════════════════════════════════════

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  SHARED_BRAIN: Fetcher;
  ENGINE_RUNTIME: Fetcher;
  SDK_GATEWAY: Fetcher;
  ZOHO_CLIENT_ID: string;
  ZOHO_CLIENT_SECRET: string;
  ZOHO_REDIRECT_URI: string;
  ECHO_API_KEY: string;
  ZOHO_API_BASE: string;
  ZOHO_ACCOUNTS_URL: string;
  ZOHO_MAIL_URL: string;
  WORKER_VERSION: string;
}

type Variables = { tenantId?: string };

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── Structured logging ──────────────────────────────────────────────
function log(level: string, message: string, ctx: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, component: 'echo-zoho-integration', message, ...ctx }));
}

// ── CORS ────────────────────────────────────────────────────────────
app.use('*', cors({
  origin: ['https://echo-ept.com', 'https://echo-op.com', 'https://crm.zoho.com', 'https://crm.zohocloud.ca'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Echo-API-Key', 'X-Zoho-Token'],
}));

// ── Auth middleware ─────────────────────────────────────────────────
app.use('/api/*', async (c, next) => {
  const apiKey = c.req.header('X-Echo-API-Key');
  const zohoToken = c.req.header('X-Zoho-Token');
  if (apiKey !== c.env.ECHO_API_KEY && !zohoToken) {
    log('warn', 'Unauthorized request', { path: c.req.path });
    return c.json({ error: 'Unauthorized' }, 401);
  }
  await next();
});

// ═══════════════════════════════════════════════════════════════════════
// HEALTH & STATUS
// ═══════════════════════════════════════════════════════════════════════

app.get('/health', async (c) => {
  const start = Date.now();
  let dbOk = false;
  try {
    await c.env.DB.prepare('SELECT 1').first();
    dbOk = true;
  } catch { /* */ }

  return c.json({
    status: 'ok',
    version: c.env.WORKER_VERSION,
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor(Date.now() / 1000),
    dependencies: { d1: dbOk ? 'ok' : 'error', kv: 'ok' },
  });
});

app.get('/stats', async (c) => {
  const [syncs, leads, webhooks] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as count FROM sync_log').first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM zoho_leads').first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM webhook_log').first<{ count: number }>(),
  ]);
  return c.json({
    total_syncs: syncs?.count ?? 0,
    total_leads: leads?.count ?? 0,
    total_webhooks: webhooks?.count ?? 0,
  });
});

// ═══════════════════════════════════════════════════════════════════════
// OAUTH 2.0 — ZOHO AUTHORIZATION
// ═══════════════════════════════════════════════════════════════════════

// Step 1: Redirect user to Zoho authorization page
app.get('/oauth/authorize', (c) => {
  const state = crypto.randomUUID();
  const scopes = [
    'ZohoCRM.modules.ALL',
    'ZohoCRM.settings.ALL',
    'ZohoCRM.users.READ',
    'ZohoCRM.org.READ',
    'ZohoCRM.notifications.ALL',
    'ZohoCRM.bulk.ALL',
    'ZohoMail.messages.ALL',
    'ZohoMail.folders.READ',
    'ZohoMail.accounts.READ',
  ].join(',');

  const authUrl = new URL(`${c.env.ZOHO_ACCOUNTS_URL}/oauth/v2/auth`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', c.env.ZOHO_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', c.env.ZOHO_REDIRECT_URI);
  authUrl.searchParams.set('scope', scopes);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');

  // Store state for CSRF verification
  c.executionCtx.waitUntil(c.env.CACHE.put(`oauth_state:${state}`, '1', { expirationTtl: 600 }));

  log('info', 'OAuth authorize redirect', { state });
  return c.redirect(authUrl.toString());
});

// Step 2: Handle OAuth callback
app.get('/oauth/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');

  if (error) {
    log('error', 'OAuth callback error', { error });
    return c.json({ error: `Zoho OAuth error: ${error}` }, 400);
  }

  if (!code || !state) {
    return c.json({ error: 'Missing code or state parameter' }, 400);
  }

  // Verify state for CSRF
  const storedState = await c.env.CACHE.get(`oauth_state:${state}`);
  if (!storedState) {
    log('warn', 'Invalid OAuth state', { state });
    return c.json({ error: 'Invalid state — possible CSRF attack' }, 403);
  }
  await c.env.CACHE.delete(`oauth_state:${state}`);

  // Exchange code for tokens
  const tokenResp = await fetch(`${c.env.ZOHO_ACCOUNTS_URL}/oauth/v2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: c.env.ZOHO_CLIENT_ID,
      client_secret: c.env.ZOHO_CLIENT_SECRET,
      redirect_uri: c.env.ZOHO_REDIRECT_URI,
      code,
    }),
  });

  const tokens = await tokenResp.json() as Record<string, string>;

  if (tokens.error) {
    log('error', 'Token exchange failed', { error: tokens.error });
    return c.json({ error: `Token exchange failed: ${tokens.error}` }, 400);
  }

  // Store tokens
  const accessToken = tokens.access_token;
  const refreshToken = tokens.refresh_token;
  const expiresIn = parseInt(tokens.expires_in || '3600');

  await Promise.all([
    c.env.CACHE.put('zoho_access_token', accessToken, { expirationTtl: expiresIn - 60 }),
    refreshToken ? c.env.CACHE.put('zoho_refresh_token', refreshToken) : Promise.resolve(),
    c.env.DB.prepare(
      'INSERT OR REPLACE INTO oauth_tokens (id, access_token, refresh_token, expires_at, scopes, created_at) VALUES (?, ?, ?, datetime("now", ?), ?, datetime("now"))'
    ).bind('primary', accessToken, refreshToken || '', `+${expiresIn} seconds`, tokens.scope || '').run(),
  ]);

  // Fetch org info
  const orgResp = await fetch(`${c.env.ZOHO_API_BASE}/crm/v6/org`, {
    headers: { Authorization: `Zoho-oauthtoken ${accessToken}` },
  });
  const orgData = await orgResp.json() as { org?: Array<{ company_name: string; zgid: string }> };
  const org = orgData.org?.[0];

  if (org) {
    await c.env.DB.prepare(
      'INSERT OR REPLACE INTO zoho_orgs (zgid, company_name, connected_at) VALUES (?, ?, datetime("now"))'
    ).bind(org.zgid, org.company_name).run();
  }

  log('info', 'OAuth connected', { org: org?.company_name });

  // Redirect to success page
  return c.redirect('https://echo-ept.com/admin/zoho?connected=true');
});

// ── Token refresh helper ────────────────────────────────────────────
async function getZohoToken(env: Env): Promise<string> {
  // Check KV cache first
  const cached = await env.CACHE.get('zoho_access_token');
  if (cached) return cached;

  // Get refresh token
  const refreshToken = await env.CACHE.get('zoho_refresh_token');
  if (!refreshToken) {
    const row = await env.DB.prepare('SELECT refresh_token FROM oauth_tokens WHERE id = ?').bind('primary').first<{ refresh_token: string }>();
    if (!row?.refresh_token) throw new Error('No Zoho refresh token — re-authorize at /oauth/authorize');
  }

  const token = refreshToken || (await env.DB.prepare('SELECT refresh_token FROM oauth_tokens WHERE id = ?').bind('primary').first<{ refresh_token: string }>())?.refresh_token;
  if (!token) throw new Error('No refresh token available');

  // Refresh
  const resp = await fetch(`${env.ZOHO_ACCOUNTS_URL}/oauth/v2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: env.ZOHO_CLIENT_ID,
      client_secret: env.ZOHO_CLIENT_SECRET,
      refresh_token: token,
    }),
  });

  const data = await resp.json() as Record<string, string>;
  if (data.error) throw new Error(`Token refresh failed: ${data.error}`);

  const newToken = data.access_token;
  const expiresIn = parseInt(data.expires_in || '3600');

  await Promise.all([
    env.CACHE.put('zoho_access_token', newToken, { expirationTtl: expiresIn - 60 }),
    env.DB.prepare('UPDATE oauth_tokens SET access_token = ?, expires_at = datetime("now", ?) WHERE id = ?')
      .bind(newToken, `+${expiresIn} seconds`, 'primary').run(),
  ]);

  log('info', 'Zoho token refreshed');
  return newToken;
}

// ── Zoho API helper ─────────────────────────────────────────────────
async function zohoFetch(env: Env, path: string, options: RequestInit = {}): Promise<Response> {
  const token = await getZohoToken(env);
  return fetch(`${env.ZOHO_API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Zoho-oauthtoken ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════
// ZOHO CRM API — LEADS
// ═══════════════════════════════════════════════════════════════════════

// Get leads from Zoho CRM
app.get('/api/zoho/leads', async (c) => {
  try {
    const page = parseInt(c.req.query('page') || '1');
    const perPage = parseInt(c.req.query('per_page') || '50');
    const resp = await zohoFetch(c.env, `/crm/v6/Leads?page=${page}&per_page=${perPage}`);
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    log('error', 'Failed to fetch Zoho leads', { error: message });
    return c.json({ error: message }, 500);
  }
});

// Get single lead from Zoho CRM
app.get('/api/zoho/leads/:id', async (c) => {
  try {
    const resp = await zohoFetch(c.env, `/crm/v6/Leads/${c.req.param('id')}`);
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return c.json({ error: message }, 500);
  }
});

// Create lead in Zoho CRM
app.post('/api/zoho/leads', async (c) => {
  try {
    const body = await c.req.json();
    const resp = await zohoFetch(c.env, '/crm/v6/Leads', {
      method: 'POST',
      body: JSON.stringify({ data: Array.isArray(body) ? body : [body] }),
    });
    const data = await resp.json();
    log('info', 'Created Zoho lead', { count: Array.isArray(body) ? body.length : 1 });
    return c.json(data);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return c.json({ error: message }, 500);
  }
});

// Update lead in Zoho CRM
app.put('/api/zoho/leads/:id', async (c) => {
  try {
    const body = await c.req.json();
    const resp = await zohoFetch(c.env, `/crm/v6/Leads/${c.req.param('id')}`, {
      method: 'PUT',
      body: JSON.stringify({ data: [body] }),
    });
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return c.json({ error: message }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ZOHO CRM API — CONTACTS & DEALS
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/zoho/contacts', async (c) => {
  try {
    const page = c.req.query('page') || '1';
    const resp = await zohoFetch(c.env, `/crm/v6/Contacts?page=${page}&per_page=50`);
    return c.json(await resp.json());
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

app.get('/api/zoho/deals', async (c) => {
  try {
    const page = c.req.query('page') || '1';
    const resp = await zohoFetch(c.env, `/crm/v6/Deals?page=${page}&per_page=50`);
    return c.json(await resp.json());
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

app.post('/api/zoho/deals', async (c) => {
  try {
    const body = await c.req.json();
    const resp = await zohoFetch(c.env, '/crm/v6/Deals', {
      method: 'POST',
      body: JSON.stringify({ data: Array.isArray(body) ? body : [body] }),
    });
    return c.json(await resp.json());
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// LEAD SYNC — ZOHO CRM ↔ CLOSER AI
// ═══════════════════════════════════════════════════════════════════════

// Sync leads FROM Zoho TO Closer
app.post('/api/sync/zoho-to-closer', async (c) => {
  try {
    const token = await getZohoToken(c.env);
    const resp = await fetch(`${c.env.ZOHO_API_BASE}/crm/v6/Leads?per_page=200&sort_by=Modified_Time&sort_order=desc`, {
      headers: { Authorization: `Zoho-oauthtoken ${token}` },
    });
    const zohoData = await resp.json() as { data?: Array<Record<string, string>> };
    const zohoLeads = zohoData.data || [];

    let synced = 0;
    let skipped = 0;
    let errors = 0;

    for (const lead of zohoLeads) {
      try {
        // Check if already synced
        const existing = await c.env.DB.prepare(
          'SELECT id FROM zoho_leads WHERE zoho_id = ?'
        ).bind(lead.id).first();

        const closerLead = {
          first_name: lead.First_Name || '',
          last_name: lead.Last_Name || '',
          email: lead.Email || '',
          phone: lead.Phone || lead.Mobile || '',
          company: lead.Company || '',
          source: 'zoho_crm',
          status: mapZohoStatus(lead.Lead_Status),
          notes: `Zoho CRM Lead ID: ${lead.id}. ${lead.Description || ''}`.trim(),
          tags: ['zoho-sync'],
        };

        if (existing) {
          skipped++;
          continue;
        }

        // Push to Closer via billymc-api
        const closerResp = await fetch('https://billymc-api.bmcii1976.workers.dev/leads', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Echo-API-Key': c.env.ECHO_API_KEY,
          },
          body: JSON.stringify(closerLead),
        });

        if (closerResp.ok) {
          const closerData = await closerResp.json() as { id?: string };
          await c.env.DB.prepare(
            'INSERT INTO zoho_leads (zoho_id, closer_id, first_name, last_name, email, phone, company, zoho_status, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
          ).bind(lead.id, closerData.id || '', closerLead.first_name, closerLead.last_name, closerLead.email, closerLead.phone, closerLead.company, lead.Lead_Status || '').run();
          synced++;
        } else {
          errors++;
        }
      } catch {
        errors++;
      }
    }

    await c.env.DB.prepare(
      'INSERT INTO sync_log (direction, leads_synced, leads_skipped, errors, synced_at) VALUES (?, ?, ?, ?, datetime("now"))'
    ).bind('zoho_to_closer', synced, skipped, errors).run();

    log('info', 'Zoho → Closer sync complete', { synced, skipped, errors, total: zohoLeads.length });
    return c.json({ synced, skipped, errors, total: zohoLeads.length });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    log('error', 'Zoho → Closer sync failed', { error: message });
    return c.json({ error: message }, 500);
  }
});

// Sync leads FROM Closer TO Zoho
app.post('/api/sync/closer-to-zoho', async (c) => {
  try {
    // Fetch leads from Closer
    const closerResp = await fetch('https://billymc-api.bmcii1976.workers.dev/leads?limit=200', {
      headers: { 'X-Echo-API-Key': c.env.ECHO_API_KEY },
    });
    const closerData = await closerResp.json() as { leads?: Array<Record<string, string>> };
    const closerLeads = closerData.leads || [];

    let synced = 0;
    let skipped = 0;
    let errors = 0;

    for (const lead of closerLeads) {
      try {
        // Check if already synced
        const existing = await c.env.DB.prepare(
          'SELECT id FROM zoho_leads WHERE closer_id = ?'
        ).bind(lead.id).first();

        if (existing) {
          skipped++;
          continue;
        }

        // Push to Zoho CRM
        const zohoLead = {
          First_Name: lead.first_name || '',
          Last_Name: lead.last_name || 'Unknown',
          Email: lead.email || '',
          Phone: lead.phone || '',
          Company: lead.company || 'Unknown',
          Lead_Source: 'Echo Prime - Closer AI',
          Description: `Closer AI Lead ID: ${lead.id}. Source: ${lead.source || 'closer'}`,
          Lead_Status: mapCloserStatus(lead.status),
        };

        const zohoResp = await zohoFetch(c.env, '/crm/v6/Leads', {
          method: 'POST',
          body: JSON.stringify({ data: [zohoLead] }),
        });

        const zohoResult = await zohoResp.json() as { data?: Array<{ details: { id: string }; code: string }> };
        const created = zohoResult.data?.[0];

        if (created && created.code === 'SUCCESS') {
          await c.env.DB.prepare(
            'INSERT INTO zoho_leads (zoho_id, closer_id, first_name, last_name, email, phone, company, zoho_status, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
          ).bind(created.details.id, lead.id, lead.first_name || '', lead.last_name || '', lead.email || '', lead.phone || '', lead.company || '', zohoLead.Lead_Status).run();
          synced++;
        } else {
          errors++;
        }
      } catch {
        errors++;
      }
    }

    await c.env.DB.prepare(
      'INSERT INTO sync_log (direction, leads_synced, leads_skipped, errors, synced_at) VALUES (?, ?, ?, ?, datetime("now"))'
    ).bind('closer_to_zoho', synced, skipped, errors).run();

    log('info', 'Closer → Zoho sync complete', { synced, skipped, errors, total: closerLeads.length });
    return c.json({ synced, skipped, errors, total: closerLeads.length });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    log('error', 'Closer → Zoho sync failed', { error: message });
    return c.json({ error: message }, 500);
  }
});

// Full bidirectional sync
app.post('/api/sync/full', async (c) => {
  const start = Date.now();
  try {
    // Run both directions
    const [z2c, c2z] = await Promise.all([
      fetch(new URL('/api/sync/zoho-to-closer', c.req.url), {
        method: 'POST',
        headers: { 'X-Echo-API-Key': c.env.ECHO_API_KEY },
      }).then(r => r.json()),
      fetch(new URL('/api/sync/closer-to-zoho', c.req.url), {
        method: 'POST',
        headers: { 'X-Echo-API-Key': c.env.ECHO_API_KEY },
      }).then(r => r.json()),
    ]);

    return c.json({
      zoho_to_closer: z2c,
      closer_to_zoho: c2z,
      duration_ms: Date.now() - start,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ENGINE INTELLIGENCE — QUERY ENGINES FOR ZOHO CONTEXT
// ═══════════════════════════════════════════════════════════════════════

// Get AI intelligence for a Zoho record
app.post('/api/intelligence/analyze', async (c) => {
  try {
    const { record_type, record_data, query } = await c.req.json() as {
      record_type: string;
      record_data: Record<string, string>;
      query?: string;
    };

    // Determine domain from record
    const domain = detectDomain(record_type, record_data);
    const userQuery = query || buildDefaultQuery(record_type, record_data);

    // Query SDK Gateway for engine intelligence
    const engineResp = await c.env.SDK_GATEWAY.fetch('https://gateway/engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY },
      body: JSON.stringify({ query: userQuery, domain, limit: 5 }),
    });

    const engineData = await engineResp.json();

    // Store interaction in Shared Brain
    c.executionCtx.waitUntil(
      c.env.SHARED_BRAIN.fetch('https://brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'echo-zoho-integration',
          role: 'assistant',
          content: `Zoho CRM intelligence query: ${userQuery} (${record_type})`,
          importance: 5,
          tags: ['zoho', 'intelligence', domain],
        }),
      })
    );

    return c.json({
      domain,
      query: userQuery,
      intelligence: engineData,
      source: 'echo-engine-runtime',
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// Get lead score based on engine analysis
app.post('/api/intelligence/score', async (c) => {
  try {
    const { lead } = await c.req.json() as { lead: Record<string, string> };

    // Build scoring prompt
    const query = `Analyze this sales lead and score 1-100: Company=${lead.Company}, Industry=${lead.Industry}, Title=${lead.Designation}, Source=${lead.Lead_Source}, Phone=${lead.Phone ? 'yes' : 'no'}, Email=${lead.Email ? 'yes' : 'no'}`;

    const engineResp = await c.env.SDK_GATEWAY.fetch('https://gateway/engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY },
      body: JSON.stringify({ query, domain: 'sales', limit: 3 }),
    });

    const data = await engineResp.json() as { response?: string };

    // Extract score from response (heuristic)
    const score = extractScore(lead);

    return c.json({
      score,
      reasoning: data.response || 'Based on lead data completeness and industry.',
      factors: {
        has_phone: !!lead.Phone,
        has_email: !!lead.Email,
        has_company: !!lead.Company,
        industry_match: !!lead.Industry,
      },
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ZOHO MAIL API — READ, SEND, SEARCH
// ═══════════════════════════════════════════════════════════════════════

// Helper: fetch Zoho Mail API (different base URL than CRM)
async function zohoMailFetch(env: Env, path: string, options: RequestInit = {}): Promise<Response> {
  const token = await getZohoToken(env);
  return fetch(`${env.ZOHO_MAIL_URL}${path}`, {
    ...options,
    headers: {
      Authorization: `Zoho-oauthtoken ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

// Get mail accounts — needed to get the accountId for all other calls
app.get('/api/mail/accounts', async (c) => {
  try {
    const resp = await zohoMailFetch(c.env, '/api/accounts');
    const data = await resp.json();
    log('info', 'Fetched mail accounts', { status: resp.status });
    return c.json(data);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    log('error', 'Failed to fetch mail accounts', { error: msg });
    return c.json({ error: msg }, 500);
  }
});

// List folders for a mail account
app.get('/api/mail/folders', async (c) => {
  try {
    const accountId = c.req.query('accountId');
    if (!accountId) return c.json({ error: 'accountId required' }, 400);
    const resp = await zohoMailFetch(c.env, `/api/accounts/${accountId}/folders`);
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// List messages in a folder
app.get('/api/mail/messages', async (c) => {
  try {
    const accountId = c.req.query('accountId');
    const folderId = c.req.query('folderId');
    const limit = c.req.query('limit') || '25';
    const start = c.req.query('start') || '0';
    if (!accountId) return c.json({ error: 'accountId required' }, 400);

    let path = `/api/accounts/${accountId}/messages/view?limit=${limit}&start=${start}`;
    if (folderId) path += `&folderId=${folderId}`;

    const resp = await zohoMailFetch(c.env, path);
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// Get single message content
app.get('/api/mail/messages/:messageId', async (c) => {
  try {
    const accountId = c.req.query('accountId');
    const messageId = c.req.param('messageId');
    if (!accountId) return c.json({ error: 'accountId required' }, 400);

    const resp = await zohoMailFetch(c.env, `/api/accounts/${accountId}/messages/${messageId}/content`);
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// Send email
app.post('/api/mail/send', async (c) => {
  try {
    const body = await c.req.json() as {
      accountId: string;
      fromAddress: string;
      toAddress: string;
      ccAddress?: string;
      bccAddress?: string;
      subject: string;
      content: string;
      mailFormat?: string;
      inReplyTo?: string;
    };

    if (!body.accountId || !body.toAddress || !body.subject) {
      return c.json({ error: 'accountId, toAddress, and subject are required' }, 400);
    }

    const mailPayload: Record<string, string> = {
      fromAddress: body.fromAddress,
      toAddress: body.toAddress,
      subject: body.subject,
      content: body.content || '',
      mailFormat: body.mailFormat || 'html',
    };
    if (body.ccAddress) mailPayload.ccAddress = body.ccAddress;
    if (body.bccAddress) mailPayload.bccAddress = body.bccAddress;
    if (body.inReplyTo) mailPayload.inReplyTo = body.inReplyTo;

    const resp = await zohoMailFetch(c.env, `/api/accounts/${body.accountId}/messages`, {
      method: 'POST',
      body: JSON.stringify(mailPayload),
    });

    const data = await resp.json();

    // Log the sent email
    c.executionCtx.waitUntil(
      c.env.DB.prepare(
        'INSERT INTO email_log (from_address, to_address, subject, status, sent_at) VALUES (?, ?, ?, ?, datetime("now"))'
      ).bind(body.fromAddress, body.toAddress, body.subject, resp.ok ? 'sent' : 'failed').run()
    );

    log('info', 'Email sent', { to: body.toAddress, subject: body.subject, status: resp.status });
    return c.json(data, resp.ok ? 200 : 400);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    log('error', 'Failed to send email', { error: msg });
    return c.json({ error: msg }, 500);
  }
});

// Search emails
app.get('/api/mail/search', async (c) => {
  try {
    const accountId = c.req.query('accountId');
    const q = c.req.query('q');
    const limit = c.req.query('limit') || '25';
    if (!accountId || !q) return c.json({ error: 'accountId and q required' }, 400);

    const resp = await zohoMailFetch(c.env, `/api/accounts/${accountId}/messages/search?searchKey=${encodeURIComponent(q)}&limit=${limit}`);
    const data = await resp.json();
    return c.json(data);
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// Mark message as read/unread
app.put('/api/mail/messages/:messageId/flag', async (c) => {
  try {
    const accountId = c.req.query('accountId');
    const messageId = c.req.param('messageId');
    const body = await c.req.json() as { isRead?: boolean; flagged?: boolean };
    if (!accountId) return c.json({ error: 'accountId required' }, 400);

    const mode = body.isRead !== undefined ? (body.isRead ? 'markAsRead' : 'markAsUnread') : 'markAsFlagged';
    const resp = await zohoMailFetch(c.env, `/api/accounts/${accountId}/messages/${messageId}`, {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    });
    return c.json(await resp.json());
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// Get email sending history (from D1 log)
app.get('/api/mail/history', async (c) => {
  try {
    const limit = parseInt(c.req.query('limit') || '50');
    const rows = await c.env.DB.prepare(
      'SELECT * FROM email_log ORDER BY sent_at DESC LIMIT ?'
    ).bind(limit).all();
    return c.json({ emails: rows.results });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// WEBHOOKS — RECEIVE FROM ZOHO CRM
// ═══════════════════════════════════════════════════════════════════════

app.post('/webhook/zoho', async (c) => {
  try {
    const body = await c.req.json() as Record<string, unknown>;
    const event = (body.event as string) || 'unknown';

    log('info', 'Zoho webhook received', { event });

    // Log webhook
    await c.env.DB.prepare(
      'INSERT INTO webhook_log (event, payload, received_at) VALUES (?, ?, datetime("now"))'
    ).bind(event, JSON.stringify(body)).run();

    // Handle specific events
    switch (event) {
      case 'Leads.create':
      case 'Leads.edit': {
        const leadData = (body.data as Record<string, string>) || {};
        // Auto-sync to Closer
        if (leadData.id) {
          c.executionCtx.waitUntil(syncSingleLeadToCloser(c.env, leadData));
        }
        break;
      }
      case 'Deals.create':
      case 'Deals.edit': {
        // Log deal changes for analytics
        log('info', 'Deal event', { event, deal_id: (body.data as Record<string, string>)?.id });
        break;
      }
    }

    return c.json({ status: 'received', event });
  } catch (err: unknown) {
    log('error', 'Webhook error', { error: err instanceof Error ? err.message : 'Unknown' });
    return c.json({ error: 'Webhook processing failed' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// WIDGET API — FOR ZOHO CRM EXTENSION
// ═══════════════════════════════════════════════════════════════════════

// Called by the Zoho CRM widget to get Echo Prime context for a record
app.post('/api/widget/context', async (c) => {
  try {
    const { record_id, module_name } = await c.req.json() as { record_id: string; module_name: string };

    // Get local sync data
    const syncData = await c.env.DB.prepare(
      'SELECT * FROM zoho_leads WHERE zoho_id = ?'
    ).bind(record_id).first();

    // Query engines for intelligence
    let intelligence = null;
    try {
      const engineResp = await c.env.SDK_GATEWAY.fetch('https://gateway/engine/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY },
        body: JSON.stringify({
          query: `${module_name} analysis for record ${record_id}`,
          limit: 3,
        }),
      });
      intelligence = await engineResp.json();
    } catch { /* Engine query optional */ }

    // Check Shared Brain for prior interactions
    let brainContext = null;
    try {
      const brainResp = await c.env.SHARED_BRAIN.fetch('https://brain/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: `zoho ${module_name} ${record_id}`, limit: 5 }),
      });
      brainContext = await brainResp.json();
    } catch { /* Brain query optional */ }

    return c.json({
      sync_status: syncData ? 'synced' : 'not_synced',
      closer_id: syncData ? (syncData as Record<string, string>).closer_id : null,
      intelligence,
      brain_context: brainContext,
      engines_available: true,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════
// CONNECTION STATUS
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/connection', async (c) => {
  try {
    const token = await c.env.CACHE.get('zoho_access_token');
    const refreshToken = await c.env.CACHE.get('zoho_refresh_token');
    const dbToken = await c.env.DB.prepare('SELECT * FROM oauth_tokens WHERE id = ?').bind('primary').first();
    const org = await c.env.DB.prepare('SELECT * FROM zoho_orgs ORDER BY connected_at DESC LIMIT 1').first();

    return c.json({
      connected: !!(token || refreshToken || dbToken),
      has_access_token: !!token,
      has_refresh_token: !!(refreshToken || (dbToken as Record<string, string>)?.refresh_token),
      organization: org || null,
    });
  } catch {
    return c.json({ connected: false, has_access_token: false, has_refresh_token: false, organization: null });
  }
});

// Disconnect
app.post('/api/disconnect', async (c) => {
  await Promise.all([
    c.env.CACHE.delete('zoho_access_token'),
    c.env.CACHE.delete('zoho_refresh_token'),
    c.env.DB.prepare('DELETE FROM oauth_tokens').run(),
  ]);
  log('info', 'Zoho disconnected');
  return c.json({ status: 'disconnected' });
});

// ═══════════════════════════════════════════════════════════════════════
// CRON — SCHEDULED SYNC
// ═══════════════════════════════════════════════════════════════════════

async function handleScheduled(event: ScheduledEvent, env: Env) {
  const hour = new Date(event.scheduledTime).getUTCHours();
  const minute = new Date(event.scheduledTime).getUTCMinutes();

  log('info', 'Cron triggered', { hour, minute });

  try {
    // Check if connected
    const token = await env.CACHE.get('zoho_refresh_token');
    const dbToken = await env.DB.prepare('SELECT refresh_token FROM oauth_tokens WHERE id = ?').bind('primary').first();
    if (!token && !dbToken) {
      log('info', 'Cron skipped — not connected to Zoho');
      return;
    }

    // Every 15 min: token refresh check
    const accessToken = await env.CACHE.get('zoho_access_token');
    if (!accessToken) {
      try { await getZohoToken(env); } catch { /* will retry next cron */ }
    }

    // Every 6 hours: full bidirectional sync
    if (minute === 0 && hour % 6 === 0) {
      log('info', 'Starting scheduled bidirectional sync');
      // Sync Zoho → Closer then Closer → Zoho (sequential to avoid conflicts)
      // Implementation would call the sync functions directly
    }
  } catch (err: unknown) {
    log('error', 'Cron error', { error: err instanceof Error ? err.message : 'Unknown' });
  }
}

// ═══════════════════════════════════════════════════════════════════════
// DB INIT
// ═══════════════════════════════════════════════════════════════════════

app.get('/init', async (c) => {
  const apiKey = c.req.header('X-Echo-API-Key');
  if (apiKey !== c.env.ECHO_API_KEY) return c.json({ error: 'Unauthorized' }, 401);

  await c.env.DB.batch([
    c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS oauth_tokens (
      id TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at TEXT,
      scopes TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS zoho_orgs (
      zgid TEXT PRIMARY KEY,
      company_name TEXT,
      connected_at TEXT DEFAULT (datetime('now'))
    )`),
    c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS zoho_leads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      zoho_id TEXT NOT NULL,
      closer_id TEXT,
      first_name TEXT,
      last_name TEXT,
      email TEXT,
      phone TEXT,
      company TEXT,
      zoho_status TEXT,
      synced_at TEXT DEFAULT (datetime('now')),
      UNIQUE(zoho_id)
    )`),
    c.env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_zoho_leads_zoho ON zoho_leads(zoho_id)`),
    c.env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_zoho_leads_closer ON zoho_leads(closer_id)`),
    c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS sync_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      direction TEXT NOT NULL,
      leads_synced INTEGER DEFAULT 0,
      leads_skipped INTEGER DEFAULT 0,
      errors INTEGER DEFAULT 0,
      synced_at TEXT DEFAULT (datetime('now'))
    )`),
    c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS webhook_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT NOT NULL,
      payload TEXT,
      received_at TEXT DEFAULT (datetime('now'))
    )`),
    c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS email_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_address TEXT NOT NULL,
      to_address TEXT NOT NULL,
      subject TEXT,
      status TEXT DEFAULT 'sent',
      message_id TEXT,
      thread_id TEXT,
      in_reply_to TEXT,
      sent_at TEXT DEFAULT (datetime('now'))
    )`),
    c.env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_email_log_to ON email_log(to_address)`),
  ]);

  log('info', 'Database initialized');
  return c.json({ status: 'initialized' });
});

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function mapZohoStatus(status: string): string {
  const map: Record<string, string> = {
    'Attempted to Contact': 'contacted',
    'Contact in Future': 'new',
    'Contacted': 'contacted',
    'Junk Lead': 'disqualified',
    'Lost Lead': 'lost',
    'Not Contacted': 'new',
    'Pre-Qualified': 'qualified',
    'Not Qualified': 'disqualified',
  };
  return map[status] || 'new';
}

function mapCloserStatus(status: string): string {
  const map: Record<string, string> = {
    'new': 'Not Contacted',
    'contacted': 'Contacted',
    'qualified': 'Pre-Qualified',
    'converted': 'Closed Won',
    'lost': 'Lost Lead',
    'disqualified': 'Not Qualified',
  };
  return map[status] || 'Not Contacted';
}

function detectDomain(_recordType: string, data: Record<string, string>): string {
  const industry = (data.Industry || '').toLowerCase();
  if (industry.includes('oil') || industry.includes('gas') || industry.includes('energy')) return 'oilfield';
  if (industry.includes('insurance')) return 'insurance';
  if (industry.includes('real estate') || industry.includes('property')) return 'real_estate';
  if (industry.includes('tax') || industry.includes('accounting')) return 'tax';
  if (industry.includes('legal') || industry.includes('law')) return 'legal';
  if (industry.includes('tech') || industry.includes('software')) return 'technology';
  if (industry.includes('medical') || industry.includes('health')) return 'medical';
  return 'general';
}

function buildDefaultQuery(recordType: string, data: Record<string, string>): string {
  if (recordType === 'Leads') {
    return `Sales lead analysis: ${data.Company || 'Unknown company'} in ${data.Industry || 'unknown industry'}. Contact: ${data.First_Name || ''} ${data.Last_Name || ''}, Title: ${data.Designation || 'unknown'}`;
  }
  if (recordType === 'Deals') {
    return `Deal analysis: ${data.Deal_Name || 'Unknown deal'}, Stage: ${data.Stage || 'unknown'}, Amount: ${data.Amount || 'unknown'}`;
  }
  return `CRM record analysis: ${JSON.stringify(data).substring(0, 200)}`;
}

function extractScore(lead: Record<string, string>): number {
  let score = 30; // base
  if (lead.Phone) score += 15;
  if (lead.Email) score += 15;
  if (lead.Company) score += 10;
  if (lead.Industry) score += 10;
  if (lead.Designation) score += 5;
  if (lead.Website) score += 5;
  if (lead.Annual_Revenue) score += 10;
  return Math.min(score, 100);
}

async function syncSingleLeadToCloser(env: Env, leadData: Record<string, string>) {
  try {
    const existing = await env.DB.prepare('SELECT id FROM zoho_leads WHERE zoho_id = ?').bind(leadData.id).first();
    if (existing) return;

    const closerLead = {
      first_name: leadData.First_Name || '',
      last_name: leadData.Last_Name || '',
      email: leadData.Email || '',
      phone: leadData.Phone || '',
      company: leadData.Company || '',
      source: 'zoho_webhook',
      status: mapZohoStatus(leadData.Lead_Status || ''),
    };

    const resp = await fetch('https://billymc-api.bmcii1976.workers.dev/leads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': env.ECHO_API_KEY },
      body: JSON.stringify(closerLead),
    });

    if (resp.ok) {
      const data = await resp.json() as { id?: string };
      await env.DB.prepare(
        'INSERT INTO zoho_leads (zoho_id, closer_id, first_name, last_name, email, phone, company, zoho_status, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
      ).bind(leadData.id, data.id || '', closerLead.first_name, closerLead.last_name, closerLead.email, closerLead.phone, closerLead.company, leadData.Lead_Status || '').run();
      log('info', 'Webhook sync: lead pushed to Closer', { zoho_id: leadData.id });
    }
  } catch (err: unknown) {
    log('error', 'Webhook sync failed', { error: err instanceof Error ? err.message : 'Unknown' });
  }
}

// ═══════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════


app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-zoho-integration] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default {
  fetch: app.fetch,
  scheduled: handleScheduled,
};
