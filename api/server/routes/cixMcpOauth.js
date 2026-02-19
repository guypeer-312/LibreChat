const { Router } = require('express');
const { logger } = require('@librechat/data-schemas');
const { getBasePath } = require('@librechat/api');
const { getOIDCAccessToken } = require('~/server/services/cixContext');

const router = Router();

const FLOW_COOKIE = 'cix_mcp_oauth_flow';
const GATEWAY_SLUG_RE = /^[a-z][a-z0-9_-]{0,63}$/;

function cixIamBaseURL() {
  return (process.env.CIX_IAM_BASE_URL || 'http://cix-iam:8085').trim().replace(/\/+$/, '');
}

function sameSiteValue() {
  // Needed for OAuth redirects. Lax still sends cookies on top-level navigations (the callback GET).
  return 'lax';
}

function secureCookie(req) {
  if (req?.secure) {
    return true;
  }
  const proto = String(req?.headers?.['x-forwarded-proto'] || '').toLowerCase();
  return proto === 'https';
}

function ensureOIDCToken() {
  const token = getOIDCAccessToken();
  if (!token) {
    throw new Error('missing OIDC access token (no request context)');
  }
  return token;
}

async function postJSON(url, body, token, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });

    const text = await resp.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    if (!resp.ok) {
      const msg = json?.error || json?.message || text || `http ${resp.status}`;
      throw new Error(msg);
    }
    if (!json || typeof json !== 'object') {
      throw new Error('invalid json response');
    }
    return json;
  } finally {
    clearTimeout(t);
  }
}

function parseGatewaySlug(value) {
  const gatewaySlug = String(value || '').toLowerCase().trim();
  if (!gatewaySlug || gatewaySlug.length > 128 || !GATEWAY_SLUG_RE.test(gatewaySlug)) {
    return null;
  }
  return gatewaySlug;
}

function ensureTrailingSlash(url) {
  const value = String(url || '').trim();
  if (!value) {
    return '';
  }
  return value.endsWith('/') ? value : `${value}/`;
}

function setFlowCookie(res, req, state, gatewaySlug, maxAgeMs) {
  const basePath = getBasePath();
  const cookiePath = `${basePath}/api/cix/mcp/oauth`;
  res.cookie(FLOW_COOKIE, `${state}.${gatewaySlug}`, {
    httpOnly: true,
    sameSite: sameSiteValue(),
    secure: secureCookie(req),
    maxAge: maxAgeMs,
    path: cookiePath,
  });
}

function clearFlowCookie(res) {
  const basePath = getBasePath();
  const cookiePath = `${basePath}/api/cix/mcp/oauth`;
  res.clearCookie(FLOW_COOKIE, { path: cookiePath });
}

function parseFlowCookie(req, expectedState) {
  const raw = String(req?.cookies?.[FLOW_COOKIE] || '').trim();
  if (!raw) {
    return null;
  }
  const idx = raw.indexOf('.');
  if (idx <= 0 || idx === raw.length - 1) {
    return null;
  }
  const state = raw.slice(0, idx).trim();
  const gatewaySlug = raw.slice(idx + 1).trim();
  if (!state || !gatewaySlug) {
    return null;
  }
  if (expectedState && state !== expectedState) {
    return null;
  }
  if (!GATEWAY_SLUG_RE.test(gatewaySlug)) {
    return null;
  }
  return { state, gatewaySlug };
}

router.get('/start', async (req, res) => {
  const gatewaySlug = parseGatewaySlug(req.query?.gateway_slug);
  if (!gatewaySlug) {
    return res.status(400).send('invalid gateway_slug\n');
  }

  const base = cixIamBaseURL();
  if (!base) {
    return res.status(500).send('CIX_IAM_BASE_URL not configured\n');
  }

  let token;
  try {
    token = ensureOIDCToken();
  } catch (err) {
    logger.warn('[cixMcpOauth.start] missing OIDC token', { error: err?.message || String(err) });
    return res.status(401).send('missing oidc token\n');
  }

  const returnTo = ensureTrailingSlash(process.env.DOMAIN_SERVER || process.env.DOMAIN_CLIENT || '');
  const timeoutMs = Number(process.env.CIX_IAM_TIMEOUT_MS || 5000);

  try {
    const json = await postJSON(
      `${base}/v1/mcp/oauth/start`,
      { gateway_slug: gatewaySlug, return_to: returnTo },
      token,
      timeoutMs,
    );

    const ok = json?.ok === true;
    const authorizationURL = typeof json?.authorization_url === 'string' ? json.authorization_url : '';
    const state = typeof json?.state === 'string' ? json.state : '';
    if (!ok || !authorizationURL || !state) {
      logger.error('[cixMcpOauth.start] invalid response shape', json);
      return res.status(502).send('oauth start failed\n');
    }

    // Store state->gatewaySlug mapping for the callback exchange.
    // We keep this in an HttpOnly cookie to avoid additional server-side state in LibreChat.
    setFlowCookie(res, req, state, gatewaySlug, 10 * 60 * 1000);

    return res.redirect(302, authorizationURL);
  } catch (err) {
    logger.error('[cixMcpOauth.start] oauth start request failed', {
      gatewaySlug,
      error: err?.message || String(err),
    });
    return res.status(502).send('oauth start request failed\n');
  }
});

router.get('/callback', async (req, res) => {
  const basePath = getBasePath();
  const code = String(req.query?.code || '').trim();
  const state = String(req.query?.state || '').trim();

  if (!code || !state) {
    return res.redirect(`${basePath}/oauth/error?error=missing_code_or_state`);
  }

  const flow = parseFlowCookie(req, state);
  if (!flow) {
    return res.redirect(`${basePath}/oauth/error?error=missing_flow_cookie`);
  }

  const base = cixIamBaseURL();
  if (!base) {
    return res.redirect(`${basePath}/oauth/error?error=iam_not_configured`);
  }

  let token;
  try {
    token = ensureOIDCToken();
  } catch (err) {
    logger.warn('[cixMcpOauth.callback] missing OIDC token', { error: err?.message || String(err) });
    return res.redirect(`${basePath}/oauth/error?error=not_logged_in`);
  }

  const timeoutMs = Number(process.env.CIX_IAM_TIMEOUT_MS || 5000);

  try {
    const json = await postJSON(
      `${base}/v1/mcp/oauth/exchange`,
      { gateway_slug: flow.gatewaySlug, state, code },
      token,
      timeoutMs,
    );

    const ok = json?.ok === true;
    if (!ok) {
      logger.error('[cixMcpOauth.callback] invalid exchange response shape', json);
      return res.redirect(`${basePath}/oauth/error?error=exchange_failed`);
    }

    clearFlowCookie(res);
    return res.redirect(`${basePath}/?mcp_oauth=ok&gateway_slug=${encodeURIComponent(flow.gatewaySlug)}`);
  } catch (err) {
    logger.error('[cixMcpOauth.callback] oauth exchange request failed', {
      gatewaySlug: flow.gatewaySlug,
      error: err?.message || String(err),
    });
    return res.redirect(`${basePath}/oauth/error?error=exchange_request_failed`);
  }
});

module.exports = router;
