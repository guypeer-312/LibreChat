const { logger } = require('@librechat/data-schemas');
const { getOIDCAccessToken } = require('./cixContext');

function vaultBaseURL() {
  return (process.env.CIX_VAULT_URL || '').trim().replace(/\/+$/, '');
}

async function postJSON(url, body, headers, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        ...headers,
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
    if (!json) {
      throw new Error('invalid json response');
    }
    return json;
  } finally {
    clearTimeout(t);
  }
}

function ensureToken() {
  const token = getOIDCAccessToken();
  if (!token) {
    throw new Error('missing OIDC access token (no request context)');
  }
  return token;
}

async function encryptStrings(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error('values required');
  }
  const base = vaultBaseURL();
  if (!base) {
    throw new Error('CIX_VAULT_URL not configured');
  }

  const token = ensureToken();
  const timeoutMs = Number(process.env.CIX_VAULT_TIMEOUT_MS || 2000);

  const json = await postJSON(
    `${base}/encrypt`,
    { values: values.map((v) => (v == null ? '' : String(v))) },
    { authorization: `Bearer ${token}` },
    timeoutMs,
  );

  if (!json.ok || !Array.isArray(json.values)) {
    logger.error('[CixVaultService.encryptStrings] Invalid response shape:', json);
    throw new Error('vault encrypt failed');
  }
  if (json.values.length !== values.length) {
    throw new Error('vault encrypt count mismatch');
  }
  return json.values;
}

async function decryptStrings(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error('values required');
  }
  const base = vaultBaseURL();
  if (!base) {
    throw new Error('CIX_VAULT_URL not configured');
  }

  const token = ensureToken();
  const timeoutMs = Number(process.env.CIX_VAULT_TIMEOUT_MS || 2000);

  const json = await postJSON(
    `${base}/decrypt`,
    { values: values.map((v) => (v == null ? '' : String(v))) },
    { authorization: `Bearer ${token}` },
    timeoutMs,
  );

  if (!json.ok || !Array.isArray(json.values)) {
    logger.error('[CixVaultService.decryptStrings] Invalid response shape:', json);
    throw new Error('vault decrypt failed');
  }
  if (json.values.length !== values.length) {
    throw new Error('vault decrypt count mismatch');
  }
  return json.values;
}

module.exports = {
  encryptStrings,
  decryptStrings,
};

