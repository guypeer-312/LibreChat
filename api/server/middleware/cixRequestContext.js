const cookies = require('cookie');
const openIdClient = require('openid-client');
const { isEnabled } = require('@librechat/api');
const { logger } = require('@librechat/data-schemas');
const { setOpenIDAuthTokens } = require('~/server/services/AuthService');
const { getOpenIdConfig } = require('~/strategies');
const { extractBearerToken, runWithCixContext } = require('~/server/services/cixContext');

const TRACE = String(process.env.CIX_VAULT_TRACE || '').toLowerCase() === 'true';
const OPENID_REFRESH_SKEW_SECONDS = 30;

const refreshLocks = new Map();

function base64UrlDecodeJSON(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function jwtExpSeconds(token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length < 2) {
    return null;
  }
  const payload = base64UrlDecodeJSON(parts[1]);
  const exp = payload?.exp;
  return typeof exp === 'number' && Number.isFinite(exp) ? exp : null;
}

function refreshLockKey(req) {
  return req?.sessionID || req?.session?.id || req?.user?.id || req?.user?._id?.toString?.() || 'global';
}

async function refreshOpenIDTokensIfNeeded(req, res, traceMeta) {
  if (!isEnabled(process.env.OPENID_REUSE_TOKENS)) {
    return null;
  }

  const sessionTokens = req?.session?.openidTokens;
  const accessToken = sessionTokens?.accessToken;
  const refreshToken = sessionTokens?.refreshToken;
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    return null;
  }
  if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
    return null;
  }

  const exp = jwtExpSeconds(accessToken);
  if (exp == null) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (now + OPENID_REFRESH_SKEW_SECONDS < exp) {
    return null;
  }

  const lockKey = refreshLockKey(req);
  const existing = refreshLocks.get(lockKey);
  if (existing) {
    return existing;
  }

  const refreshPromise = (async () => {
    const openIdConfig = getOpenIdConfig();
    const tokenset = await openIdClient.refreshTokenGrant(openIdConfig, refreshToken);

    const userId = req?.user?._id?.toString?.() || req?.user?.id;
    const newAccessToken =
      setOpenIDAuthTokens(tokenset, req, res, userId ? String(userId) : undefined, refreshToken) ||
      tokenset.access_token;

    // Keep `req.user.federatedTokens` fresh so runtime placeholder substitution uses the updated token.
    if (req?.user) {
      const accessExp = jwtExpSeconds(newAccessToken) || exp;
      req.user.federatedTokens = {
        ...(req.user.federatedTokens || {}),
        access_token: newAccessToken,
        id_token: tokenset.id_token,
        expires_at: accessExp,
      };
    }

    if (TRACE && req?.originalUrl?.startsWith('/api/')) {
      logger.info('[cixRequestContext] refreshed openid access token', {
        ...traceMeta,
        now,
        exp,
      });
    }

    return newAccessToken;
  })();

  refreshLocks.set(lockKey, refreshPromise);
  refreshPromise.finally(() => refreshLocks.delete(lockKey));

  return refreshPromise;
}

module.exports = async function cixRequestContext(req, res, next) {
  const rawHeader = req?.headers?.authorization ?? req?.headers?.Authorization;
  let oidcAccessToken = extractBearerToken(rawHeader);
  let source = oidcAccessToken ? 'auth_header' : 'none';
  const traceMeta = {
    present: Boolean(oidcAccessToken),
    source,
    path: req?.originalUrl,
  };

  // For OpenID users, prefer the server-side stored access token.
  // This is required for request types that can't set custom headers (e.g. EventSource/SSE),
  // and avoids large-cookie issues when OPENID_REUSE_TOKENS is enabled.
  if (isEnabled(process.env.OPENID_REUSE_TOKENS)) {
    try {
      const refreshed = await refreshOpenIDTokensIfNeeded(req, res, traceMeta);
      if (!oidcAccessToken) {
        const sessionToken = refreshed || req.session?.openidTokens?.accessToken;
        if (typeof sessionToken === 'string' && sessionToken.length > 0) {
          oidcAccessToken = sessionToken;
          source = refreshed ? 'session_refreshed' : 'session';
        }
      }
    } catch (err) {
      logger.warn('[cixRequestContext] failed to refresh openid access token', {
        error: err?.message || String(err),
      });
    }
  }

  // Backward-compat fallback (when OpenID tokens are stored in cookies).
  if (!oidcAccessToken) {
    const cookieHeader = req?.headers?.cookie;
    const parsedCookies = cookieHeader ? cookies.parse(cookieHeader) : {};
    if (typeof parsedCookies.openid_access_token === 'string' && parsedCookies.openid_access_token) {
      oidcAccessToken = parsedCookies.openid_access_token;
      source = 'cookie';
    }
  }

  // Ensure OpenID users always carry the current server-side token in `req.user` so that
  // runtime placeholder substitution (e.g. {{LIBRECHAT_OPENID_ACCESS_TOKEN}} in MCP headers)
  // uses the refreshed session token instead of a stale value stored on the user document.
  if (isEnabled(process.env.OPENID_REUSE_TOKENS) && req?.user && req?.session?.openidTokens) {
    const sessionToken = req.session.openidTokens.accessToken;
    if (typeof sessionToken === 'string' && sessionToken.length > 0) {
      const accessExp = jwtExpSeconds(sessionToken);
      req.user.federatedTokens = {
        ...(req.user.federatedTokens || {}),
        access_token: sessionToken,
        expires_at: accessExp || req.user.federatedTokens?.expires_at,
      };
    }
  }

  if (TRACE && req?.originalUrl?.startsWith('/api/')) {
    logger.warn('[cixRequestContext] oidc access token', {
      present: Boolean(oidcAccessToken),
      source,
      path: req.originalUrl,
    });
  }

  runWithCixContext({ oidcAccessToken }, () => next());
};
