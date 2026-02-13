const cookies = require('cookie');
const { isEnabled } = require('@librechat/api');
const { logger } = require('@librechat/data-schemas');
const { extractBearerToken, runWithCixContext } = require('~/server/services/cixContext');

const TRACE = String(process.env.CIX_VAULT_TRACE || '').toLowerCase() === 'true';

module.exports = function cixRequestContext(req, _res, next) {
  const rawHeader = req?.headers?.authorization ?? req?.headers?.Authorization;
  let oidcAccessToken = extractBearerToken(rawHeader);
  let source = oidcAccessToken ? 'auth_header' : 'none';

  // For OpenID users, prefer the server-side stored access token.
  // This is required for request types that can't set custom headers (e.g. EventSource/SSE),
  // and avoids large-cookie issues when OPENID_REUSE_TOKENS is enabled.
  if (!oidcAccessToken && isEnabled(process.env.OPENID_REUSE_TOKENS)) {
    const sessionToken = req.session?.openidTokens?.accessToken;
    if (typeof sessionToken === 'string' && sessionToken.length > 0) {
      oidcAccessToken = sessionToken;
      source = 'session';
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

  if (TRACE && req?.originalUrl?.startsWith('/api/')) {
    logger.warn('[cixRequestContext] oidc access token', {
      present: Boolean(oidcAccessToken),
      source,
      path: req.originalUrl,
    });
  }

  runWithCixContext({ oidcAccessToken }, () => next());
};
