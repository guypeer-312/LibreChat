const { AsyncLocalStorage } = require('node:async_hooks');

const storage = new AsyncLocalStorage();

function extractBearerToken(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') {
    return undefined;
  }
  const match = headerValue.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || undefined;
}

function runWithCixContext(ctx, fn) {
  return storage.run(ctx, fn);
}

function getCixContext() {
  return storage.getStore();
}

function getOIDCAccessToken() {
  const ctx = getCixContext();
  return ctx?.oidcAccessToken;
}

module.exports = {
  extractBearerToken,
  runWithCixContext,
  getCixContext,
  getOIDCAccessToken,
};

