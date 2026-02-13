const { logger, registerModelPlugin } = require('@librechat/data-schemas');
const { encryptStrings, decryptStrings } = require('../server/services/CixVaultService');

const CIPHER_PREFIX = 'cixvault:v1:';
const TRACE = String(process.env.CIX_VAULT_TRACE || '').toLowerCase() === 'true';
const INSTALLED = Symbol.for('cixVaultEncryption.installed');

function shouldDecrypt(value) {
  return typeof value === 'string' && value.startsWith(CIPHER_PREFIX);
}

function asJSONString(value) {
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value);
}

function setValue(target, field, value) {
  if (!target) {
    return;
  }
  target[field] = value;
}

function applyDecrypted(target, field, plaintext, isJSON, wrapArray) {
  if (!target) {
    return;
  }
  if (!isJSON) {
    target[field] = plaintext;
    return;
  }
  try {
    target[field] = JSON.parse(plaintext);
  } catch {
    target[field] = plaintext;
  }

  if (wrapArray && Array.isArray(target[field]) === false) {
    // `wrapArray` fields always decrypt back into an array payload (e.g. Message.content).
    // If parsing somehow resulted in a non-array, keep it as-is (fail-soft).
  }
}

async function encryptObjectFields(obj, stringFields, jsonFields) {
  if (!obj || typeof obj !== 'object') {
    return;
  }

  /** @type {{ field: string, isJSON: boolean, wrapArray: boolean, value: string }[]} */
  const items = [];

  for (const field of stringFields) {
    if (obj[field] == null) {
      continue;
    }
    items.push({ field, isJSON: false, wrapArray: false, value: String(obj[field]) });
  }
  for (const jf of jsonFields) {
    const field = jf?.name;
    if (!field) {
      continue;
    }
    if (obj[field] == null) {
      continue;
    }
    items.push({ field, isJSON: true, wrapArray: jf.wrapArray === true, value: asJSONString(obj[field]) });
  }

  if (items.length === 0) {
    return;
  }

  if (TRACE) {
    logger.warn('[cixVaultEncryption] encryptObjectFields', {
      fieldCount: items.length,
      fields: items.map((x) => x.field),
    });
  }

  let enc;
  try {
    enc = await encryptStrings(items.map((x) => x.value));
  } catch (err) {
    logger.error('[cixVaultEncryption] encryptStrings failed', err);
    throw err;
  }
  for (let i = 0; i < items.length; i++) {
    const v = enc[i];
    setValue(obj, items[i].field, items[i].wrapArray ? [v] : v);
  }
}

function getUpdateContainers(update) {
  if (!update || typeof update !== 'object') {
    return [];
  }

  const containers = [update];
  if (update.$set && typeof update.$set === 'object') {
    containers.push(update.$set);
  }
  if (update.$setOnInsert && typeof update.$setOnInsert === 'object') {
    containers.push(update.$setOnInsert);
  }
  return containers;
}

async function encryptQueryUpdate(query, stringFields, jsonFields) {
  if (!query || typeof query.getUpdate !== 'function') {
    if (TRACE) {
      logger.warn('[cixVaultEncryption] encryptQueryUpdate: no getUpdate (skipping)', {
        hasQuery: Boolean(query),
        queryType: typeof query,
      });
    }
    return;
  }
  const update = query.getUpdate();
  if (!update) {
    return;
  }
  const containers = getUpdateContainers(update);
  for (const c of containers) {
    await encryptObjectFields(c, stringFields, jsonFields);
  }
  query.setUpdate(update);
}

async function decryptDocs(docs, stringFields, jsonFields) {
  if (!Array.isArray(docs) || docs.length === 0) {
    return;
  }

  /** @type {{ doc: any, field: string, isJSON: boolean, wrapArray: boolean, value: string }[]} */
  const items = [];
  for (const doc of docs) {
    if (!doc) {
      continue;
    }

    for (const field of stringFields) {
      const v = doc[field];
      if (shouldDecrypt(v)) {
        items.push({ doc, field, isJSON: false, wrapArray: false, value: v });
      }
    }
    for (const jf of jsonFields) {
      const field = jf?.name;
      if (!field) {
        continue;
      }

      const v = doc[field];
      const wrapArray = jf.wrapArray === true;

      if (wrapArray && Array.isArray(v) && v.length === 1 && shouldDecrypt(v[0])) {
        items.push({ doc, field, isJSON: true, wrapArray: true, value: v[0] });
      } else if (shouldDecrypt(v)) {
        items.push({ doc, field, isJSON: true, wrapArray: false, value: v });
      }
    }
  }

  if (items.length === 0) {
    return;
  }

  if (TRACE) {
    logger.warn('[cixVaultEncryption] decryptDocs', {
      itemCount: items.length,
    });
  }

  let dec;
  try {
    dec = await decryptStrings(items.map((x) => x.value));
  } catch (err) {
    logger.error('[cixVaultEncryption] decryptStrings failed', err);
    throw err;
  }
  for (let i = 0; i < items.length; i++) {
    applyDecrypted(items[i].doc, items[i].field, dec[i], items[i].isJSON, items[i].wrapArray);
  }
}

function installForSchema(schema, modelName, spec) {
  if (!schema) {
    return;
  }

  const stringFields = spec?.stringFields || [];
  const jsonFields = spec?.jsonFields || [];

  const installedSet = schema[INSTALLED] instanceof Set ? schema[INSTALLED] : new Set();
  if (installedSet.has(modelName)) {
    return;
  }
  installedSet.add(modelName);
  schema[INSTALLED] = installedSet;

  if (TRACE) {
    logger.warn('[cixVaultEncryption] installForSchema', { model: modelName });
  }

  schema.pre('save', async function () {
    if (TRACE) {
      logger.warn('[cixVaultEncryption] hook pre save', { model: modelName });
    }
    await encryptObjectFields(this, stringFields, jsonFields);
  });

  // NOTE: `Model.create()` / `insertMany()` do not trigger `save` middleware.
  // We add explicit support to avoid storing plaintext when bulk inserts are used.
  schema.pre('insertMany', function (next, docs) {
    if (TRACE) {
      logger.warn('[cixVaultEncryption] hook pre insertMany', {
        model: modelName,
        docCount: Array.isArray(docs) ? docs.length : 0,
      });
    }
    if (!Array.isArray(docs) || docs.length === 0) {
      return next();
    }
    Promise.all(docs.map((d) => encryptObjectFields(d, stringFields, jsonFields)))
      .then(() => next())
      .catch(next);
  });

  schema.pre('findOneAndUpdate', async function () {
    if (TRACE) {
      const update = typeof this.getUpdate === 'function' ? this.getUpdate() : undefined;
      logger.warn('[cixVaultEncryption] hook pre findOneAndUpdate', {
        model: modelName,
        updateType: Array.isArray(update) ? 'array' : typeof update,
        updateKeys: update && !Array.isArray(update) && typeof update === 'object' ? Object.keys(update) : undefined,
      });
    }
    await encryptQueryUpdate(this, stringFields, jsonFields);
  });
  schema.pre('findOneAndReplace', async function () {
    if (TRACE) {
      const update = typeof this.getUpdate === 'function' ? this.getUpdate() : undefined;
      logger.warn('[cixVaultEncryption] hook pre findOneAndReplace', {
        model: modelName,
        updateType: Array.isArray(update) ? 'array' : typeof update,
        updateKeys: update && !Array.isArray(update) && typeof update === 'object' ? Object.keys(update) : undefined,
      });
    }
    await encryptQueryUpdate(this, stringFields, jsonFields);
  });
  schema.pre('updateOne', async function () {
    if (TRACE) {
      const update = typeof this.getUpdate === 'function' ? this.getUpdate() : undefined;
      logger.warn('[cixVaultEncryption] hook pre updateOne', {
        model: modelName,
        updateType: Array.isArray(update) ? 'array' : typeof update,
        updateKeys: update && !Array.isArray(update) && typeof update === 'object' ? Object.keys(update) : undefined,
      });
    }
    await encryptQueryUpdate(this, stringFields, jsonFields);
  });
  schema.pre('updateMany', async function () {
    if (TRACE) {
      const update = typeof this.getUpdate === 'function' ? this.getUpdate() : undefined;
      logger.warn('[cixVaultEncryption] hook pre updateMany', {
        model: modelName,
        updateType: Array.isArray(update) ? 'array' : typeof update,
        updateKeys: update && !Array.isArray(update) && typeof update === 'object' ? Object.keys(update) : undefined,
      });
    }
    await encryptQueryUpdate(this, stringFields, jsonFields);
  });
  schema.pre('replaceOne', async function () {
    if (TRACE) {
      const update = typeof this.getUpdate === 'function' ? this.getUpdate() : undefined;
      logger.warn('[cixVaultEncryption] hook pre replaceOne', {
        model: modelName,
        updateType: Array.isArray(update) ? 'array' : typeof update,
        updateKeys: update && !Array.isArray(update) && typeof update === 'object' ? Object.keys(update) : undefined,
      });
    }
    await encryptQueryUpdate(this, stringFields, jsonFields);
  });

  schema.post('find', async function (docs) {
    await decryptDocs(docs, stringFields, jsonFields);
  });
  schema.post('findOne', async function (doc) {
    if (!doc) {
      return;
    }
    await decryptDocs([doc], stringFields, jsonFields);
  });
  schema.post('findOneAndUpdate', async function (doc) {
    if (!doc) {
      return;
    }
    await decryptDocs([doc], stringFields, jsonFields);
  });
  schema.post('findOneAndReplace', async function (doc) {
    if (!doc) {
      return;
    }
    await decryptDocs([doc], stringFields, jsonFields);
  });
}

function registerCixVaultEncryption() {
  if (!process.env.CIX_VAULT_URL) {
    logger.warn('[cixVaultEncryption] CIX_VAULT_URL not set; encryption disabled');
    return;
  }
  if (typeof registerModelPlugin !== 'function') {
    logger.error('[cixVaultEncryption] registerModelPlugin is not available (data-schemas too old?)');
    return;
  }

  registerModelPlugin('Message', (schema) =>
    installForSchema(schema, 'Message', {
      stringFields: ['text', 'summary'],
      jsonFields: [{ name: 'content', wrapArray: true }],
    }),
  );
  registerModelPlugin('File', (schema) =>
    installForSchema(schema, 'File', {
      stringFields: ['text'],
      jsonFields: [],
    }),
  );
  registerModelPlugin('ToolCall', (schema) =>
    installForSchema(schema, 'ToolCall', {
      stringFields: [],
      jsonFields: [{ name: 'result' }, { name: 'attachments' }],
    }),
  );
  registerModelPlugin('MemoryEntry', (schema) =>
    installForSchema(schema, 'MemoryEntry', {
      stringFields: ['value'],
      jsonFields: [],
    }),
  );

  // LibreChat runs with NODE_ENV=production by default in docker, and its logger defaults to `warn`.
  // Log at `warn` so operators can confirm encryption is active via container logs.
  logger.warn('[cixVaultEncryption] Registered (Message/File/ToolCall/MemoryEntry)');
}

module.exports = { registerCixVaultEncryption };
