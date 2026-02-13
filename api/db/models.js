const mongoose = require('mongoose');
const { createModels } = require('@librechat/data-schemas');
const { registerCixVaultEncryption } = require('./cixVaultEncryption');

registerCixVaultEncryption();

const models = createModels(mongoose);

module.exports = { ...models };
