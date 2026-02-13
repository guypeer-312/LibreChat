const { connectDb } = require('./connect');
const indexSync = require('./indexSync');

// Ensure DB models are registered (and CIX encryption hooks are installed) before the app starts.
require('./models');

module.exports = { connectDb, indexSync };
