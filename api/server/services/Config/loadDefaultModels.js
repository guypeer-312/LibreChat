const { logger } = require('@librechat/data-schemas');
const { isEnabled } = require('@librechat/api');
const { EModelEndpoint, getEnabledEndpoints } = require('librechat-data-provider');
const {
  getAnthropicModels,
  getBedrockModels,
  getOpenAIModels,
  getGoogleModels,
} = require('@librechat/api');
const { getAppConfig } = require('./app');

/**
 * @param {ServerRequest} req
 * @returns {string | undefined}
 */
function getBearerTokenFromRequest(req) {
  if (!isEnabled(process.env.CIX_LLM_GATEWAY_OIDC)) {
    return undefined;
  }

  const header = req?.headers?.authorization || req?.headers?.Authorization;
  if (!header || typeof header !== 'string') {
    return undefined;
  }

  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return undefined;
  }

  return match[1]?.trim();
}

/**
 * Loads the default models for the application.
 * @async
 * @function
 * @param {ServerRequest} req - The Express request object.
 */
async function loadDefaultModels(req) {
  try {
    const enabledEndpoints = getEnabledEndpoints();
    const appConfig = req.config ?? (await getAppConfig({ role: req.user?.role }));
    const vertexConfig = appConfig?.endpoints?.[EModelEndpoint.anthropic]?.vertexConfig;
    const openAIApiKey = getBearerTokenFromRequest(req);
    const user = req.user?.id;

    const results = {
      [EModelEndpoint.openAI]: [],
      [EModelEndpoint.google]: [],
      [EModelEndpoint.anthropic]: [],
      [EModelEndpoint.azureOpenAI]: [],
      [EModelEndpoint.assistants]: [],
      [EModelEndpoint.azureAssistants]: [],
      [EModelEndpoint.bedrock]: [],
    };

    const tasks = [];

    if (enabledEndpoints.includes(EModelEndpoint.openAI)) {
      tasks.push(
        getOpenAIModels({ user, openAIApiKey })
          .then((models) => {
            results[EModelEndpoint.openAI] = models;
          })
          .catch((error) => {
            logger.error('Error fetching OpenAI models:', error);
          }),
      );
    }

    if (enabledEndpoints.includes(EModelEndpoint.anthropic)) {
      tasks.push(
        getAnthropicModels({ user, vertexModels: vertexConfig?.modelNames })
          .then((models) => {
            results[EModelEndpoint.anthropic] = models;
          })
          .catch((error) => {
            logger.error('Error fetching Anthropic models:', error);
          }),
      );
    }

    if (enabledEndpoints.includes(EModelEndpoint.azureOpenAI)) {
      tasks.push(
        getOpenAIModels({ user, azure: true })
          .then((models) => {
            results[EModelEndpoint.azureOpenAI] = models;
          })
          .catch((error) => {
            logger.error('Error fetching Azure OpenAI models:', error);
          }),
      );
    }

    if (enabledEndpoints.includes(EModelEndpoint.assistants)) {
      tasks.push(
        getOpenAIModels({ assistants: true, openAIApiKey })
          .then((models) => {
            results[EModelEndpoint.assistants] = models;
          })
          .catch((error) => {
            logger.error('Error fetching OpenAI Assistants API models:', error);
          }),
      );
    }

    if (enabledEndpoints.includes(EModelEndpoint.azureAssistants)) {
      tasks.push(
        getOpenAIModels({ azure: true, openAIApiKey })
          .then((models) => {
            results[EModelEndpoint.azureAssistants] = models;
          })
          .catch((error) => {
            logger.error('Error fetching Azure OpenAI Assistants API models:', error);
          }),
      );
    }

    if (enabledEndpoints.includes(EModelEndpoint.google)) {
      tasks.push(
        Promise.resolve(getGoogleModels())
          .then((models) => {
            results[EModelEndpoint.google] = models;
          })
          .catch((error) => {
            logger.error('Error getting Google models:', error);
          }),
      );
    }

    if (enabledEndpoints.includes(EModelEndpoint.bedrock)) {
      tasks.push(
        Promise.resolve(getBedrockModels())
          .then((models) => {
            results[EModelEndpoint.bedrock] = models;
          })
          .catch((error) => {
            logger.error('Error getting Bedrock models:', error);
          }),
      );
    }

    await Promise.all(tasks);

    return results;
  } catch (error) {
    logger.error('Error fetching default models:', error);
    throw new Error(`Failed to load default models: ${error.message}`);
  }
}

module.exports = loadDefaultModels;
