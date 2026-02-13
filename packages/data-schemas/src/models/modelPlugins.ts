import type { Schema } from 'mongoose';

export type ModelPlugin = (schema: Schema, mongoose: typeof import('mongoose')) => void;

const pluginsByModelName = new Map<string, ModelPlugin[]>();
const appliedPlugins = new WeakMap<Schema, Set<ModelPlugin>>();

export function registerModelPlugin(modelName: string, plugin: ModelPlugin) {
  const name = (modelName || '').trim();
  if (!name) {
    throw new Error('modelName is required');
  }
  if (typeof plugin !== 'function') {
    throw new Error('plugin must be a function');
  }

  const existing = pluginsByModelName.get(name);
  if (existing) {
    existing.push(plugin);
    return;
  }

  pluginsByModelName.set(name, [plugin]);
}

export function applyModelPlugins(
  modelName: string,
  schema: Schema,
  mongoose: typeof import('mongoose'),
) {
  const name = (modelName || '').trim();
  if (!name) {
    return;
  }

  const plugins = pluginsByModelName.get(name);
  if (!plugins || plugins.length === 0) {
    return;
  }

  let applied = appliedPlugins.get(schema);
  if (!applied) {
    applied = new Set();
    appliedPlugins.set(schema, applied);
  }

  for (const plugin of plugins) {
    if (applied.has(plugin)) {
      continue;
    }
    plugin(schema, mongoose);
    applied.add(plugin);
  }
}

