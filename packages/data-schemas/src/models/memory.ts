import memorySchema from '~/schema/memory';
import type { IMemoryEntry } from '~/types/memory';
import { applyModelPlugins } from './modelPlugins';

export function createMemoryModel(mongoose: typeof import('mongoose')) {
  applyModelPlugins('MemoryEntry', memorySchema, mongoose);
  return mongoose.models.MemoryEntry || mongoose.model<IMemoryEntry>('MemoryEntry', memorySchema);
}
