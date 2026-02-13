import fileSchema from '~/schema/file';
import type { IMongoFile } from '~/types';
import { applyModelPlugins } from './modelPlugins';

/**
 * Creates or returns the File model using the provided mongoose instance and schema
 */
export function createFileModel(mongoose: typeof import('mongoose')) {
  applyModelPlugins('File', fileSchema, mongoose);
  return mongoose.models.File || mongoose.model<IMongoFile>('File', fileSchema);
}
