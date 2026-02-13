import toolCallSchema, { IToolCallData } from '~/schema/toolCall';
import { applyModelPlugins } from './modelPlugins';

/**
 * Creates or returns the ToolCall model using the provided mongoose instance and schema
 */
export function createToolCallModel(mongoose: typeof import('mongoose')) {
  applyModelPlugins('ToolCall', toolCallSchema, mongoose);
  return mongoose.models.ToolCall || mongoose.model<IToolCallData>('ToolCall', toolCallSchema);
}
