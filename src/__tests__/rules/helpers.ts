import { matchRule } from '../../scanner/PatternMatcher.js';
import type { DiscoveredFile, Rule } from '../../types.js';

export const mockFile = (
  type = 'md',
  component = 'skill',
): DiscoveredFile => ({
  path: '/test/file.' + type,
  relativePath: 'file.' + type,
  type: type as DiscoveredFile['type'],
  component: component as DiscoveredFile['component'],
  size: 1000,
  modified: new Date(),
});

export function findRule(rules: Rule[], id: string): Rule {
  const rule = rules.find(r => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

export const opts = { contextLines: 2 };
export { matchRule };
