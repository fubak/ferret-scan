/**
 * Capability Mapping Tests
 */

import { detectAgentType } from '../features/capabilityMapping.js';

describe('detectAgentType', () => {
  it('detects claude-code from .claude path', () => {
    expect(detectAgentType('/home/user/.claude/agents/test.md')).toBe('claude-code');
  });

  it('detects claude-code from CLAUDE.md', () => {
    expect(detectAgentType('/project/CLAUDE.md')).toBe('claude-code');
  });

  it('detects claude-code from claude.json', () => {
    expect(detectAgentType('/project/claude.json')).toBe('claude-code');
  });

  it('detects cursor from .cursorrules', () => {
    expect(detectAgentType('/project/.cursorrules')).toBe('cursor');
  });

  it('detects cursor from .cursor directory', () => {
    expect(detectAgentType('/project/.cursor/settings.json')).toBe('cursor');
  });

  it('detects windsurf from .windsurfrules', () => {
    expect(detectAgentType('/project/.windsurfrules')).toBe('windsurf');
  });

  it('detects continue from .continuerc', () => {
    expect(detectAgentType('/project/.continuerc')).toBe('continue');
  });

  it('detects continue from .continuerc path', () => {
    expect(detectAgentType('/project/.continuerc')).toBe('continue');
  });

  it('detects aider from .aider.conf.yml', () => {
    expect(detectAgentType('/project/.aider.conf.yml')).toBe('aider');
  });

  it('detects cline from .clinerules', () => {
    expect(detectAgentType('/project/.clinerules')).toBe('cline');
  });

  it('detects mcp from .mcp.json', () => {
    expect(detectAgentType('/project/.mcp.json')).toBe('mcp');
  });

  it('detects mcp from mcp.json', () => {
    expect(detectAgentType('/project/mcp.json')).toBe('mcp');
  });

  it('returns null for unknown file', () => {
    expect(detectAgentType('/project/some-random-file.txt')).toBeNull();
  });

  it('returns null for generic config file', () => {
    expect(detectAgentType('/project/config.yaml')).toBeNull();
  });
});
