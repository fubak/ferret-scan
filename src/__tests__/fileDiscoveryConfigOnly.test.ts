/**
 * FileDiscovery configOnly mode tests
 * Tests the configOnly-specific branches in isAnalyzableFile
 */

import { discoverFiles } from '../scanner/FileDiscovery.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const CONFIG_ONLY_OPTIONS = {
  maxFileSize: 1024 * 1024,
  ignore: [],
  configOnly: true,
  marketplaceMode: 'configs' as const,
};

describe('discoverFiles - configOnly mode', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-configonly-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('includes .env files in configOnly mode', async () => {
    fs.writeFileSync(path.join(tmpDir, '.env'), 'SECRET=value123');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const envFiles = result.files.filter(f => f.path.includes('.env'));
    expect(envFiles.length).toBeGreaterThan(0);
  });

  it('includes .env.local in configOnly mode', async () => {
    fs.writeFileSync(path.join(tmpDir, '.env.local'), 'LOCAL=test');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const envFiles = result.files.filter(f => f.path.includes('.env.local'));
    expect(envFiles.length).toBeGreaterThan(0);
  });

  it('includes secrets.env in configOnly mode', async () => {
    fs.writeFileSync(path.join(tmpDir, 'secrets.env'), 'API_KEY=secret');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const envFiles = result.files.filter(f => f.path.includes('secrets.env'));
    expect(envFiles.length).toBeGreaterThan(0);
  });

  it('includes .claude/agents/ files in configOnly mode', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'my-agent.md'), '# My Agent');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const agentFiles = result.files.filter(f => f.path.includes('agents'));
    expect(agentFiles.length).toBeGreaterThan(0);
  });

  it('includes .claude/hooks/ files in configOnly mode', async () => {
    const hooksDir = path.join(tmpDir, '.claude', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(path.join(hooksDir, 'my-hook.sh'), '#!/bin/bash\necho test');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const hookFiles = result.files.filter(f => f.path.includes('hooks'));
    expect(hookFiles.length).toBeGreaterThan(0);
  });

  it('includes .claude/skills/ files in configOnly mode', async () => {
    const skillsDir = path.join(tmpDir, '.claude', 'skills');
    fs.mkdirSync(skillsDir, { recursive: true });
    fs.writeFileSync(path.join(skillsDir, 'my-skill.md'), '# My Skill');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const skillFiles = result.files.filter(f => f.path.includes('skills'));
    expect(skillFiles.length).toBeGreaterThan(0);
  });

  it('includes .claude/commands/ files in configOnly mode', async () => {
    const commandsDir = path.join(tmpDir, '.claude', 'commands');
    fs.mkdirSync(commandsDir, { recursive: true });
    fs.writeFileSync(path.join(commandsDir, 'my-cmd.md'), '# My Command');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const cmdFiles = result.files.filter(f => f.path.includes('commands'));
    expect(cmdFiles.length).toBeGreaterThan(0);
  });

  it('includes .claude settings.json in configOnly mode', async () => {
    const claudeDir = path.join(tmpDir, '.claude');
    fs.mkdirSync(claudeDir);
    fs.writeFileSync(path.join(claudeDir, 'settings.json'), '{"allowedTools":[]}');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const settingsFiles = result.files.filter(f => f.path.includes('settings.json'));
    expect(settingsFiles.length).toBeGreaterThan(0);
  });

  it('excludes .claude/plugins/cache/ in configOnly mode', async () => {
    const cacheDir = path.join(tmpDir, '.claude', 'plugins', 'cache');
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, 'plugin.md'), '# Cached Plugin');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const cacheFiles = result.files.filter(f => f.path.includes('plugins/cache'));
    expect(cacheFiles).toHaveLength(0);
  });

  it('excludes arbitrary .claude files in configOnly mode', async () => {
    const claudeDir = path.join(tmpDir, '.claude');
    fs.mkdirSync(claudeDir);
    fs.writeFileSync(path.join(claudeDir, 'random.txt'), 'random content');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const txtFiles = result.files.filter(f => f.path.includes('random.txt'));
    expect(txtFiles).toHaveLength(0);
  });

  it('excludes non-AI files in configOnly mode (default return false)', async () => {
    fs.writeFileSync(path.join(tmpDir, 'random-file.ts'), 'const x = 1;');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    // random TypeScript files outside known directories should be excluded
    const tsFiles = result.files.filter(f => f.path.includes('random-file.ts'));
    expect(tsFiles).toHaveLength(0);
  });

  it('handles marketplaceMode=off vs configs for .claude/plugins', async () => {
    const marketplaceDir = path.join(tmpDir, '.claude', 'plugins', 'marketplaces', 'testplugin', 'agents');
    fs.mkdirSync(marketplaceDir, { recursive: true });
    fs.writeFileSync(path.join(marketplaceDir, 'plugin-agent.md'), '# Plugin Agent');

    // marketplaceMode=off should exclude marketplace
    const resultOff = await discoverFiles([tmpDir], {
      ...CONFIG_ONLY_OPTIONS,
      marketplaceMode: 'off',
    });
    const offFiles = resultOff.files.filter(f => f.path.includes('marketplaces'));
    expect(offFiles).toHaveLength(0);
  });

  it('discovers files from .openclaw/agents/ in configOnly mode', async () => {
    const agentsDir = path.join(tmpDir, '.openclaw', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'my-agent.json'), '{}');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const agentFiles = result.files.filter(f => f.path.includes('.openclaw'));
    expect(agentFiles.length).toBeGreaterThan(0);
  });

  it('excludes .openclaw/workspace/ in configOnly mode', async () => {
    const workspaceDir = path.join(tmpDir, '.openclaw', 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });
    fs.writeFileSync(path.join(workspaceDir, 'data.json'), '{}');

    const result = await discoverFiles([tmpDir], CONFIG_ONLY_OPTIONS);
    const workspaceFiles = result.files.filter(f => f.path.includes('workspace'));
    expect(workspaceFiles).toHaveLength(0);
  });
});

describe('discoverFiles - marketplace mode variations', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-marketplace-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('excludes marketplace reference docs in "configs" mode', async () => {
    const refDir = path.join(tmpDir, '.claude', 'plugins', 'marketplaces', 'plugin1', 'references');
    fs.mkdirSync(refDir, { recursive: true });
    fs.writeFileSync(path.join(refDir, 'api.md'), '# API Reference');

    const result = await discoverFiles([tmpDir], {
      maxFileSize: 1024 * 1024,
      ignore: [],
      configOnly: false,
      marketplaceMode: 'configs',
    });
    const refFiles = result.files.filter(f => f.path.includes('references'));
    expect(refFiles).toHaveLength(0);
  });

  it('excludes low-signal readme.md from marketplace in "configs" mode', async () => {
    const pluginDir = path.join(tmpDir, '.claude', 'plugins', 'marketplaces', 'plugin1');
    fs.mkdirSync(pluginDir, { recursive: true });
    fs.writeFileSync(path.join(pluginDir, 'readme.md'), '# Plugin Readme');

    const result = await discoverFiles([tmpDir], {
      maxFileSize: 1024 * 1024,
      ignore: [],
      configOnly: false,
      marketplaceMode: 'configs',
    });
    const readmeFiles = result.files.filter(f => f.path.includes('readme.md'));
    expect(readmeFiles).toHaveLength(0);
  });

  it('includes all files in marketplace "all" mode', async () => {
    const pluginDir = path.join(tmpDir, '.claude', 'plugins', 'marketplaces', 'plugin1');
    fs.mkdirSync(pluginDir, { recursive: true });
    fs.writeFileSync(path.join(pluginDir, 'readme.md'), '# Plugin Readme');

    const result = await discoverFiles([tmpDir], {
      maxFileSize: 1024 * 1024,
      ignore: [],
      configOnly: false,
      marketplaceMode: 'all',
    });
    const readmeFiles = result.files.filter(f => f.path.includes('readme.md'));
    expect(readmeFiles.length).toBeGreaterThan(0);
  });

  it('excludes non-agent marketplace files in "off" mode', async () => {
    // In 'off' mode, marketplace ts/js files should be excluded (non-config types)
    const pluginDir = path.join(tmpDir, '.claude', 'plugins', 'marketplaces', 'plugin1');
    fs.mkdirSync(pluginDir, { recursive: true });
    fs.writeFileSync(path.join(pluginDir, 'index.ts'), '// code');

    const result = await discoverFiles([tmpDir], {
      maxFileSize: 1024 * 1024,
      ignore: [],
      configOnly: false,
      marketplaceMode: 'off',
    });
    const tsFiles = result.files.filter(f => f.path.includes('marketplaces') && f.type === 'ts');
    expect(tsFiles).toHaveLength(0);
  });
});
