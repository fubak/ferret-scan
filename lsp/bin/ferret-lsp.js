#!/usr/bin/env node
/**
 * Ferret LSP launcher
 * Starts the Language Server on stdio.
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const serverPath = resolve(__dirname, '../dist/server.js');

// Dynamic import so it works with ESM
import(serverPath).catch((err) => {
  console.error('Failed to start Ferret LSP server:', err);
  process.exit(1);
});
