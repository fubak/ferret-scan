/**
 * MCP Server Trust Scoring
 * Evaluates the security posture of an MCP server configuration.
 */

export interface McpTrustResult {
  score: number;
  trustLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'CRITICAL';
  flags: string[];
}

// Known suspicious package names / name fragments
const SUSPICIOUS_NAMES = [
  'shadow', 'stealer', 'exfil', 'beacon', 'c2-', '-c2',
  'keylog', 'implant', 'dropper', 'exploit',
];

/**
 * Score an MCP server configuration entry.
 *
 * @param serverConfig - A single MCP server config object (value from `mcpServers` map)
 * @returns Trust score (0-100), trust level, and list of flags
 */
export function scoreMcpServer(serverConfig: unknown): McpTrustResult {
  const flags: string[] = [];
  let score = 100;

  if (typeof serverConfig !== 'object' || serverConfig === null) {
    return { score: 0, trustLevel: 'CRITICAL', flags: ['Invalid config object'] };
  }

  const cfg = serverConfig as Record<string, unknown>;

  // Insecure transport
  const transport = cfg['transport'];
  if (transport === 'http' || transport === 'sse') {
    score -= 30;
    flags.push(`Insecure transport: '${transport}' — prefer stdio or wss`);
  }

  // Plain HTTP URL
  const url = typeof cfg['url'] === 'string' ? cfg['url'] : '';
  if (url.startsWith('http://')) {
    score -= 25;
    flags.push('Plain HTTP URL — credentials and tool calls are transmitted in cleartext');
  }

  // Unpinned npx command
  const command = typeof cfg['command'] === 'string' ? cfg['command'] : '';
  if (command === 'npx' || command.endsWith('/npx')) {
    const args: string[] = Array.isArray(cfg['args']) ? (cfg['args'] as string[]) : [];
    const firstArg = args[0] ?? '';
    if (firstArg && !firstArg.includes('@') && !firstArg.startsWith('-')) {
      score -= 20;
      flags.push(`Unpinned npx package '${firstArg}' — pin to a specific version to prevent rug pulls`);
    }
  }

  // Dangerous flags in args
  const args: string[] = Array.isArray(cfg['args']) ? (cfg['args'] as string[]) : [];
  for (const arg of args) {
    if (typeof arg === 'string' && (arg.includes('--allow-all') || arg.includes('--dangerously-skip'))) {
      score -= 30;
      flags.push(`Dangerous arg '${arg}' — bypasses MCP safety checks`);
    }
  }

  // Suspicious name
  const name = typeof cfg['name'] === 'string' ? cfg['name'].toLowerCase() : '';
  const pkg = args.find(a => typeof a === 'string' && !a.startsWith('-')) ?? '';
  const combined = `${name} ${pkg}`.toLowerCase();
  for (const pattern of SUSPICIOUS_NAMES) {
    if (combined.includes(pattern)) {
      score -= 50;
      flags.push(`Name matches suspicious pattern '${pattern}'`);
      break;
    }
  }

  const clampedScore = Math.max(0, Math.min(100, score));
  return {
    score: clampedScore,
    trustLevel: clampedScore >= 80 ? 'HIGH'
      : clampedScore >= 60 ? 'MEDIUM'
      : clampedScore >= 40 ? 'LOW'
      : 'CRITICAL',
    flags,
  };
}
