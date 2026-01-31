/**
 * Indicator Matcher - Matches content against threat intelligence indicators
 * Provides fast lookup and matching of IoCs against scanned content
 */

import type {
  ThreatDatabase,
  ThreatIndicator,
  IndicatorType
} from './ThreatFeed.js';
import type {
  Finding,
  DiscoveredFile,
  ContextLine
} from '../types.js';
import logger from '../utils/logger.js';

/**
 * Threat intelligence finding
 */
export interface ThreatIntelFinding extends Finding {
  /** Matched threat indicator */
  threatIndicator: ThreatIndicator;
  /** Match confidence (0-100) */
  matchConfidence: number;
  /** Additional threat context */
  threatContext: {
    indicatorType: IndicatorType;
    threatSource: string;
    firstSeen: string;
    lastSeen: string;
    threatTags: string[];
  };
}

/**
 * Matcher configuration
 */
interface MatcherConfig {
  /** Minimum confidence threshold for matches */
  minConfidence: number;
  /** Whether to match patterns (can be expensive) */
  enablePatternMatching: boolean;
  /** Maximum number of matches per file */
  maxMatchesPerFile: number;
}

/**
 * Default matcher configuration
 */
const DEFAULT_CONFIG: MatcherConfig = {
  minConfidence: 50,
  enablePatternMatching: true,
  maxMatchesPerFile: 100
};

/**
 * Pre-compiled pattern cache for performance
 */
const patternCache = new Map<string, RegExp>();

/**
 * Get or create compiled regex pattern
 */
function getCompiledPattern(pattern: string): RegExp {
  if (!patternCache.has(pattern)) {
    try {
      const regex = new RegExp(pattern, 'gi');
      patternCache.set(pattern, regex);
    } catch (error) {
      logger.warn(`Invalid regex pattern: ${pattern}`);
      // Return a regex that never matches
      patternCache.set(pattern, /(?!.*)/);
    }
  }

  return patternCache.get(pattern)!;
}

/**
 * Create context lines for threat intel finding
 */
function createThreatContext(
  _file: DiscoveredFile,
  content: string,
  line: number,
  contextLines: number = 3
): ContextLine[] {
  const lines = content.split('\n');
  const start = Math.max(0, line - contextLines);
  const end = Math.min(lines.length, line + contextLines + 1);

  const context: ContextLine[] = [];
  for (let i = start; i < end; i++) {
    context.push({
      lineNumber: i + 1,
      content: lines[i] || '',
      isMatch: i === line
    });
  }

  return context;
}

/**
 * Calculate match confidence based on context and indicator confidence
 */
function calculateMatchConfidence(
  indicator: ThreatIndicator,
  matchContext: {
    exactMatch: boolean;
    fileType: string;
    component: string;
  }
): number {
  let confidence = indicator.confidence;

  // Boost confidence for exact matches
  if (matchContext.exactMatch) {
    confidence = Math.min(100, confidence + 10);
  }

  // Adjust based on file context
  if (matchContext.component === 'hook' || matchContext.component === 'skill') {
    confidence = Math.min(100, confidence + 5);
  }

  // Adjust based on file type relevance
  if (indicator.type === 'package' && matchContext.fileType === 'json') {
    confidence = Math.min(100, confidence + 5);
  }

  return confidence;
}

/**
 * Match domain indicators in content
 */
function matchDomains(
  content: string,
  indicators: ThreatIndicator[],
  file: DiscoveredFile,
  config: MatcherConfig
): ThreatIntelFinding[] {
  const findings: ThreatIntelFinding[] = [];
  const lines = content.split('\n');

  for (const indicator of indicators) {
    if (indicator.type !== 'domain') continue;

    const domain = indicator.value;
    const regex = new RegExp(`\\b${domain.replace('.', '\\.')}\\b`, 'gi');

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex] || '';
      const match = regex.test(line);

      if (match && findings.length < config.maxMatchesPerFile) {
        const confidence = calculateMatchConfidence(indicator, {
          exactMatch: true,
          fileType: file.type,
          component: file.component
        });

        if (confidence >= config.minConfidence) {
          findings.push(createThreatIntelFinding(
            indicator,
            file,
            content,
            lineIndex + 1,
            domain,
            confidence
          ));
        }
      }
    }
  }

  return findings;
}

/**
 * Match package indicators in content
 */
function matchPackages(
  content: string,
  indicators: ThreatIndicator[],
  file: DiscoveredFile,
  config: MatcherConfig
): ThreatIntelFinding[] {
  const findings: ThreatIntelFinding[] = [];
  const lines = content.split('\n');

  for (const indicator of indicators) {
    if (indicator.type !== 'package') continue;

    const packageName = indicator.value;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex] || '';

      // Simple string matching for package names
      if (line.toLowerCase().includes(packageName.toLowerCase()) &&
          findings.length < config.maxMatchesPerFile) {

        const confidence = calculateMatchConfidence(indicator, {
          exactMatch: true,
          fileType: file.type,
          component: file.component
        });

        if (confidence >= config.minConfidence) {
          findings.push(createThreatIntelFinding(
            indicator,
            file,
            content,
            lineIndex + 1,
            packageName,
            confidence
          ));
        }
      }
    }
  }

  return findings;
}

/**
 * Match pattern indicators in content
 */
function matchPatterns(
  content: string,
  indicators: ThreatIndicator[],
  file: DiscoveredFile,
  config: MatcherConfig
): ThreatIntelFinding[] {
  if (!config.enablePatternMatching) {
    return [];
  }

  const findings: ThreatIntelFinding[] = [];
  const lines = content.split('\n');

  for (const indicator of indicators) {
    if (indicator.type !== 'pattern') continue;

    const regex = getCompiledPattern(indicator.value);

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex] || '';
      const match = regex.test(line);

      if (match && findings.length < config.maxMatchesPerFile) {
        const confidence = calculateMatchConfidence(indicator, {
          exactMatch: false,
          fileType: file.type,
          component: file.component
        });

        if (confidence >= config.minConfidence) {
          findings.push(createThreatIntelFinding(
            indicator,
            file,
            content,
            lineIndex + 1,
            indicator.value,
            confidence
          ));
        }
      }
    }
  }

  return findings;
}

/**
 * Match hash indicators in content
 */
function matchHashes(
  content: string,
  indicators: ThreatIndicator[],
  file: DiscoveredFile,
  config: MatcherConfig
): ThreatIntelFinding[] {
  const findings: ThreatIntelFinding[] = [];

  for (const indicator of indicators) {
    if (indicator.type !== 'hash') continue;

    const hash = indicator.value.toLowerCase();

    // Simple hash matching
    if (content.toLowerCase().includes(hash)) {
      const lines = content.split('\n');

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex] || '';

        if (line.toLowerCase().includes(hash) && findings.length < config.maxMatchesPerFile) {
          const confidence = calculateMatchConfidence(indicator, {
            exactMatch: true,
            fileType: file.type,
            component: file.component
          });

          if (confidence >= config.minConfidence) {
            findings.push(createThreatIntelFinding(
              indicator,
              file,
              content,
              lineIndex + 1,
              hash,
              confidence
            ));
          }
          break; // Only match once per file
        }
      }
    }
  }

  return findings;
}

/**
 * Create threat intelligence finding
 */
function createThreatIntelFinding(
  indicator: ThreatIndicator,
  file: DiscoveredFile,
  content: string,
  line: number,
  match: string,
  confidence: number
): ThreatIntelFinding {
  return {
    ruleId: `THREAT-${indicator.type.toUpperCase()}-${indicator.source.toUpperCase().replace(/-/g, '_')}`,
    ruleName: `Threat Intelligence: ${indicator.description}`,
    severity: indicator.severity === 'critical' ? 'CRITICAL' :
              indicator.severity === 'high' ? 'HIGH' :
              indicator.severity === 'medium' ? 'MEDIUM' : 'LOW',
    category: 'behavioral',
    file: file.path,
    relativePath: file.relativePath,
    line,
    match,
    context: createThreatContext(file, content, line - 1),
    remediation: `Review and remove this ${indicator.type} indicator. ${indicator.description}`,
    metadata: {
      threatIntelligence: true,
      indicator,
      threatSource: indicator.source,
      threatTags: indicator.tags
    },
    timestamp: new Date(),
    riskScore: confidence,
    // Threat-specific fields
    threatIndicator: indicator,
    matchConfidence: confidence,
    threatContext: {
      indicatorType: indicator.type,
      threatSource: indicator.source,
      firstSeen: indicator.firstSeen,
      lastSeen: indicator.lastSeen,
      threatTags: indicator.tags
    }
  };
}

/**
 * Match all indicators against content
 */
export function matchIndicators(
  db: ThreatDatabase,
  file: DiscoveredFile,
  content: string,
  config: Partial<MatcherConfig> = {}
): ThreatIntelFinding[] {
  const matcherConfig = { ...DEFAULT_CONFIG, ...config };
  const findings: ThreatIntelFinding[] = [];

  try {
    logger.debug(`Matching threat indicators against ${file.relativePath}`);

    // Get enabled indicators with minimum confidence
    const eligibleIndicators = db.indicators.filter(indicator =>
      indicator.confidence >= matcherConfig.minConfidence
    );

    if (eligibleIndicators.length === 0) {
      return findings;
    }

    // Group indicators by type for efficient matching
    const indicatorsByType = new Map<IndicatorType, ThreatIndicator[]>();
    for (const indicator of eligibleIndicators) {
      if (!indicatorsByType.has(indicator.type)) {
        indicatorsByType.set(indicator.type, []);
      }
      indicatorsByType.get(indicator.type)!.push(indicator);
    }

    // Match each indicator type
    for (const [type, indicators] of indicatorsByType) {
      switch (type) {
        case 'domain':
        case 'url':
          findings.push(...matchDomains(content, indicators, file, matcherConfig));
          break;
        case 'package':
          findings.push(...matchPackages(content, indicators, file, matcherConfig));
          break;
        case 'pattern':
          findings.push(...matchPatterns(content, indicators, file, matcherConfig));
          break;
        case 'hash':
          findings.push(...matchHashes(content, indicators, file, matcherConfig));
          break;
        // Additional types can be added here
      }

      // Respect max matches limit
      if (findings.length >= matcherConfig.maxMatchesPerFile) {
        break;
      }
    }

    logger.debug(`Found ${findings.length} threat intelligence matches in ${file.relativePath}`);

  } catch (error) {
    logger.error(`Error matching threat indicators in ${file.relativePath}: ${error instanceof Error ? error.message : String(error)}`);
  }

  return findings;
}

/**
 * Check if threat intelligence matching should be performed
 */
export function shouldMatchIndicators(
  _file: DiscoveredFile,
  config: { threatIntel: boolean }
): boolean {
  return config.threatIntel;
}

export default {
  matchIndicators,
  shouldMatchIndicators
};