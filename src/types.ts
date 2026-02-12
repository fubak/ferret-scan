/**
 * Ferret-Scan Type Definitions
 * Security scanner for AI CLI configurations
 */

/** Severity levels for security findings */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Threat categories detected by the scanner */
export type ThreatCategory =
  | 'exfiltration'
  | 'credentials'
  | 'injection'
  | 'backdoors'
  | 'supply-chain'
  | 'permissions'
  | 'persistence'
  | 'obfuscation'
  | 'ai-specific'
  | 'advanced-hiding'
  | 'behavioral';

/** Component types that can be analyzed */
export type ComponentType =
  | 'skill'
  | 'agent'
  | 'hook'
  | 'plugin'
  | 'mcp'
  | 'settings'
  | 'ai-config-md'
  | 'rules-file';

/** File types supported for analysis */
export type FileType = 'md' | 'sh' | 'bash' | 'zsh' | 'json' | 'yaml' | 'yml' | 'ts' | 'js' | 'tsx' | 'jsx';

/** Semantic pattern for AST-based analysis */
export interface SemanticPattern {
  /** Pattern type */
  type: 'function-call' | 'property-access' | 'dynamic-import' | 'eval-chain' | 'object-structure';
  /** Pattern identifier */
  pattern: string;
  /** Required context */
  context?: string[];
  /** Minimum confidence level (0-1) */
  confidence?: number;
}

/** Correlation rule for multi-file analysis */
export interface CorrelationRule {
  /** Rule identifier */
  id: string;
  /** Description of the correlation pattern */
  description: string;
  /** File patterns that must be present */
  filePatterns: string[];
  /** Content patterns that must exist across files */
  contentPatterns: string[];
  /** Maximum distance between related files (directory levels) */
  maxDistance?: number;
}

/** Remediation fix definition */
export interface RemediationFix {
  /** Fix type */
  type: 'replace' | 'remove' | 'quarantine' | 'permission-change';
  /** Fix description */
  description: string;
  /** Pattern to match for fix */
  pattern: string;
  /** Replacement content (for replace type) */
  replacement?: string;
  /** Safety level (0=dangerous, 1=safe) */
  safety: number;
  /** Whether fix can be applied automatically */
  automatic: boolean;
}

/** A single security rule definition */
export interface Rule {
  /** Unique rule identifier (e.g., "EXFIL-001") */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Category of threat this rule detects */
  category: ThreatCategory;
  /** Severity level of findings from this rule */
  severity: Severity;
  /** Detailed description of what this rule detects */
  description: string;
  /** Regex patterns to match against content */
  patterns: RegExp[];
  /** File types this rule applies to */
  fileTypes: FileType[];
  /** Component types this rule applies to */
  components: ComponentType[];
  /** Recommended remediation steps */
  remediation: string;
  /** Reference URLs for more information */
  references: string[];
  /** Whether this rule is enabled by default */
  enabled: boolean;
  /** Patterns that exclude a match (false positive filters) */
  excludePatterns?: RegExp[];
  /** Context patterns that must also be present for a match */
  requireContext?: RegExp[];
  /** Context patterns that invalidate a match (documentation indicators) */
  excludeContext?: RegExp[];
  /** Minimum match length to trigger (filters short matches) */
  minMatchLength?: number;
  /** Semantic patterns for AST-based detection */
  semanticPatterns?: SemanticPattern[];
  /** Correlation rules for multi-file analysis */
  correlationRules?: CorrelationRule[];
  /** Available fixes for this rule */
  remediationFixes?: RemediationFix[];
}

/** AST node information for semantic findings */
export interface ASTNodeInfo {
  /** Node type (function, property, etc.) */
  nodeType: string;
  /** Node name/identifier */
  name?: string;
  /** Parent context */
  parent?: string;
  /** Child nodes */
  children?: string[];
}

/** Semantic context for advanced analysis */
export interface SemanticContext {
  /** Function/method name */
  functionName?: string;
  /** Variable names in scope */
  variables?: string[];
  /** Import statements */
  imports?: string[];
  /** Call chain */
  callChain?: string[];
}

/** A security finding from the scanner */
export interface Finding {
  /** Rule ID that triggered this finding */
  ruleId: string;
  /** Rule name */
  ruleName: string;
  /** Severity level */
  severity: Severity;
  /** Category of threat */
  category: ThreatCategory;
  /** Full path to the file */
  file: string;
  /** Relative path for display */
  relativePath: string;
  /** Line number where the finding occurred */
  line: number;
  /** Column number (if available) */
  column?: number;
  /** The matched text */
  match: string;
  /** Context lines around the finding */
  context: ContextLine[];
  /** Remediation recommendation */
  remediation: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Timestamp when finding was detected */
  timestamp: Date;
  /** Risk score (0-100) */
  riskScore: number;
}

/** Semantic finding with AST information */
export interface SemanticFinding extends Finding {
  /** AST node information */
  astNode?: ASTNodeInfo;
  /** Semantic context */
  semanticContext?: SemanticContext;
  /** Confidence level (0-1) */
  confidence: number;
}

/** Correlation finding across multiple files */
export interface CorrelationFinding extends Finding {
  /** Related files in the attack pattern */
  relatedFiles: string[];
  /** Attack pattern name */
  attackPattern: string;
  /** Risk vectors identified */
  riskVectors: string[];
  /** Correlation strength (0-1) */
  correlationStrength: number;
}

/** A line of context around a finding */
export interface ContextLine {
  /** Line number */
  lineNumber: number;
  /** Line content */
  content: string;
  /** Whether this is the matched line */
  isMatch: boolean;
}

/** A discovered file to be analyzed */
export interface DiscoveredFile {
  /** Full absolute path */
  path: string;
  /** Relative path from scan root */
  relativePath: string;
  /** File extension/type */
  type: FileType;
  /** Detected component type */
  component: ComponentType;
  /** File size in bytes */
  size: number;
  /** Last modified timestamp */
  modified: Date;
}

/** Results from a complete scan */
export interface ScanResult {
  /** Whether the scan completed successfully */
  success: boolean;
  /** Timestamp when scan started */
  startTime: Date;
  /** Timestamp when scan completed */
  endTime: Date;
  /** Duration in milliseconds */
  duration: number;
  /** Paths that were scanned */
  scannedPaths: string[];
  /** Total files discovered */
  totalFiles: number;
  /** Files that were actually analyzed */
  analyzedFiles: number;
  /** Files that were skipped (ignored) */
  skippedFiles: number;
  /** All findings from the scan */
  findings: Finding[];
  /** Findings grouped by severity */
  findingsBySeverity: Record<Severity, Finding[]>;
  /** Findings grouped by category */
  findingsByCategory: Record<ThreatCategory, Finding[]>;
  /** Overall risk score (0-100) */
  overallRiskScore: number;
  /** Summary statistics */
  summary: ScanSummary;
  /** Any errors encountered during scanning */
  errors: ScanError[];
}

/** Summary statistics for a scan */
export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/** An error encountered during scanning */
export interface ScanError {
  /** File path where error occurred */
  file?: string;
  /** Error message */
  message: string;
  /** Error code */
  code?: string;
  /** Whether the error was fatal */
  fatal: boolean;
}

/** Scanner configuration options */
export interface ScannerConfig {
  /** Paths to scan */
  paths: string[];
  /** Severity levels to report */
  severities: Severity[];
  /** Categories to scan for */
  categories: ThreatCategory[];
  /** Patterns to ignore (glob) */
  ignore: string[];
  /** Minimum severity to fail on */
  failOn: Severity;
  /** Enable watch mode */
  watch: boolean;
  /** Enable threat intelligence */
  threatIntel: boolean;
  /** Enable semantic analysis */
  semanticAnalysis: boolean;
  /** Enable cross-file correlation */
  correlationAnalysis: boolean;
  /** Enable auto-remediation */
  autoRemediation: boolean;
  /** Context lines to show around findings */
  contextLines: number;
  /** Maximum file size to scan (bytes) */
  maxFileSize: number;
  /** Output format */
  format: OutputFormat;
  /** Output file path */
  outputFile?: string;
  /** Verbose output */
  verbose: boolean;
  /** CI mode (simplified output) */
  ci: boolean;
}

/** Supported output formats */
export type OutputFormat = 'console' | 'json' | 'sarif' | 'html' | 'csv';

/** CLI options passed from command line */
export interface CliOptions {
  path?: string;
  format?: OutputFormat;
  severity?: string;
  categories?: string;
  failOn?: string;
  output?: string;
  watch?: boolean;
  ci?: boolean;
  verbose?: boolean;
  threatIntel?: boolean;
  semanticAnalysis?: boolean;
  correlationAnalysis?: boolean;
  autoRemediation?: boolean;
  config?: string;
}

/** Configuration file structure (.ferretrc.json) */
export interface ConfigFile {
  severity?: Severity[];
  categories?: ThreatCategory[];
  ignore?: string[];
  failOn?: Severity;
  threatIntelligence?: {
    enabled: boolean;
    feeds?: string[];
    updateInterval?: string;
  };
  remediation?: {
    autoFix?: boolean;
    quarantineDir?: string;
    backupOriginals?: boolean;
  };
}

/** Default scanner configuration */
export const DEFAULT_CONFIG: ScannerConfig = {
  paths: [],
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  categories: [
    'exfiltration',
    'credentials',
    'injection',
    'backdoors',
    'supply-chain',
    'permissions',
    'persistence',
    'obfuscation',
    'ai-specific',
    'advanced-hiding',
    'behavioral',
  ],
  ignore: ['**/node_modules/**', '**/.git/**'],
  failOn: 'HIGH',
  watch: false,
  threatIntel: false,
  semanticAnalysis: false,
  correlationAnalysis: false,
  autoRemediation: false,
  contextLines: 3,
  maxFileSize: 10 * 1024 * 1024, // 10MB
  format: 'console',
  verbose: false,
  ci: false,
};

/** Severity weights for risk scoring */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 100,
  HIGH: 75,
  MEDIUM: 50,
  LOW: 25,
  INFO: 10,
};

/** Severity order for sorting */
export const SEVERITY_ORDER: Severity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
];
