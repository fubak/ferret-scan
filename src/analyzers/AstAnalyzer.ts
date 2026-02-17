/**
 * AST Analyzer - TypeScript/JavaScript semantic analysis for security scanning
 * Analyzes code blocks in markdown and TypeScript configurations for complex patterns
 */

import type * as ts from 'typescript';
import type {
  SemanticFinding,
  SemanticPattern,
  ASTNodeInfo,
  SemanticContext,
  DiscoveredFile,
  Rule,
  ContextLine
} from '../types.js';
import logger from '../utils/logger.js';

let _ts: typeof import('typescript') | undefined;

async function getTS(): Promise<typeof import('typescript')> {
  if (!_ts) {
    try {
      _ts = await import('typescript');
    } catch {
      throw new Error(
        'The "typescript" package is required for semantic analysis. ' +
        'Install it with: npm install -D typescript'
      );
    }
  }
  return _ts;
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function matchesSymbolLike(text: string, symbol: string): boolean {
  // Match a function/property token within a dotted chain without substring false positives.
  // Examples:
  // - pattern "exec" should match "exec(" and "child_process.exec" but not "execute("
  // - pattern "axios" should match "axios.get" and "axios(" but not "myaxios"
  const trimmed = symbol.trim();
  if (!trimmed) return false;

  // Prefix-like patterns (e.g. "fs." or "process.env") used in some semantic rules.
  if (trimmed.endsWith('.')) {
    const base = trimmed.slice(0, -1);
    const escapedBase = escapeRegExp(base);
    return new RegExp(`(?:^|\\.)${escapedBase}\\.`).test(text);
  }
  if (trimmed.includes('.')) {
    const escapedPrefix = escapeRegExp(trimmed);
    return new RegExp(`(?:^|\\.)${escapedPrefix}(?:\\.|$)`).test(text);
  }

  const escaped = escapeRegExp(trimmed);
  const re = new RegExp(`(?:^|\\.)${escaped}(?:$|[^A-Za-z0-9_$])`);
  return re.test(text);
}

/**
 * Extract code blocks from markdown content
 */
function extractCodeBlocks(content: string): { code: string; language: string; line: number }[] {
  const codeBlocks: { code: string; language: string; line: number }[] = [];
  const lines = content.split('\n');

  let inCodeBlock = false;
  let currentBlock: string[] = [];
  let currentLanguage = '';
  let blockStartLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmedLine = line?.trim() ?? '';

    if (trimmedLine.startsWith('```')) {
      if (!inCodeBlock) {
        // Starting a code block
        inCodeBlock = true;
        currentLanguage = trimmedLine.slice(3).trim().toLowerCase();
        blockStartLine = i + 2; // +2 because we want the first line of actual code
        currentBlock = [];
      } else {
        // Ending a code block
        inCodeBlock = false;
        if (currentBlock.length > 0 && isAnalyzableLanguage(currentLanguage)) {
          codeBlocks.push({
            code: currentBlock.join('\n'),
            language: currentLanguage,
            line: blockStartLine || 1 // Ensure we have a valid line number
          });
        }
        currentBlock = [];
        currentLanguage = '';
      }
    } else if (inCodeBlock) {
      currentBlock.push(line ?? '');
    }
  }

  return codeBlocks;
}

/**
 * Check if language can be analyzed
 */
function isAnalyzableLanguage(language: string): boolean {
  const supportedLanguages = ['typescript', 'ts', 'javascript', 'js', 'jsx', 'tsx'];
  return supportedLanguages.includes(language);
}

/**
 * Create TypeScript AST from code
 */
function createAST(tsLib: typeof import('typescript'), code: string, fileName = 'analysis.ts'): ts.SourceFile {
  return tsLib.createSourceFile(
    fileName,
    code,
    tsLib.ScriptTarget.Latest,
    true,
    fileName?.endsWith('.tsx') ? tsLib.ScriptKind.TSX : tsLib.ScriptKind.TS
  );
}

/**
 * Extract semantic context from AST
 */
function extractSemanticContext(tsLib: typeof import('typescript'), sourceFile: ts.SourceFile): SemanticContext {
  const context: SemanticContext = {
    variables: [],
    imports: [],
    callChain: []
  };

  function visit(node: ts.Node): void {
    switch (node.kind) {
      case tsLib.SyntaxKind.ImportDeclaration: {
        const importDecl = node as ts.ImportDeclaration;
        if (importDecl.moduleSpecifier && tsLib.isStringLiteral(importDecl.moduleSpecifier)) {
          context.imports!.push(importDecl.moduleSpecifier.text);
        }
        break;
      }

      case tsLib.SyntaxKind.VariableDeclaration: {
        const varDecl = node as ts.VariableDeclaration;
        if (varDecl.name && tsLib.isIdentifier(varDecl.name)) {
          context.variables!.push(varDecl.name.text);
        }
        break;
      }

      case tsLib.SyntaxKind.CallExpression: {
        const callExpr = node as ts.CallExpression;
        const callText = callExpr.expression.getText(sourceFile);
        context.callChain!.push(callText);
        break;
      }
    }

    tsLib.forEachChild(node, visit);
  }

  visit(sourceFile);
  return context;
}

/**
 * Find security patterns in AST
 */
function findSecurityPatterns(
  tsLib: typeof import('typescript'),
  sourceFile: ts.SourceFile,
  patterns: SemanticPattern[]
): { pattern: SemanticPattern; node: ts.Node; confidence: number }[] {
  const matches: { pattern: SemanticPattern; node: ts.Node; confidence: number }[] = [];

  function visit(node: ts.Node): void {
    for (const pattern of patterns) {
      const match = matchSemanticPattern(tsLib, node, pattern, sourceFile);
      if (match) {
        matches.push({
          pattern,
          node,
          confidence: match.confidence
        });
      }
    }

    tsLib.forEachChild(node, visit);
  }

  visit(sourceFile);
  return matches;
}

/**
 * Match a semantic pattern against an AST node
 */
function matchSemanticPattern(
  tsLib: typeof import('typescript'),
  node: ts.Node,
  pattern: SemanticPattern,
  sourceFile: ts.SourceFile
): { confidence: number } | null {
  const nodeText = node.getText(sourceFile);
  let confidence = pattern.confidence ?? 0.8;

  switch (pattern.type) {
    case 'function-call':
      if (tsLib.isCallExpression(node)) {
        const functionName = node.expression.getText(sourceFile);
        if (matchesSymbolLike(functionName, pattern.pattern)) {
          return { confidence };
        }
      }
      break;

    case 'property-access':
      if (tsLib.isPropertyAccessExpression(node)) {
        const fullAccess = node.getText(sourceFile);
        if (matchesSymbolLike(fullAccess, pattern.pattern)) {
          return { confidence };
        }
      }
      break;

    case 'dynamic-import':
      if (tsLib.isCallExpression(node)) {
        if (node.expression.kind === tsLib.SyntaxKind.ImportKeyword) {
          const arg = node.arguments[0];
          if (arg && (tsLib.isStringLiteralLike(arg) || tsLib.isNoSubstitutionTemplateLiteral(arg))) {
            break;
          }

          if (pattern.pattern === 'dynamic-import' || nodeText.includes(pattern.pattern)) {
            confidence += 0.1;
            return { confidence };
          }
        }
      }
      break;

    case 'eval-chain':
      if (tsLib.isCallExpression(node) || tsLib.isNewExpression(node)) {
        const expr = node.expression;
        const target = pattern.pattern;

        if (tsLib.isIdentifier(expr) && expr.text === target) {
          confidence += 0.2;
          return { confidence };
        }

        if (tsLib.isPropertyAccessExpression(expr) && expr.name.text === target) {
          const receiver = expr.expression;
          if (tsLib.isIdentifier(receiver) && (receiver.text === 'globalThis' || receiver.text === 'window')) {
            confidence += 0.2;
            return { confidence };
          }
        }
      }
      break;

    case 'object-structure':
      if (tsLib.isObjectLiteralExpression(node)) {
        if (nodeText.includes(pattern.pattern)) {
          return { confidence };
        }
      }
      break;
  }

  return null;
}

/**
 * Create AST node info
 */
function createASTNodeInfo(tsLib: typeof import('typescript'), node: ts.Node, sourceFile: ts.SourceFile): ASTNodeInfo {
  const nodeName = getNodeName(tsLib, node);
  return {
    nodeType: tsLib.SyntaxKind[node.kind],
    ...(nodeName && { name: nodeName }),
    ...(node.parent && { parent: tsLib.SyntaxKind[node.parent.kind] }),
    children: node.getChildren(sourceFile).map(child => tsLib.SyntaxKind[child.kind])
  };
}

/**
 * Get node name/identifier
 */
function getNodeName(tsLib: typeof import('typescript'), node: ts.Node): string | undefined {
  if (tsLib.isIdentifier(node)) {
    return node.text;
  }
  if (tsLib.isFunctionDeclaration(node) && node.name) {
    return node.name.text;
  }
  if (tsLib.isVariableDeclaration(node) && tsLib.isIdentifier(node.name)) {
    return node.name.text;
  }
  return undefined;
}

/**
 * Get line and column from AST node
 */
function getPositionFromNode(node: ts.Node, sourceFile: ts.SourceFile): { line: number; column: number } {
  const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return {
    line: pos.line + 1, // Convert to 1-based
    column: pos.character + 1
  };
}

/**
 * Create context lines for semantic finding
 */
function createContextLines(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  contextLines = 3
): ContextLine[] {
  const text = sourceFile.getText();
  const lines = text.split('\n');
  const pos = getPositionFromNode(node, sourceFile);
  const matchLine = pos.line - 1; // Convert back to 0-based

  const start = Math.max(0, matchLine - contextLines);
  const end = Math.min(lines.length, matchLine + contextLines + 1);

  const context: ContextLine[] = [];
  for (let i = start; i < end; i++) {
    context.push({
      lineNumber: i + 1,
      content: lines[i] ?? '',
      isMatch: i === matchLine
    });
  }

  return context;
}

/**
 * Analyze a single file for semantic patterns
 */
export async function analyzeFile(
  file: DiscoveredFile,
  content: string,
  rules: Rule[]
): Promise<SemanticFinding[]> {
  const findings: SemanticFinding[] = [];

  try {
    // Get rules with semantic patterns
    const semanticRules = rules.filter(rule => rule.semanticPatterns && rule.semanticPatterns.length > 0);

    if (semanticRules.length === 0) {
      return findings;
    }

    const tsLib = await getTS();

    logger.debug(`AST analysis for ${file.relativePath} with ${semanticRules.length} semantic rules`);

    let codeBlocksToAnalyze: { code: string; language: string; line: number }[] = [];

    // Extract code blocks from markdown files
    if (file.type === 'md') {
      codeBlocksToAnalyze = extractCodeBlocks(content);
    } else if (['ts', 'js', 'tsx', 'jsx'].includes(file.type)) {
      // Analyze the entire file for TypeScript/JavaScript files
      codeBlocksToAnalyze = [{ code: content, language: file.type, line: 1 }];
    }

    // Analyze each code block
    for (const codeBlock of codeBlocksToAnalyze) {
      try {
        const sourceFile = createAST(tsLib, codeBlock.code, `${file.relativePath}_block_${codeBlock.line}.${codeBlock.language}`);
        const semanticContext = extractSemanticContext(tsLib, sourceFile);

        // Check each semantic rule
        for (const rule of semanticRules) {
          if (!rule.semanticPatterns) continue;

          const patternMatches = findSecurityPatterns(tsLib, sourceFile, rule.semanticPatterns);

          for (const match of patternMatches) {
            const position = getPositionFromNode(match.node, sourceFile);
            const astNodeInfo = createASTNodeInfo(tsLib, match.node, sourceFile);
            const contextLines = createContextLines(sourceFile, match.node, 3);

            const finding: SemanticFinding = {
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              category: rule.category,
              file: file.path,
              relativePath: file.relativePath,
              line: (codeBlock.line || 1) + position.line - 1, // Adjust for code block position
              column: position.column,
              match: match.node.getText(sourceFile).substring(0, 100), // Limit match length
              context: contextLines,
              remediation: rule.remediation,
              metadata: {
                semanticPattern: match.pattern,
                codeBlock: codeBlock.line,
                language: codeBlock.language
              },
              timestamp: new Date(),
              riskScore: Math.round(match.confidence * 100),
              astNode: astNodeInfo,
              semanticContext,
              confidence: match.confidence
            };

            findings.push(finding);
          }
        }
      } catch (error) {
        logger.warn(`Error analyzing code block at line ${codeBlock.line} in ${file.relativePath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

  } catch (error) {
    logger.error(`Error in semantic analysis for ${file.relativePath}: ${error instanceof Error ? error.message : String(error)}`);
  }

  return findings;
}

/**
 * Check if semantic analysis should be performed
 */
export function shouldAnalyze(file: DiscoveredFile, config: { semanticAnalysis: boolean; maxFileSize: number }): boolean {
  if (!config.semanticAnalysis) {
    return false;
  }

  // Skip files that are too large
  if (file.size > config.maxFileSize) {
    return false;
  }

  // Only analyze markdown and TypeScript/JavaScript files
  const supportedTypes = ['md', 'ts', 'js', 'tsx', 'jsx'];
  return supportedTypes.includes(file.type);
}

/**
 * Get memory usage for monitoring
 */
export function getMemoryUsage(): { used: number; total: number } {
  const memUsage = process.memoryUsage();
  return {
    used: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
    total: Math.round(memUsage.heapTotal / 1024 / 1024) // MB
  };
}

export default {
  analyzeFile,
  shouldAnalyze,
  getMemoryUsage
};
