/**
 * Ferret LSP Server
 * Provides diagnostics, hover, and completion for Ferret security scanning
 * across any LSP-capable editor.
 */

import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  TextDocumentSyncKind,
  InitializeResult,
  Diagnostic,
  DiagnosticSeverity,
  Position,
  Range,
  Hover,
  MarkupKind,
  CompletionItem,
  CompletionItemKind,
  CodeAction,
  CodeActionKind,
  Command,
  WorkspaceEdit,
} from 'vscode-languageserver/node.js';

import { TextDocument } from 'vscode-languageserver-textdocument';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';

const execFileAsync = promisify(execFile);

interface FerretFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  category: string;
  file: string;
  line: number;
  column?: number;
  match: string;
  remediation: string;
  riskScore: number;
}

const connection = createConnection(ProposedFeatures.all);
const documents: TextDocuments<TextDocument> = new TextDocuments(TextDocument);

let workspaceRoot: string | null = null;
let ferretPath = 'ferret'; // can be overridden by settings

// In development (inside the monorepo), prefer the local ferret binary
try {
  const localFerret = resolve(__dirname, '../../bin/ferret.js');
  const fs = await import('node:fs');
  if (fs.existsSync(localFerret)) {
    ferretPath = 'node';
    // We'll adjust runFerretScan to handle this
  }
} catch {}

connection.onInitialize((params: InitializeParams) => {
  workspaceRoot = params.workspaceFolders?.[0]?.uri
    ? new URL(params.workspaceFolders[0].uri).pathname
    : null;

  const result: InitializeResult = {
    capabilities: {
      textDocumentSync: {
        openClose: true,
        change: TextDocumentSyncKind.Incremental,
        willSave: false,
        willSaveWaitUntil: false,
        save: { includeText: false },
      },
      hoverProvider: true,
      completionProvider: {
        triggerCharacters: ['"', ':', '-', ' '],
        resolveProvider: false,
      },
      codeActionProvider: true,
      documentFormattingProvider: false,
      workspace: {
        workspaceFolders: {
          supported: true,
          changeNotifications: true,
        },
      },
    },
    serverInfo: {
      name: 'ferret-lsp',
      version: '0.1.0',
    },
  };
  return result;
});

connection.onInitialized(() => {
  connection.console.log('Ferret LSP server initialized');
});

// Allow clients to configure the ferret binary path
connection.onDidChangeConfiguration((change) => {
  const settings = change.settings?.ferret || {};
  if (settings.executablePath) {
    ferretPath = settings.executablePath;
  }
});

async function runFerretScan(filePath: string): Promise<FerretFinding[]> {
  // Preferred path: direct import (fast + reliable in monorepo)
  try {
    const { scan } = await import('../../dist/scanner/Scanner.js');
    const { DEFAULT_CONFIG } = await import('../../dist/types.js');

    const config = {
      ...DEFAULT_CONFIG,
      paths: [filePath],
      ci: true,
      verbose: false,
      configOnly: false,
      marketplaceMode: 'off' as const,
      // Force scanning of the exact file the editor has open
      ignore: ['**/.git/**', '**/node_modules/**'],
    };

    const result = await scan(config as any);
    return result.findings.map((f: any) => ({
      ruleId: f.ruleId,
      ruleName: f.ruleName,
      severity: f.severity,
      category: f.category,
      file: f.file,
      line: f.line,
      column: f.column,
      match: f.match,
      remediation: f.remediation,
      riskScore: f.riskScore,
    }));
  } catch (directErr: any) {
    connection.console.log(`Direct scan failed for ${filePath}, falling back to CLI: ${directErr.message}`);
  }

  // Fallback: spawn the CLI
  try {
    let cmd = ferretPath;
    let args = ['check', '--format', 'json', filePath];

    const localFerret = resolve(__dirname, '../../bin/ferret.js');
    const fs = await import('node:fs/promises');
    try {
      await fs.access(localFerret);
      cmd = process.execPath;
      args = [localFerret, 'check', '--format', 'json', filePath];
    } catch {}

    const { stdout } = await execFileAsync(cmd, args, {
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const parsed = JSON.parse(stdout);
    if (parsed.findings && Array.isArray(parsed.findings)) {
      return parsed.findings as FerretFinding[];
    }
    return [];
  } catch (err: any) {
    connection.console.error(`Ferret scan failed for ${filePath}: ${err.message ?? err}`);
    return [];
  }
}

function severityToDiagnosticSeverity(sev: string): DiagnosticSeverity {
  switch (sev.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return DiagnosticSeverity.Error;
    case 'MEDIUM':
      return DiagnosticSeverity.Warning;
    default:
      return DiagnosticSeverity.Information;
  }
}

async function publishDiagnosticsForDocument(document: TextDocument) {
  // document.uri is a string (e.g. file:///path/to/file)
  const uriStr: string = document.uri;
  const filePath = uriStr.replace(/^file:\/\//, '');

  // For open documents in the editor, prefer fast in-memory scanning when possible
  let findings: FerretFinding[] = [];

  try {
    // Try direct in-memory pattern matching for speed and reliability
    const { matchRules } = await import('../../dist/scanner/PatternMatcher.js');
    const { getRulesForScan } = await import('../../dist/rules/index.js');

    const allRules = getRulesForScan(
      ['injection', 'credentials', 'exfiltration', 'backdoors', 'supply-chain', 'permissions', 'persistence', 'obfuscation', 'ai-specific'],
      ['CRITICAL', 'HIGH', 'MEDIUM']
    );

    const syntheticFile = {
      path: filePath,
      relativePath: filePath.split('/').pop() || filePath,
      type: (filePath.endsWith('.md') ? 'md' : filePath.endsWith('.json') ? 'json' : 'md') as any,
      component: 'ai-config-md' as any,
      size: document.getText().length,
      modified: new Date(),
    };

    const rawFindings = matchRules(allRules, syntheticFile as any, document.getText(), { contextLines: 1 });

    findings = rawFindings.map(f => ({
      ruleId: f.ruleId,
      ruleName: f.ruleName,
      severity: f.severity,
      category: f.category,
      file: filePath,
      line: f.line,
      column: f.column,
      match: f.match,
      remediation: f.remediation,
      riskScore: f.riskScore,
    }));
  } catch {
    // Fallback to full scanner
    findings = await runFerretScan(filePath);
  }

  const diagnostics: Diagnostic[] = findings.map((f) => {
    const line = Math.max(0, (f.line ?? 1) - 1);
    const col = Math.max(0, (f.column ?? 1) - 1);

    const diagnostic: Diagnostic = {
      severity: severityToDiagnosticSeverity(f.severity),
      range: Range.create(Position.create(line, col), Position.create(line, col + Math.max(1, f.match.length))),
      message: `${f.ruleId}: ${f.ruleName} — ${f.remediation}`,
      source: 'ferret-lsp',
      code: f.ruleId,
      data: {
        category: f.category,
        riskScore: f.riskScore,
        remediation: f.remediation,
      },
    };
    return diagnostic;
  });

  connection.sendDiagnostics({
    uri: document.uri,
    diagnostics,
  });
}

// Document events
documents.onDidOpen(async (event) => {
  await publishDiagnosticsForDocument(event.document);
});

documents.onDidChangeContent(async (event) => {
  // Debounce in real implementation; for v1 we scan on every change (editors usually throttle)
  await publishDiagnosticsForDocument(event.document);
});

documents.onDidSave(async (event) => {
  await publishDiagnosticsForDocument(event.document);
});

// Simple word range extractor (since TextDocument from lsp lib doesn't have getWordRangeAtPosition)
function getWordRangeAtPosition(doc: TextDocument, position: Position): Range | null {
  const text = doc.getText();
  const lines = text.split(/\r?\n/);
  const lineText = lines[position.line] || '';
  const char = position.character;

  // Find word boundaries
  let start = char;
  let end = char;
  const wordChars = /[A-Z0-9-]/i;

  while (start > 0 && wordChars.test(lineText[start - 1])) start--;
  while (end < lineText.length && wordChars.test(lineText[end])) end++;

  if (start === end) return null;

  return Range.create(Position.create(position.line, start), Position.create(position.line, end));
}

// Hover provider — show rich rule information
connection.onHover(async (params) => {
  const document = documents.get(params.textDocument.uri);
  if (!document) return null;

  const position = params.position;
  const wordRange = getWordRangeAtPosition(document, position);
  if (!wordRange) return null;

  const word = document.getText(wordRange).toUpperCase();

  // Treat hovered word as a rule ID (e.g. INJ-003, CRED-001)
  if (/^[A-Z]+-\d{3}$/.test(word)) {
    try {
      // Prefer direct import for speed and richer output (works when ferret-lsp is run from monorepo or linked)
      const { getRuleById } = await import('../../dist/rules/index.js');
      const rule = getRuleById(word);
      if (rule) {
        const md = [
          `**${rule.id}** — ${rule.name}`,
          '',
          `**Severity:** ${rule.severity}  |  **Category:** ${rule.category}`,
          '',
          rule.description,
          '',
          `**Remediation:** ${rule.remediation}`,
          '',
          rule.references.length > 0 ? '**References:**\n' + rule.references.map((r: string) => `- ${r}`).join('\n') : '',
        ].filter(Boolean).join('\n');

        return {
          contents: { kind: MarkupKind.Markdown, value: md },
        } as Hover;
      }
    } catch {
      // Fall back to CLI if direct import fails (e.g. separate install)
    }

    // Fallback: shell out
    try {
      const { stdout } = await execFileAsync(ferretPath, ['rules', 'show', word], { timeout: 5000 });
      return {
        contents: { kind: MarkupKind.Markdown, value: '```\n' + stdout + '\n```' },
      } as Hover;
    } catch {
      // ignore
    }
  }

  return null;
});

// Code Actions (Quick Fixes for security findings) - with actual document edits
connection.onCodeAction((params) => {
  const actions: (Command | CodeAction)[] = [];
  const document = documents.get(params.textDocument.uri);

  for (const diagnostic of params.context.diagnostics) {
    if (diagnostic.source !== 'ferret-lsp') continue;

    const ruleId = typeof diagnostic.code === 'string' ? diagnostic.code : '';
    const line = diagnostic.range.start.line;

    // High-value action: Insert a ferret-ignore comment above the finding
    if (document) {
      const edit: WorkspaceEdit = {
        changes: {
          [params.textDocument.uri]: [
            {
              range: Range.create(Math.max(0, line), 0, Math.max(0, line), 0),
              newText: `<!-- ferret-ignore ${ruleId} -->\n`,
            },
          ],
        },
      };

      actions.push({
        title: `Ignore ${ruleId} (insert ferret-ignore comment)`,
        kind: CodeActionKind.QuickFix,
        diagnostics: [diagnostic],
        edit,
        isPreferred: true,
      });
    }

    // Command fallback (for clients that don't support workspace edits well)
    actions.push({
      title: `Log remediation for ${ruleId}`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [diagnostic],
      command: {
        title: 'Show remediation',
        command: 'ferret.showRemediation',
        arguments: [ruleId, diagnostic.message],
      },
    });
  }

  return actions;
});

// Completion for .ferretrc.json, custom rules, and rule IDs
connection.onCompletion(async () => {
  const baseItems: CompletionItem[] = [
    { label: 'CRITICAL', kind: CompletionItemKind.Enum, detail: 'Severity' },
    { label: 'HIGH', kind: CompletionItemKind.Enum, detail: 'Severity' },
    { label: 'MEDIUM', kind: CompletionItemKind.Enum, detail: 'Severity' },
    { label: 'LOW', kind: CompletionItemKind.Enum, detail: 'Severity' },
    { label: 'injection', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'credentials', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'exfiltration', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'backdoors', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'permissions', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'persistence', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'supply-chain', kind: CompletionItemKind.Enum, detail: 'Category' },
    { label: 'ai-specific', kind: CompletionItemKind.Enum, detail: 'Category' },
  ];

  // Try to provide real rule IDs for better DX when editing rules files
  try {
    const { getAllRules } = await import('../../dist/rules/index.js');
    const rules = getAllRules();
    const ruleCompletions = rules.slice(0, 30).map(rule => ({
      label: rule.id,
      kind: CompletionItemKind.Constant,
      detail: rule.name,
      documentation: rule.description,
    }));
    baseItems.push(...ruleCompletions);
  } catch {
    // ignore — fallback to base list
  }

  return baseItems;
});

// Make the documents manager listen on the connection
documents.listen(connection);

// Start listening
connection.listen();
connection.console.log('Ferret LSP server listening on stdio');
