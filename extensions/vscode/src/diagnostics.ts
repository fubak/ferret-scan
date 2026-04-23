import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

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

interface FerretScanResult {
    success: boolean;
    findings: FerretFinding[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
}

export class FerretDiagnosticProvider {
    private config: vscode.WorkspaceConfiguration;
    private findingsCache = new Map<string, FerretFinding[]>();

    constructor(
        private context: vscode.ExtensionContext,
        private diagnostics: vscode.DiagnosticCollection
    ) {
        this.config = vscode.workspace.getConfiguration('ferret');
    }

    shouldScan(document: vscode.TextDocument): boolean {
        if (!this.config.get('enabled')) return false;

        const ext = path.extname(document.fileName);
        const supportedExts = ['.md', '.json', '.yaml', '.yml', '.sh', '.bash', '.ts', '.js'];

        return supportedExts.includes(ext) ||
               document.fileName.includes('.claude') ||
               document.fileName.includes('.cursor') ||
               document.fileName.includes('.windsurf');
    }

    async scanDocument(document: vscode.TextDocument): Promise<void> {
        if (!this.shouldScan(document)) return;

        try {
            const findings = await this.runFerretScan(document.uri.fsPath);
            this.findingsCache.set(document.uri.toString(), findings);
            this.updateDiagnostics(document.uri, findings);
        } catch (error) {
            console.error('Ferret scan error:', error);
            vscode.window.showErrorMessage(`Ferret scan failed: ${error}`);
        }
    }

    async scanWorkspace(): Promise<void> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) return;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Ferret Security Scan',
            cancellable: false
        }, async (progress) => {
            progress.report({ message: 'Scanning workspace...' });

            for (const folder of workspaceFolders) {
                try {
                    const findings = await this.runFerretScan(folder.uri.fsPath);

                    // Group findings by file
                    const findingsByFile = new Map<string, FerretFinding[]>();
                    for (const finding of findings) {
                        const fileUri = vscode.Uri.file(finding.file);
                        const existing = findingsByFile.get(fileUri.toString()) || [];
                        existing.push(finding);
                        findingsByFile.set(fileUri.toString(), existing);
                    }

                    // Update diagnostics for each file
                    for (const [uriStr, fileFindings] of findingsByFile) {
                        const uri = vscode.Uri.parse(uriStr);
                        this.findingsCache.set(uriStr, fileFindings);
                        this.updateDiagnostics(uri, fileFindings);
                    }

                    progress.report({
                        message: `Found ${findings.length} security issues`,
                        increment: 100
                    });
                } catch (error) {
                    console.error('Workspace scan error:', error);
                }
            }
        });
    }

    private async runFerretScan(filePath: string): Promise<FerretFinding[]> {
        const execPath = this.config.get('executablePath') as string || 'ferret';
        const severities = this.config.get('severity') as string[] || ['CRITICAL', 'HIGH', 'MEDIUM'];

        const args = [
            'scan',
            filePath,
            '--format', 'json',
            '--severity', severities.join(',')
        ];

        try {
            const { stdout, stderr } = await execFileAsync(execPath, args, {
                maxBuffer: 10 * 1024 * 1024, // 10MB
                timeout: 30000
            });

            if (stderr && !stderr.includes('[INFO]')) {
                console.warn('Ferret stderr:', stderr);
            }

            const result: FerretScanResult = JSON.parse(stdout);
            return result.findings || [];
        } catch (error: any) {
            // Exit code 1 means findings were found
            if (error.code === 1 && error.stdout) {
                try {
                    const result: FerretScanResult = JSON.parse(error.stdout);
                    return result.findings || [];
                } catch (parseError) {
                    console.error('Failed to parse Ferret output:', parseError);
                    return [];
                }
            }
            throw error;
        }
    }

    private updateDiagnostics(uri: vscode.Uri, findings: FerretFinding[]): void {
        const diagnostics: vscode.Diagnostic[] = findings.map(finding => {
            const line = Math.max(0, finding.line - 1);
            const range = new vscode.Range(
                new vscode.Position(line, finding.column || 0),
                new vscode.Position(line, (finding.column || 0) + finding.match.length)
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${finding.ruleId}] ${finding.ruleName}: ${finding.match}`,
                this.mapSeverity(finding.severity)
            );

            diagnostic.source = 'ferret-security';
            diagnostic.code = finding.ruleId;
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(uri, range),
                    `Remediation: ${finding.remediation}`
                )
            ];

            return diagnostic;
        });

        this.diagnostics.set(uri, diagnostics);
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toUpperCase()) {
            case 'CRITICAL':
            case 'HIGH':
                return vscode.DiagnosticSeverity.Error;
            case 'MEDIUM':
                return vscode.DiagnosticSeverity.Warning;
            case 'LOW':
                return vscode.DiagnosticSeverity.Information;
            case 'INFO':
                return vscode.DiagnosticSeverity.Hint;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    getFindings(uri: vscode.Uri): FerretFinding[] {
        return this.findingsCache.get(uri.toString()) || [];
    }

    getAllFindings(): Map<string, FerretFinding[]> {
        return this.findingsCache;
    }
}
