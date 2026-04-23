import * as vscode from 'vscode';
import * as path from 'path';

export class FerretTreeDataProvider implements vscode.TreeDataProvider<FindingTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<FindingTreeItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private findings: Map<string, any[]> = new Map();

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.findings.clear();
        this.refresh();
    }

    setFindings(findings: Map<string, any[]>): void {
        this.findings = findings;
        this.refresh();
    }

    getTreeItem(element: FindingTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FindingTreeItem): Thenable<FindingTreeItem[]> {
        if (!element) {
            // Root level - show files with findings
            const items: FindingTreeItem[] = [];

            for (const [uriStr, fileFindings] of this.findings) {
                const uri = vscode.Uri.parse(uriStr);
                const fileName = path.basename(uri.fsPath);
                const workspaceFolder = vscode.workspace.getWorkspaceFolder(uri);
                const relativePath = workspaceFolder
                    ? path.relative(workspaceFolder.uri.fsPath, uri.fsPath)
                    : fileName;

                const item = new FindingTreeItem(
                    `${relativePath} (${fileFindings.length})`,
                    vscode.TreeItemCollapsibleState.Expanded,
                    'file',
                    uri
                );
                item.iconPath = new vscode.ThemeIcon('file');
                item.contextValue = 'file';
                items.push(item);
            }

            return Promise.resolve(items);
        } else if (element.contextValue === 'file' && element.resourceUri) {
            // Show findings for this file
            const fileFindings = this.findings.get(element.resourceUri.toString()) || [];
            const items = fileFindings.map(finding => {
                const item = new FindingTreeItem(
                    `[${finding.severity}] ${finding.ruleName}`,
                    vscode.TreeItemCollapsibleState.None,
                    'finding',
                    element.resourceUri,
                    finding.line
                );

                item.description = finding.ruleId;
                item.tooltip = new vscode.MarkdownString(
                    `**${finding.ruleName}**\n\n` +
                    `Severity: ${finding.severity}\n\n` +
                    `Match: \`${finding.match}\`\n\n` +
                    `Remediation: ${finding.remediation}`
                );

                item.iconPath = this.getSeverityIcon(finding.severity);
                item.contextValue = 'finding';

                item.command = {
                    command: 'ferret.goToFinding',
                    title: 'Go to Finding',
                    arguments: [element.resourceUri, finding.line - 1]
                };

                return item;
            });

            return Promise.resolve(items);
        }

        return Promise.resolve([]);
    }

    private getSeverityIcon(severity: string): vscode.ThemeIcon {
        switch (severity.toUpperCase()) {
            case 'CRITICAL':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'HIGH':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case 'MEDIUM':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            case 'LOW':
                return new vscode.ThemeIcon('symbol-misc');
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}

class FindingTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string,
        public readonly resourceUri?: vscode.Uri,
        public readonly line?: number
    ) {
        super(label, collapsibleState);
    }
}
