import * as vscode from 'vscode';
import { FerretDiagnosticProvider } from './diagnostics';
import { FerretTreeDataProvider } from './treeView';
import { FerretCodeActionProvider } from './quickFixes';

let diagnosticProvider: FerretDiagnosticProvider;
let diagnosticCollection: vscode.DiagnosticCollection;
let treeDataProvider: FerretTreeDataProvider;

export function activate(context: vscode.ExtensionContext) {
    console.log('Ferret Security extension activated');

    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('ferret-security');
    context.subscriptions.push(diagnosticCollection);

    // Initialize providers
    diagnosticProvider = new FerretDiagnosticProvider(context, diagnosticCollection);
    treeDataProvider = new FerretTreeDataProvider();

    // Register tree view
    const treeView = vscode.window.createTreeView('ferretFindings', {
        treeDataProvider: treeDataProvider
    });
    context.subscriptions.push(treeView);

    // Register code action provider
    const codeActionProvider = new FerretCodeActionProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { pattern: '**/*.{md,json,yaml,yml,sh,bash,ts,js}' },
            codeActionProvider,
            {
                providedCodeActionKinds: FerretCodeActionProvider.providedCodeActionKinds
            }
        )
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('ferret.scan', async () => {
            await diagnosticProvider.scanWorkspace();
            treeDataProvider.refresh();
        }),
        vscode.commands.registerCommand('ferret.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await diagnosticProvider.scanDocument(editor.document);
                treeDataProvider.refresh();
            }
        }),
        vscode.commands.registerCommand('ferret.fix', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await codeActionProvider.applyAutoFixes(editor.document);
            }
        }),
        vscode.commands.registerCommand('ferret.showRules', async () => {
            await showRulesPanel(context);
        }),
        vscode.commands.registerCommand('ferret.clearFindings', () => {
            diagnosticCollection.clear();
            treeDataProvider.clear();
        }),
        vscode.commands.registerCommand('ferret.goToFinding', (uri: vscode.Uri, line: number) => {
            vscode.window.showTextDocument(uri).then(editor => {
                const position = new vscode.Position(line, 0);
                editor.selection = new vscode.Selection(position, position);
                editor.revealRange(new vscode.Range(position, position));
            });
        })
    );

    // File watchers
    const config = vscode.workspace.getConfiguration('ferret');

    if (config.get('scanOnSave')) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument(document => {
                if (diagnosticProvider.shouldScan(document)) {
                    diagnosticProvider.scanDocument(document);
                    treeDataProvider.refresh();
                }
            })
        );
    }

    if (config.get('scanOnType')) {
        let timeout: NodeJS.Timeout | undefined;
        context.subscriptions.push(
            vscode.workspace.onDidChangeTextDocument(event => {
                if (timeout) clearTimeout(timeout);
                timeout = setTimeout(() => {
                    if (diagnosticProvider.shouldScan(event.document)) {
                        diagnosticProvider.scanDocument(event.document);
                        treeDataProvider.refresh();
                    }
                }, 1000);
            })
        );
    }

    // Initial workspace scan
    if (vscode.workspace.workspaceFolders) {
        diagnosticProvider.scanWorkspace().then(() => {
            treeDataProvider.refresh();
        });
    }

    // Status bar
    const statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.text = '$(shield) Ferret';
    statusBarItem.command = 'ferret.scan';
    statusBarItem.tooltip = 'Click to scan workspace';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
}

async function showRulesPanel(context: vscode.ExtensionContext) {
    const panel = vscode.window.createWebviewPanel(
        'ferretRules',
        'Ferret Security Rules',
        vscode.ViewColumn.Two,
        {
            enableScripts: true
        }
    );

    panel.webview.html = getWebviewContent();
}

function getWebviewContent(): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: var(--vscode-font-family); padding: 20px; }
            .rule { border: 1px solid var(--vscode-panel-border); padding: 15px; margin: 10px 0; border-radius: 5px; }
            .rule-header { display: flex; justify-content: space-between; align-items: center; }
            .severity { padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
            .critical { background: #f44336; color: white; }
            .high { background: #ff9800; color: white; }
            .medium { background: #ffc107; color: black; }
            .low { background: #8bc34a; color: black; }
        </style>
    </head>
    <body>
        <h1>Ferret Security Rules</h1>
        <p>Active security rules for AI agent configuration scanning</p>
        <div id="rules">Loading...</div>
        <script>
            const vscode = acquireVsCodeApi();
            // Rules will be loaded dynamically
        </script>
    </body>
    </html>
    `;
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}
