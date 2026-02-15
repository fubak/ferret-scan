import * as vscode from 'vscode';

export class FerretCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'ferret-security') continue;

            const code = diagnostic.code as string;

            // Add quick fixes based on rule type
            if (code && code.startsWith('CRED-')) {
                actions.push(this.createRemoveCredentialAction(document, diagnostic));
                actions.push(this.createMoveToEnvAction(document, diagnostic));
            }

            if (code && code.startsWith('INJ-')) {
                actions.push(this.createRemoveInjectionAction(document, diagnostic));
            }

            if (code && code.startsWith('EXFIL-')) {
                actions.push(this.createRemoveExfiltrationAction(document, diagnostic));
            }

            // Generic suppress finding action
            actions.push(this.createSuppressFindingAction(document, diagnostic));
        }

        return actions;
    }

    private createRemoveCredentialAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Remove hardcoded credential',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];
        action.isPreferred = true;

        const edit = new vscode.WorkspaceEdit();
        edit.replace(document.uri, diagnostic.range, '[REDACTED]');
        action.edit = edit;

        return action;
    }

    private createMoveToEnvAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Move to environment variable',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        edit.replace(
            document.uri,
            diagnostic.range,
            'process.env.API_KEY || "YOUR_API_KEY"'
        );
        action.edit = edit;

        return action;
    }

    private createRemoveInjectionAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Remove prompt injection pattern',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];
        action.isPreferred = true;

        const edit = new vscode.WorkspaceEdit();
        edit.delete(document.uri, diagnostic.range);
        action.edit = edit;

        return action;
    }

    private createRemoveExfiltrationAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Remove data exfiltration code',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];
        action.isPreferred = true;

        const edit = new vscode.WorkspaceEdit();
        edit.delete(document.uri, diagnostic.range);
        action.edit = edit;

        return action;
    }

    private createSuppressFindingAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Suppress this finding',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const line = diagnostic.range.start.line;
        const lineText = document.lineAt(line).text;
        const indent = lineText.match(/^\s*/)?.[0] || '';

        const edit = new vscode.WorkspaceEdit();
        const position = new vscode.Position(line, 0);
        edit.insert(
            document.uri,
            position,
            `${indent}// ferret-ignore ${diagnostic.code}\n`
        );
        action.edit = edit;

        return action;
    }

    async applyAutoFixes(document: vscode.TextDocument): Promise<void> {
        const diagnostics = vscode.languages.getDiagnostics(document.uri);
        const ferretDiagnostics = diagnostics.filter(d => d.source === 'ferret-security');

        if (ferretDiagnostics.length === 0) {
            vscode.window.showInformationMessage('No Ferret findings to fix');
            return;
        }

        const result = await vscode.window.showQuickPick(
            ['Remove all credentials', 'Remove all injections', 'Suppress all findings'],
            { placeHolder: 'Select auto-fix action' }
        );

        if (!result) return;

        const edit = new vscode.WorkspaceEdit();

        for (const diagnostic of ferretDiagnostics) {
            const code = diagnostic.code as string;

            if (result === 'Remove all credentials' && code?.startsWith('CRED-')) {
                edit.replace(document.uri, diagnostic.range, '[REDACTED]');
            } else if (result === 'Remove all injections' && code?.startsWith('INJ-')) {
                edit.delete(document.uri, diagnostic.range);
            } else if (result === 'Suppress all findings') {
                const line = diagnostic.range.start.line;
                const lineText = document.lineAt(line).text;
                const indent = lineText.match(/^\s*/)?.[0] || '';
                const position = new vscode.Position(line, 0);
                edit.insert(document.uri, position, `${indent}// ferret-ignore ${code}\n`);
            }
        }

        await vscode.workspace.applyEdit(edit);
        vscode.window.showInformationMessage(`Applied ${result}`);
    }
}
