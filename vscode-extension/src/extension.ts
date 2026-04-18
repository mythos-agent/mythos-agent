import * as vscode from "vscode";
import { SphinxScanner } from "./scanner";

let scanner: SphinxScanner;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("shedu");
  scanner = new SphinxScanner(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "shedu.scanWorkspace";
  statusBarItem.text = "$(shield) shedu";
  statusBarItem.tooltip = "Click to scan workspace";
  statusBarItem.show();

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("shedu.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await scanner.scanFile(editor.document);
        updateStatusBar();
      }
    }),

    vscode.commands.registerCommand("shedu.scanWorkspace", async () => {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "shedu: Scanning workspace...",
          cancellable: false,
        },
        async () => {
          await scanner.scanWorkspace();
          updateStatusBar();
        }
      );
    }),

    vscode.commands.registerCommand(
      "shedu.fixVulnerability",
      async (uri: vscode.Uri, diagnostic: vscode.Diagnostic) => {
        await scanner.fixVulnerability(uri, diagnostic);
      }
    ),

    vscode.commands.registerCommand("shedu.clearDiagnostics", () => {
      diagnosticCollection.clear();
      updateStatusBar();
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      const config = vscode.workspace.getConfiguration("shedu");
      if (config.get<boolean>("scanOnSave", true)) {
        await scanner.scanFile(document);
        updateStatusBar();
      }
    })
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(async (document) => {
      if (isSupportedFile(document)) {
        await scanner.scanFile(document);
        updateStatusBar();
      }
    })
  );

  // Code actions (quick fix)
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new SphinxCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // Scan all open files on activation
  for (const editor of vscode.window.visibleTextEditors) {
    if (isSupportedFile(editor.document)) {
      scanner.scanFile(editor.document);
    }
  }

  context.subscriptions.push(diagnosticCollection, statusBarItem);
}

export function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}

function updateStatusBar() {
  let total = 0;
  let critical = 0;

  diagnosticCollection.forEach((uri, diagnostics) => {
    total += diagnostics.length;
    critical += diagnostics.filter(
      (d) => d.severity === vscode.DiagnosticSeverity.Error
    ).length;
  });

  if (total === 0) {
    statusBarItem.text = "$(shield) shedu: Clean";
    statusBarItem.backgroundColor = undefined;
  } else if (critical > 0) {
    statusBarItem.text = `$(shield) shedu: ${critical} critical, ${total} total`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground"
    );
  } else {
    statusBarItem.text = `$(shield) shedu: ${total} issues`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
  }
}

function isSupportedFile(document: vscode.TextDocument): boolean {
  const supported = [
    "typescript",
    "typescriptreact",
    "javascript",
    "javascriptreact",
    "python",
    "go",
    "java",
    "php",
  ];
  return supported.includes(document.languageId);
}

class SphinxCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "shedu") continue;

      // AI Fix action
      const fixAction = new vscode.CodeAction(
        `shedu: Fix with AI`,
        vscode.CodeActionKind.QuickFix
      );
      fixAction.command = {
        command: "shedu.fixVulnerability",
        title: "Fix with AI",
        arguments: [document.uri, diagnostic],
      };
      fixAction.diagnostics = [diagnostic];
      fixAction.isPreferred = true;
      actions.push(fixAction);

      // Suppress action
      const suppressAction = new vscode.CodeAction(
        `shedu: Suppress this warning`,
        vscode.CodeActionKind.QuickFix
      );
      suppressAction.edit = new vscode.WorkspaceEdit();
      const line = document.lineAt(diagnostic.range.start.line);
      suppressAction.edit.insert(
        document.uri,
        line.range.start,
        `// shedu-ignore: ${diagnostic.code}\n`
      );
      suppressAction.diagnostics = [diagnostic];
      actions.push(suppressAction);
    }

    return actions;
  }
}
