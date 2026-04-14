import * as vscode from "vscode";
import { MythohScanner } from "./scanner";

let scanner: MythohScanner;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("sphinx-agent");
  scanner = new MythohScanner(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "sphinx-agent.scanWorkspace";
  statusBarItem.text = "$(shield) sphinx-agent";
  statusBarItem.tooltip = "Click to scan workspace";
  statusBarItem.show();

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("sphinx-agent.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await scanner.scanFile(editor.document);
        updateStatusBar();
      }
    }),

    vscode.commands.registerCommand("sphinx-agent.scanWorkspace", async () => {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "sphinx-agent: Scanning workspace...",
          cancellable: false,
        },
        async () => {
          await scanner.scanWorkspace();
          updateStatusBar();
        }
      );
    }),

    vscode.commands.registerCommand(
      "sphinx-agent.fixVulnerability",
      async (uri: vscode.Uri, diagnostic: vscode.Diagnostic) => {
        await scanner.fixVulnerability(uri, diagnostic);
      }
    ),

    vscode.commands.registerCommand("sphinx-agent.clearDiagnostics", () => {
      diagnosticCollection.clear();
      updateStatusBar();
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      const config = vscode.workspace.getConfiguration("sphinx-agent");
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
      new MythohCodeActionProvider(),
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
    statusBarItem.text = "$(shield) sphinx-agent: Clean";
    statusBarItem.backgroundColor = undefined;
  } else if (critical > 0) {
    statusBarItem.text = `$(shield) sphinx-agent: ${critical} critical, ${total} total`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground"
    );
  } else {
    statusBarItem.text = `$(shield) sphinx-agent: ${total} issues`;
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

class MythohCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "sphinx-agent") continue;

      // AI Fix action
      const fixAction = new vscode.CodeAction(
        `sphinx-agent: Fix with AI`,
        vscode.CodeActionKind.QuickFix
      );
      fixAction.command = {
        command: "sphinx-agent.fixVulnerability",
        title: "Fix with AI",
        arguments: [document.uri, diagnostic],
      };
      fixAction.diagnostics = [diagnostic];
      fixAction.isPreferred = true;
      actions.push(fixAction);

      // Suppress action
      const suppressAction = new vscode.CodeAction(
        `sphinx-agent: Suppress this warning`,
        vscode.CodeActionKind.QuickFix
      );
      suppressAction.edit = new vscode.WorkspaceEdit();
      const line = document.lineAt(diagnostic.range.start.line);
      suppressAction.edit.insert(
        document.uri,
        line.range.start,
        `// sphinx-agent-ignore: ${diagnostic.code}\n`
      );
      suppressAction.diagnostics = [diagnostic];
      actions.push(suppressAction);
    }

    return actions;
  }
}
