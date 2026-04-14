import * as vscode from "vscode";
import { RULES, SECRET_RULES, type Rule } from "./rules";

export class MythohScanner {
  constructor(
    private diagnosticCollection: vscode.DiagnosticCollection
  ) {}

  async scanFile(document: vscode.TextDocument): Promise<void> {
    const config = vscode.workspace.getConfiguration("sphinx-agent");
    const severityThreshold = config.get<string>("severity", "low");
    const enableSecrets = config.get<boolean>("enableSecrets", true);

    const lang = this.getLanguage(document.languageId);
    if (!lang) return;

    const text = document.getText();
    const lines = text.split("\n");
    const diagnostics: vscode.Diagnostic[] = [];

    // Pattern rules
    for (const rule of RULES) {
      if (!rule.languages.includes(lang) && !rule.languages.includes("*"))
        continue;
      if (!this.meetsThreshold(rule.severity, severityThreshold)) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check for suppression comment
        if (i > 0 && lines[i - 1].trim().startsWith("// sphinx-agent-ignore"))
          continue;

        for (const pattern of rule.patterns) {
          const regex = new RegExp(pattern, "gi");
          if (regex.test(line)) {
            const range = new vscode.Range(i, 0, i, line.length);
            const diag = new vscode.Diagnostic(
              range,
              `${rule.title}: ${rule.description}`,
              this.toVsSeverity(rule.severity)
            );
            diag.source = "sphinx-agent";
            diag.code = rule.id;
            if (rule.cwe) {
              diag.code = { value: rule.id, target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${rule.cwe.replace("CWE-", "")}.html`) };
            }
            diagnostics.push(diag);
          }
        }
      }
    }

    // Secrets detection
    if (enableSecrets) {
      for (const rule of SECRET_RULES) {
        if (!this.meetsThreshold(rule.severity, severityThreshold)) continue;

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (i > 0 && lines[i - 1].trim().startsWith("// sphinx-agent-ignore"))
            continue;

          const regex = new RegExp(rule.patterns[0], "gi");
          if (regex.test(line)) {
            const range = new vscode.Range(i, 0, i, line.length);
            const diag = new vscode.Diagnostic(
              range,
              `${rule.title}: ${rule.description}`,
              vscode.DiagnosticSeverity.Error
            );
            diag.source = "sphinx-agent";
            diag.code = rule.id;
            diagnostics.push(diag);
          }
        }
      }
    }

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  async scanWorkspace(): Promise<void> {
    const files = await vscode.workspace.findFiles(
      "**/*.{ts,tsx,js,jsx,py,go,java,php}",
      "**/node_modules/**"
    );

    for (const file of files) {
      const doc = await vscode.workspace.openTextDocument(file);
      await this.scanFile(doc);
    }
  }

  async fixVulnerability(
    uri: vscode.Uri,
    diagnostic: vscode.Diagnostic
  ): Promise<void> {
    const config = vscode.workspace.getConfiguration("sphinx-agent");
    const apiKey = config.get<string>("apiKey", "");

    if (!apiKey) {
      const action = await vscode.window.showWarningMessage(
        "sphinx-agent: API key required for AI fixes. Configure in settings.",
        "Open Settings"
      );
      if (action === "Open Settings") {
        vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "sphinx-agent.apiKey"
        );
      }
      return;
    }

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "sphinx-agent: Generating AI fix...",
        cancellable: false,
      },
      async () => {
        try {
          const document = await vscode.workspace.openTextDocument(uri);
          const line = document.lineAt(diagnostic.range.start.line);
          const lineText = line.text;

          // Call Claude API for fix
          const fix = await this.getAIFix(apiKey, lineText, diagnostic);

          if (fix) {
            const edit = new vscode.WorkspaceEdit();
            edit.replace(uri, line.range, fix);
            await vscode.workspace.applyEdit(edit);
            vscode.window.showInformationMessage(
              `sphinx-agent: Fixed ${typeof diagnostic.code === 'object' ? diagnostic.code.value : diagnostic.code}`
            );
            // Re-scan the file
            const doc = await vscode.workspace.openTextDocument(uri);
            await this.scanFile(doc);
          }
        } catch (err) {
          vscode.window.showErrorMessage(
            `sphinx-agent: Fix failed — ${err instanceof Error ? err.message : "unknown error"}`
          );
        }
      }
    );
  }

  private async getAIFix(
    apiKey: string,
    vulnerableLine: string,
    diagnostic: vscode.Diagnostic
  ): Promise<string | null> {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1024,
        messages: [
          {
            role: "user",
            content: `Fix this security vulnerability. Return ONLY the fixed line of code, nothing else.

Vulnerability: ${diagnostic.message}
Code: ${vulnerableLine}

Fixed code:`,
          },
        ],
      }),
    });

    if (!response.ok) return null;

    const data = (await response.json()) as {
      content: Array<{ type: string; text: string }>;
    };
    const text = data.content?.[0]?.text?.trim();
    return text || null;
  }

  private getLanguage(languageId: string): string | null {
    const map: Record<string, string> = {
      typescript: "typescript",
      typescriptreact: "typescript",
      javascript: "javascript",
      javascriptreact: "javascript",
      python: "python",
      go: "go",
      java: "java",
      php: "php",
    };
    return map[languageId] || null;
  }

  private meetsThreshold(
    severity: string,
    threshold: string
  ): boolean {
    const order = ["critical", "high", "medium", "low", "info"];
    return order.indexOf(severity) <= order.indexOf(threshold);
  }

  private toVsSeverity(
    severity: string
  ): vscode.DiagnosticSeverity {
    switch (severity) {
      case "critical":
        return vscode.DiagnosticSeverity.Error;
      case "high":
        return vscode.DiagnosticSeverity.Error;
      case "medium":
        return vscode.DiagnosticSeverity.Warning;
      case "low":
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Hint;
    }
  }
}
