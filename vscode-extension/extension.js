'use strict';
/**
 * Veredicto para VS Code — capa fina sobre el CLI `veredicto`.
 *
 * NO reimplementa ninguna verificación: ejecuta `veredicto check` como
 * subproceso, lee el certificado JSON que el CLI emite y lo presenta.
 *
 * Fail-closed también en la UX: el estado VERIFIED solo se muestra si el
 * CLI terminó, dejó un certificado JSON legible, el certificado dice
 * VERIFIED y el código de salida coincide (0). Cualquier otra cosa
 * (CLI ausente, salida ilegible, contradicción) es NOT_VERIFIED o un
 * aviso de error con el motivo — nunca un pase inventado.
 */

const vscode = require('vscode');
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let outputChannel;
let statusBarItem;

/** Pone la barra de estado en uno de los estados conocidos. */
function setStatus(state, extra) {
  if (!statusBarItem) return;
  switch (state) {
    case 'none':
      statusBarItem.text = '$(question) Veredicto: sin veredicto';
      statusBarItem.tooltip = 'Todavía no se ha comprobado este repo. Clic para ejecutar `veredicto check`.';
      statusBarItem.backgroundColor = undefined;
      break;
    case 'running':
      statusBarItem.text = '$(loading~spin) Veredicto: comprobando…';
      statusBarItem.tooltip = 'Ejecutando el CLI de Veredicto…';
      statusBarItem.backgroundColor = undefined;
      break;
    case 'verified':
      statusBarItem.text = '$(pass-filled) Veredicto: VERIFIED';
      statusBarItem.tooltip = extra || 'El CLI verificó el repo (ver canal de salida «Veredicto»).';
      statusBarItem.backgroundColor = undefined;
      break;
    case 'not-verified':
      statusBarItem.text = '$(error) Veredicto: NOT_VERIFIED';
      statusBarItem.tooltip = extra || 'El CLI NO pudo verificar el repo (ver canal de salida «Veredicto»).';
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      break;
    case 'no-cli':
      statusBarItem.text = '$(warning) Veredicto: sin CLI';
      statusBarItem.tooltip = extra || 'No se encontró el CLI de Veredicto.';
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
      break;
  }
  statusBarItem.show();
}

/** Escribe el detalle completo del certificado en el canal de salida. */
function logCertificate(cert, headline) {
  outputChannel.appendLine('');
  outputChannel.appendLine('─'.repeat(72));
  outputChannel.appendLine(headline);
  outputChannel.appendLine(`Repo:        ${cert.repo}`);
  outputChannel.appendLine(`Commit:      ${cert.commit || '—'}`);
  outputChannel.appendLine(`Diff SHA-256: ${cert.diff_sha256 || '—'}`);
  outputChannel.appendLine(`Árbol limpio: ${cert.working_tree_clean ? 'sí' : 'no'}`);
  outputChannel.appendLine(`Comprobado:  ${cert.checked_at || '—'}`);
  outputChannel.appendLine(`CLI:         veredicto ${cert.tool_version || '?'}`);
  outputChannel.appendLine('Chequeos:');
  for (const c of cert.checks || []) {
    outputChannel.appendLine(`  [${c.passed ? 'OK  ' : 'FAIL'}] ${c.name} — ${c.detail || ''}`);
  }
  if (Array.isArray(cert.reasons) && cert.reasons.length) {
    outputChannel.appendLine('Motivos:');
    for (const r of cert.reasons) outputChannel.appendLine(`  - ${r}`);
  }
  outputChannel.appendLine(`Certificado SHA-256: ${cert.certificate_sha256 || '—'}`);
}

/**
 * Ejecuta el CLI y resuelve con { cert, stdout } o rechaza con Error
 * cuyo mensaje es el motivo legible (CLI ausente, timeout, etc.).
 */
function runCli(cliPath, repoPath, timeoutSec) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veredicto-vscode-'));
  const certPath = path.join(tmpDir, 'certificado.json');
  const args = ['check', '--repo', repoPath, '--out', certPath, '--timeout', String(timeoutSec)];
  return new Promise((resolve, reject) => {
    execFile(
      cliPath,
      args,
      { timeout: (timeoutSec + 60) * 1000, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        const cleanup = () => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) { /* sin efecto */ } };
        if (err && err.code === 'ENOENT') {
          cleanup();
          reject(new Error(`no se encontró el CLI «${cliPath}» en el PATH. Instala el CLI (pip install veredicto-cli) o ajusta el ajuste «veredicto.cliPath».`));
          return;
        }
        // El CLI sale con 1 cuando el veredicto es NOT_VERIFIED: eso NO es
        // un error de ejecución, el certificado manda. Solo tratamos como
        // fallo los códigos distintos de 0/1 o la ausencia de certificado.
        let cert = null;
        try {
          cert = JSON.parse(fs.readFileSync(certPath, 'utf8'));
        } catch (_) {
          cert = null;
        }
        cleanup();
        if (!cert || typeof cert !== 'object' || typeof cert.verdict !== 'string') {
          const detail = (stderr || (err && err.message) || '').trim();
          reject(new Error(`el CLI no dejó un certificado legible${err && typeof err.code === 'number' ? ` (código de salida ${err.code})` : ''}${detail ? `: ${detail}` : ''}.`));
          return;
        }
        resolve({ cert, exitCode: err && typeof err.code === 'number' ? err.code : 0, stdout: stdout || '' });
      }
    );
  });
}

/** Comando principal: veredicto.check */
async function checkRepo() {
  const folders = vscode.workspace.workspaceFolders || [];
  if (!folders.length) {
    vscode.window.showErrorMessage('Veredicto: no hay ninguna carpeta de workspace abierta.');
    setStatus('none');
    return;
  }
  let folder = folders[0];
  if (folders.length > 1) {
    const pick = await vscode.window.showQuickPick(
      folders.map((f) => ({ label: f.name, description: f.uri.fsPath, folder: f })),
      { placeHolder: '¿Qué carpeta quieres comprobar con Veredicto?' }
    );
    if (!pick) return; // cancelado por la persona: sin cambios de estado
    folder = pick.folder;
  }

  const cfg = vscode.workspace.getConfiguration('veredicto');
  const cliPath = cfg.get('cliPath', 'veredicto');
  const timeoutSec = cfg.get('timeout', 300);

  setStatus('running');
  outputChannel.appendLine('');
  outputChannel.appendLine(`> veredicto check --repo "${folder.uri.fsPath}" (vía «${cliPath}»)`);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Veredicto: comprobando el repo…' },
    async () => {
      try {
        const { cert, exitCode, stdout } = await runCli(cliPath, folder.uri.fsPath, timeoutSec);
        const headline = stdout.trim().split('\n')[0] || `veredicto: ${cert.verdict}`;
        logCertificate(cert, headline);

        // Fail-closed: VERIFIED exige certificado VERIFIED *y* salida 0.
        // Si el certificado y el código de salida se contradicen, no se cree
        // a ninguno de los dos: NOT_VERIFIED con el motivo de la contradicción.
        if (cert.verdict === 'VERIFIED' && exitCode === 0) {
          setStatus('verified', headline);
          vscode.window.showInformationMessage(`Veredicto: VERIFIED — ${path.basename(folder.uri.fsPath)} @ ${(cert.commit || '').slice(0, 12)} · chequeos ${(cert.checks || []).filter((c) => c.passed).length}/${(cert.checks || []).length}`);
        } else if (cert.verdict === 'VERIFIED' && exitCode !== 0) {
          setStatus('not-verified');
          outputChannel.appendLine(`CONTRADICCIÓN: el certificado dice VERIFIED pero el CLI salió con código ${exitCode}; se trata como NOT_VERIFIED.`);
          vscode.window.showErrorMessage('Veredicto: NOT_VERIFIED — el certificado y el código de salida del CLI se contradicen.');
        } else {
          setStatus('not-verified');
          const motivos = (cert.reasons || []).join('; ') || 'algún chequeo no pasó';
          vscode.window.showWarningMessage(`Veredicto: NOT_VERIFIED — ${motivos} (detalle en la salida «Veredicto»).`);
          outputChannel.show(true);
        }
      } catch (e) {
        // CLI ausente o salida ilegible: aviso con el motivo, jamás VERIFIED.
        const msg = e && e.message ? e.message : String(e);
        setStatus('no-cli');
        outputChannel.appendLine(`ERROR: ${msg}`);
        outputChannel.show(true);
        vscode.window.showErrorMessage(`Veredicto: no se pudo comprobar — ${msg}`);
      }
    }
  );
}

function activate(context) {
  outputChannel = vscode.window.createOutputChannel('Veredicto');
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBarItem.command = 'veredicto.check';
  setStatus('none');

  const cmd = vscode.commands.registerCommand('veredicto.check', checkRepo);
  context.subscriptions.push(cmd, outputChannel, statusBarItem);
}

function deactivate() {}

module.exports = { activate, deactivate };
