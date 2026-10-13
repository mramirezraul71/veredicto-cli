# Veredicto para VS Code

**Tu agente de código dice "listo". Esta extensión no le cree: le pide al CLI
de Veredicto que lo compruebe, sin salir del editor.**

Es la compañera del CLI [`veredicto`](https://github.com/celdilla/veredicto-cli) (medida R-05 de VEREDICTO,
fase 2). La extensión **no reimplementa ninguna verificación**: ejecuta
`veredicto check` sobre la carpeta del workspace abierto, lee el certificado
JSON que el CLI emite y lo presenta. Si el CLI no está o su salida no es
legible, la extensión lo dice con el motivo — **nunca muestra VERIFIED sin
una salida real del CLI** (fail-closed también en la interfaz).

## Qué hace

- **Comando `Veredicto: Check this repo`** (paleta de comandos y menú
  contextual del explorador): ejecuta el CLI sobre el workspace abierto
  (si hay varias carpetas, pregunta cuál).
- **Notificación con el veredicto**: `VERIFIED` con commit y conteo de
  chequeos, o `NOT_VERIFIED` con los motivos.
- **Panel de salida «Veredicto»** con el detalle completo: commit, hash del
  diff, árbol limpio o sucio, cada chequeo con su resultado, motivos y la
  huella del certificado.
- **Distintivo en la barra de estado** con el último veredicto:
  `sin veredicto` → `comprobando…` → `VERIFIED` / `NOT_VERIFIED`;
  si el CLI no está disponible, `sin CLI` con fondo de aviso. El distintivo
  es clicable y relanza la comprobación.

VERIFIED exige doble acuerdo: el certificado del CLI dice `VERIFIED` **y**
el proceso salió con código 0. Si se contradicen, manda el pesimismo:
`NOT_VERIFIED` con la contradicción anotada en la salida.

## Requisitos

- **El CLI de Veredicto instalado** y alcanzable: `pip install veredicto-cli`
  (o desde el código fuente de este repo). Sin CLI no hay veredicto posible.
- VS Code ≥ 1.80.
- Lo mismo que pida la suite del repo comprobado (Python + pytest y/o
  Node + npm), porque es el CLI quien la ejecuta.

## Ajustes

| Ajuste | Defecto | Qué es |
|---|---|---|
| `veredicto.cliPath` | `veredicto` | Nombre o ruta del ejecutable del CLI, por si no está en el PATH. |
| `veredicto.timeout` | `300` | Timeout por suite de tests que se pasa al CLI (`--timeout`), en segundos. |

## Qué NO hace

- **No verifica nada por sí misma**: ni lee el diff, ni corre tests, ni
  emite certificados. Todo eso es el CLI; esta extensión solo lo invoca
  y presenta su salida.
- **No muestra VERIFIED sin el CLI**: sin ejecutable, sin certificado
  legible o con contradicción entre certificado y código de salida,
  el resultado visible es error o `NOT_VERIFIED`, jamás un pase.
- **No juzga el código ni la suite** (eso ya es límite del propio CLI:
  verifica que la suite del repo pasa, no que la suite sea buena).
- **No guarda ni envía nada**: el certificado temporal se borra al
  terminar; nada sale de la máquina.
- **No firma**: el certificado de v1 lleva un hash encadenado de
  integridad, no una firma criptográfica (ver el README del CLI).

## Desarrollo

La extensión es JavaScript plano, sin paso de compilación:

```bash
node --check extension.js     # comprobación de sintaxis
npm run package               # genera el .vsix con vsce (requiere red la primera vez)
```

Para probarla: abre esta carpeta en VS Code y pulsa F5 (Run Extension),
o instala el `.vsix` con `code --install-extension veredicto-vscode-0.1.0.vsix`.

## Licencia

MIT — ver [LICENSE](https://github.com/celdilla/veredicto-cli/blob/main/LICENSE). Un producto de **Celdilla LLC**.
