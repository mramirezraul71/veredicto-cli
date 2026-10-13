# veredicto — verificación fail-closed para repos

**Tu agente de código dice "listo". `veredicto` no le cree: lo comprueba.**

`veredicto check` inspecciona un repo git, ejecuta su suite de tests **de
verdad** (capturando el resultado real del runner) y emite un veredicto
determinista — `VERIFIED` o `NOT_VERIFIED` — junto con un certificado JSON
que fija exactamente qué estado se verificó (commit, hash del diff, lista de
chequeos con su resultado).

La regla de oro es *fail-closed*: si algo no se puede comprobar, el veredicto
es `NOT_VERIFIED` con el motivo. Nunca se inventa un pase.

## Instalación

Requisitos: Python 3.11+, `git` y, según la suite del repo, `pytest` (en el
entorno del repo o en su `.venv`) y/o Node.js + `npm`.

```bash
pip install veredicto-cli        # cuando se publique en PyPI
# o desde el código fuente:
git clone <este-repo> && cd veredicto-cli
pip install .
```

Para **firmar** certificados (opcional) hace falta la librería
`cryptography`, que va en un extra para no obligar a quien solo verifica
repos:

```bash
pip install "veredicto-cli[sign]"
```

Sin ese extra todo funciona como siempre, pero los certificados salen
sin firmar (marcados `"unsigned"`, ver abajo).

Para desarrollo, sin instalar: `python -m pytest` funciona desde la raíz
del repo (el `conftest.py` mete `src/` en el path).

## Uso

```bash
veredicto check                          # verifica el repo actual
veredicto check --repo /ruta/al/repo     # otro repo
veredicto check --out certificado.json   # guarda el certificado en un archivo
veredicto check --timeout 600            # timeout por suite (defecto: 300 s)
```

Salida humana (una línea) y código de salida pensado para scripts/CI:

```
VERIFIED — /ruta/repo @ 9f31c2ab41d0 · chequeos 3/3 · diff e3b0c44298fc · firmado ed25519 0123456789ab
```

| Código (`check`) | Significado |
|--------|-------------|
| 0 | `VERIFIED` |
| 1 | `NOT_VERIFIED` |
| 2 | error de uso o de firma (se pidió firmar y no se pudo) |

Si no se pasa `--out`, el certificado JSON completo se imprime en stdout
tras la línea de veredicto.

### Firmar el certificado

```bash
# 1. Genera tu par de claves de emisor (una vez). La privada queda con
#    permisos 0600 y nunca se imprime ni entra en ningún certificado.
veredicto keygen --out ~/.veredicto
#   → veredicto-private.pem / veredicto-public.pem + la huella pública

# 2. Firma al verificar: con --key o con la variable de entorno.
veredicto check --repo /ruta/al/repo --out certificado.json \
    --key ~/.veredicto/veredicto-private.pem
export VEREDICTO_KEY=~/.veredicto/veredicto-private.pem
veredicto check --repo /ruta/al/repo --out certificado.json
```

Sin clave configurada, el certificado se emite como siempre pero con
`"signature": {"status": "unsigned"}` — explícito, nunca en silencio.
Si se pide firmar y no se puede (clave ausente, librería sin instalar),
`check` falla con código 2 en vez de emitir un certificado sin firmar
haciendo como que no pasa nada.

### Verificar un certificado (un tercero)

```bash
veredicto verify certificado.json
# SIGNATURE VALID · clave 0123… — la firma ed25519 valida…
veredicto verify certificado.json --pubkey veredicto-public.pem
```

| Código (`verify`) | Significado |
|--------|-------------|
| 0 | firma **válida** |
| 1 | firma **inválida** (contenido alterado, huella que no coincide, o la clave incluida no es la de `--pubkey`) |
| 2 | certificado **sin firma**, no verificable (falta la librería) o error de uso |

Ver el modelo de confianza en la sección del certificado: `--pubkey`
importa.

## Qué verifica

1. **`git-head`** — el path es un repo git y `HEAD` resuelve a un commit
   concreto. Sin HEAD identificable no hay nada verificable.
2. **`working-tree`** — el estado del árbol contra `HEAD` es identificable:
   se calcula el SHA-256 del diff (`git diff HEAD --binary` más el contenido
   de los archivos sin trackear). Un árbol sucio **no** invalida el
   veredicto; el certificado fija el estado exacto que se verificó.
3. **Suite de tests** — detección y ejecución real:
   - Python: si hay archivos `test_*.py` / `*_test.py`, corre `pytest`
     (con el `.venv` del repo si existe). Si pytest no recolecta ningún
     test (rc=5) → *sin suite verificable*.
   - Node: si `package.json` trae un `scripts.test` real (no el placeholder
     de `npm init`), corre `npm test`.
   - Si **no hay suite detectable** → `NOT_VERIFIED` con motivo
     *"sin suite verificable"*. Un repo sin tests no es verificable, y
     punto.

El veredicto es `VERIFIED` solo si **todos** los chequeos pasan.

## El certificado

```json
{
  "tool": "veredicto",
  "tool_version": "0.1.0",
  "verdict": "VERIFIED",
  "reasons": [],
  "repo": "/ruta/absoluta/al/repo",
  "commit": "<sha de HEAD>",
  "diff_sha256": "<sha256 del estado contra HEAD>",
  "working_tree_clean": true,
  "checks": [
    {"name": "git-head", "passed": true, "detail": "..."},
    {"name": "working-tree", "passed": true, "detail": "..."},
    {"name": "tests-pytest", "passed": true, "detail": "..."}
  ],
  "checked_at": "2026-10-13T12:00:00+00:00",
  "signature": {
    "status": "signed",
    "algorithm": "ed25519",
    "public_key": "<clave pública, base64 de los 32 bytes>",
    "public_key_fingerprint": "<sha256 de la clave pública>",
    "signature": "<firma ed25519, base64>"
  },
  "certificate_sha256": "<hash encadenado>"
}
```

El certificado lleva **dos capas distintas**:

1. `certificate_sha256` — **hash encadenado de integridad**: SHA-256 del
   JSON canónico del certificado (sin ese campo ni el bloque de firma;
   que a su vez contiene el hash del commit y el hash del diff). Detecta
   manipulaciones, pero no identifica a nadie: cualquiera puede
   regenerarlo. Se comprueba con `veredicto_cli.check.verify_chain(cert)`.
2. `signature` — **firma ed25519** (opcional, ver "Firmar el
   certificado"): el emisor firma con su clave privada el mismo payload
   canónico. El bloque incluye la clave pública y su huella (SHA-256 de
   los 32 bytes crudos de la clave). La clave privada nunca aparece en el
   certificado ni en los logs. Sin clave, el bloque es solo
   `{"status": "unsigned"}`.

> **Modelo de confianza, sin humo.** La firma prueba dos cosas: que el
> certificado lo emitió quien posee la clave privada correspondiente a
> la pública incluida, y que el contenido no se alteró desde la firma.
> **No** prueba por sí sola que esa clave pública sea de quien dice ser:
> cualquiera puede generar un par de claves, firmar un certificado
> retocado y la verificación contra la clave *incluida* pasará. Por eso
> el tercero debe atar la clave a una identidad por un canal de
> confianza: contrastar la **huella** que muestra `veredicto verify`
> contra la publicada por el emisor, o pasar `--pubkey` con la clave
> obtenida de forma fiable — si la incluida no es esa, el veredicto es
> inválido. Y ni con identidad segura prueba la firma que la suite del
> repo sea buena (ver "Qué NO verifica").

## Qué NO verifica (honestidad de alcance)

- **No juzga la calidad ni la corrección del código.** Verifica que la
  suite del propio repo pasa, no que la suite sea buena: un repo con tests
  triviales o que no cubren lo importante puede salir `VERIFIED`.
- **No verifica afirmaciones en lenguaje natural.** No compara "el agente
  dijo que hizo X" con el diff; solo certifica el estado y la suite.
  (Esa comparación vive en el puente completo de VEREDICTO, no en este CLI.)
- **No detecta tests deshabilitados o amañados** (`skip`, asserts vacíos,
  suites que el propio autor debilitó). Si la suite miente, el certificado
  refleja la mentira con sello bonito.
- **No ejecuta nada fuera de la suite declarada**: ni linters, ni builds,
  ni chequeos de seguridad. Lo que la suite no cubre, no existe para el
  veredicto.
- **La firma no convierte un certificado en verdad absoluta.** Prueba
  origen (la clave) e integridad (nada cambió tras firmar), no que el
  contenido sea *correcto*: un emisor con la clave puede firmar un
  certificado de un repo cuya suite es mala, y un certificado sin firmar
  no gana identidad por llevar el hash encadenado. Nada de esto sustituye
  a la revisión humana.

## Desarrollo

```bash
python -m pytest        # suite propia: VERIFIED / NOT_VERIFIED + firma
                        # (los tests de firma se saltan sin el extra [sign])
```

## Licencia

MIT — ver [LICENSE](LICENSE). Un producto de **Celdilla LLC**.
