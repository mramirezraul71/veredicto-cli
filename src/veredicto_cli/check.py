"""Núcleo de verificación de VEREDICTO CLI.

Filosofía (heredada del verificador de agent-bridge, reimplementada para un
CLI autónomo): fail-closed. Cualquier cosa que no se pueda comprobar de
forma determinista produce NOT_VERIFIED con su motivo; jamás se asume un
pase.

Chequeos:
  1. git-head      — el path es un repo git y HEAD resuelve a un commit.
  2. working-tree  — el estado del árbol contra HEAD es identificable:
                     se calcula el SHA-256 del diff (tracked) más el
                     contenido de los archivos sin trackear. Un árbol sucio
                     NO invalida el veredicto: el certificado registra
                     exactamente qué estado se verificó.
  3. test-suite    — suite detectable y ejecutada de verdad:
                       · Python: archivos test_*.py / *_test.py → pytest.
                       · Node: package.json con scripts.test real → npm test.
                     Si no hay suite detectable → NOT_VERIFIED con motivo
                     "sin suite verificable". Si pytest no recolecta ningún
                     test (rc=5) también es "sin suite verificable".

El certificado es JSON e incluye un hash encadenado (certificate_sha256):
SHA-256 del JSON canónico del certificado, que a su vez contiene el hash
del commit y el hash del diff. Es un hash de integridad, no identidad.

Firma (opcional, módulo `signing`): si hay clave privada configurada
(`--key` o $VEREDICTO_KEY), el certificado se firma con ed25519 sobre el
mismo payload canónico y lleva la clave pública del emisor y su huella.
Sin clave, el certificado se marca explícitamente `"signature":
{"status": "unsigned"}`. La canonicalización vive en `signing` y es la
fuente única para ambas capas.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess as _sp
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from . import TOOL_NAME, __version__
from .signing import (
    SigningError, chain_hash, load_private_key, resolve_key_path,
    sign_block, unsigned_block,
)

VERIFIED = "VERIFIED"
NOT_VERIFIED = "NOT_VERIFIED"

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
              ".pytest_cache", "dist", "build", ".tox", ".mypy_cache"}

_DEFAULT_NPM_TEST = 'echo "Error: no test specified" && exit 1'


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git(repo: Path, *args: str, timeout: int = 30) -> "_sp.CompletedProcess[bytes]":
    return _sp.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, timeout=timeout,
    )


def _tail(text: str, lines: int = 15) -> str:
    return "\n".join(text.splitlines()[-lines:])


# ---------------------------------------------------------------------------
# Chequeo 1+2: git / árbol de trabajo / diff
# ---------------------------------------------------------------------------

def _untracked_files(repo: Path) -> List[str]:
    """Archivos sin trackear (porcelain -z, ordenados para determinismo)."""
    proc = _git(repo, "status", "--porcelain=v1", "-z")
    if proc.returncode != 0:
        return []
    entries = proc.stdout.split(b"\0")
    untracked = []
    for entry in entries:
        if entry.startswith(b"?? "):
            untracked.append(entry[3:].decode("utf-8", errors="replace"))
    return sorted(untracked)


def _diff_digest(repo: Path) -> Tuple[str, bool, int]:
    """(sha256 del estado contra HEAD, árbol limpio, nº archivos sin trackear).

    El payload hasheado es: bytes de `git diff HEAD --binary` y, por cada
    archivo sin trackear (ordenado por path), su path y el SHA-256 de su
    contenido. Determinista para un mismo estado del árbol.
    """
    diff = _git(repo, "diff", "HEAD", "--binary").stdout
    status = _git(repo, "status", "--porcelain=v1", "-z").stdout
    clean = status.strip() == b""
    untracked = _untracked_files(repo)
    h = hashlib.sha256()
    h.update(diff)
    for rel in untracked:
        h.update(b"\0untracked\0")
        h.update(rel.encode("utf-8", errors="replace"))
        h.update(b"\0")
        try:
            content = (repo / rel).read_bytes()
            h.update(hashlib.sha256(content).digest())
        except (OSError, ValueError):
            h.update(b"<ilegible>")
    return h.hexdigest(), clean, len(untracked)


def check_git(repo: Path) -> Tuple[List[dict], Optional[str], Optional[str], bool]:
    """Devuelve (checks, commit, diff_sha256, working_tree_clean)."""
    checks: List[dict] = []
    inside = _git(repo, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        checks.append({
            "name": "git-head", "passed": False,
            "detail": f"no es un repo git: {repo}",
        })
        checks.append({
            "name": "working-tree", "passed": False,
            "detail": "sin repo git: estado del árbol no identificable",
        })
        return checks, None, None, False
    head = _git(repo, "rev-parse", "HEAD")
    if head.returncode != 0:
        checks.append({
            "name": "git-head", "passed": False,
            "detail": "HEAD no resuelve (repo sin commits): nada verificable",
        })
        checks.append({
            "name": "working-tree", "passed": False,
            "detail": "sin HEAD: diff no calculable",
        })
        return checks, None, None, False
    commit = head.stdout.decode().strip()
    checks.append({
        "name": "git-head", "passed": True,
        "detail": f"HEAD identificable: {commit}",
        "commit": commit,
    })
    diff_hash, clean, n_untracked = _diff_digest(repo)
    if clean:
        detail = "árbol limpio contra HEAD (diff vacío)"
    else:
        detail = (f"árbol con cambios contra HEAD "
                  f"({n_untracked} archivo(s) sin trackear); "
                  f"el certificado fija el estado exacto verificado")
    checks.append({
        "name": "working-tree", "passed": True,
        "detail": detail,
        "diff_sha256": diff_hash,
        "working_tree_clean": clean,
    })
    return checks, commit, diff_hash, clean


# ---------------------------------------------------------------------------
# Chequeo 3: suite de tests (detección + ejecución real)
# ---------------------------------------------------------------------------

def _find_python_tests(repo: Path) -> List[Path]:
    found: List[Path] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if (name.startswith("test_") and name.endswith(".py")) or \
               name.endswith("_test.py"):
                found.append(Path(root) / name)
    return sorted(found)


def _python_interpreter(repo: Path) -> str:
    for cand in (repo / ".venv" / "bin" / "python",
                 repo / ".venv" / "Scripts" / "python.exe",
                 repo / "venv" / "bin" / "python"):
        if cand.is_file():
            return str(cand)
    return sys.executable


def _check_pytest(repo: Path, timeout: int) -> dict:
    interp = _python_interpreter(repo)
    command = [interp, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    base = {"name": "tests-pytest", "runner": "pytest",
            "command": " ".join(command)}
    try:
        proc = _sp.run(command, cwd=repo, capture_output=True, text=True,
                       timeout=timeout, env=env)
    except _sp.TimeoutExpired:
        return {**base, "passed": False,
                "detail": f"timeout tras {timeout}s ejecutando pytest"}
    except FileNotFoundError:
        return {**base, "passed": False,
                "detail": f"intérprete no encontrado: {interp}"}
    out = proc.stdout + proc.stderr
    if "No module named pytest" in out:
        return {**base, "passed": False, "exit_code": proc.returncode,
                "detail": "pytest no está instalado en el entorno del repo: "
                          "suite no ejecutable (fail-closed)"}
    if proc.returncode == 5:
        return {**base, "passed": False, "exit_code": 5,
                "detail": "sin suite verificable: pytest no recolectó "
                          "ningún test (rc=5)"}
    if proc.returncode == 0:
        return {**base, "passed": True, "exit_code": 0,
                "detail": f"pytest OK (rc=0)\n{_tail(out)}"}
    return {**base, "passed": False, "exit_code": proc.returncode,
            "detail": f"tests FALLAN (rc={proc.returncode})\n{_tail(out)}"}


def _npm_test_script(repo: Path) -> Optional[str]:
    pkg = repo / "package.json"
    if not pkg.is_file():
        return None
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    script = (data.get("scripts") or {}).get("test")
    if not script or not str(script).strip():
        return None
    if str(script).strip() == _DEFAULT_NPM_TEST:
        return None  # placeholder de npm init: no es una suite real
    return str(script)


def _check_npm(repo: Path, timeout: int, script: str) -> dict:
    # En Windows npm es un .cmd: CreateProcess no lo ejecuta directamente y
    # hay que lanzarlo vía cmd /c con la ruta resuelta (si no, un Windows con
    # npm instalado parecía "sin npm" y el check fallaba fail-closed).
    _npm = shutil.which("npm")
    if _npm and os.name == "nt" and _npm.lower().endswith((".cmd", ".bat")):
        command = ["cmd", "/c", _npm, "test"]
    else:
        command = ["npm", "test"]
    base = {"name": "tests-npm", "runner": "npm",
            "command": f"npm test  # {script}"}
    try:
        proc = _sp.run(command, cwd=repo, capture_output=True, text=True,
                       timeout=timeout)
    except _sp.TimeoutExpired:
        return {**base, "passed": False,
                "detail": f"timeout tras {timeout}s ejecutando npm test"}
    except FileNotFoundError:
        return {**base, "passed": False,
                "detail": "npm no está disponible en el entorno (fail-closed)"}
    out = proc.stdout + proc.stderr
    if proc.returncode == 0:
        return {**base, "passed": True, "exit_code": 0,
                "detail": f"npm test OK (rc=0)\n{_tail(out)}"}
    return {**base, "passed": False, "exit_code": proc.returncode,
            "detail": f"tests FALLAN (rc={proc.returncode})\n{_tail(out)}"}


def check_tests(repo: Path, timeout: int) -> List[dict]:
    checks: List[dict] = []
    py_tests = _find_python_tests(repo)
    if py_tests:
        checks.append(_check_pytest(repo, timeout))
    npm_script = _npm_test_script(repo)
    if npm_script is not None:
        checks.append(_check_npm(repo, timeout, npm_script))
    if not checks:
        checks.append({
            "name": "test-suite", "passed": False,
            "detail": "sin suite verificable: no se detectaron tests de "
                      "Python (test_*.py / *_test.py para pytest) ni script "
                      "\"test\" en package.json",
        })
    return checks


# ---------------------------------------------------------------------------
# Certificado
# ---------------------------------------------------------------------------

def _chain_hash(cert: dict) -> str:
    # La canonicalización vive en signing (fuente única): excluye
    # certificate_sha256 y el bloque de firma, así que firmar o no firmar
    # no cambia el hash encadenado de un mismo contenido.
    return chain_hash(cert)


def verify_chain(cert: dict) -> bool:
    """Comprueba el hash encadenado de un certificado emitido por esta tool."""
    claimed = cert.get("certificate_sha256")
    if not claimed:
        return False
    return claimed == _chain_hash(cert)


def run_check(repo_path, timeout: int = 300, key_path=None) -> dict:
    """Ejecuta todos los chequeos sobre `repo_path` y devuelve el certificado.

    Firma: si `key_path` (o $VEREDICTO_KEY) apunta a una clave privada
    ed25519, el certificado se firma antes de sellarlo con el hash
    encadenado. Si se pidió firmar y no se puede, SigningError: nunca se
    emite "sin firmar" en silencio cuando se pidió firma.
    """
    repo = Path(repo_path).resolve()
    checks: List[dict] = []
    commit: Optional[str] = None
    diff_hash: Optional[str] = None
    clean = False
    if not repo.is_dir():
        checks.append({
            "name": "git-head", "passed": False,
            "detail": f"el path no existe o no es un directorio: {repo}",
        })
    else:
        git_checks, commit, diff_hash, clean = check_git(repo)
        checks.extend(git_checks)
        if commit is not None:
            checks.extend(check_tests(repo, timeout))
    verdict = VERIFIED if checks and all(c["passed"] for c in checks) \
        else NOT_VERIFIED
    reasons = [c["detail"].splitlines()[0] for c in checks if not c["passed"]]
    cert = {
        "tool": TOOL_NAME,
        "tool_version": __version__,
        "verdict": verdict,
        "reasons": reasons,
        "repo": str(repo),
        "commit": commit,
        "diff_sha256": diff_hash,
        "working_tree_clean": clean if commit is not None else None,
        "checks": checks,
        "checked_at": _utcnow(),
    }
    resolved_key = resolve_key_path(key_path)
    if resolved_key is not None:
        private_key = load_private_key(resolved_key)  # SigningError si no
        cert["signature"] = sign_block(cert, private_key)
    else:
        cert["signature"] = unsigned_block()
    cert["certificate_sha256"] = _chain_hash(cert)
    return cert


def one_line(cert: dict) -> str:
    """Resumen humano de una línea del veredicto."""
    commit = (cert.get("commit") or "sin-HEAD")[:12]
    passed = sum(1 for c in cert["checks"] if c["passed"])
    total = len(cert["checks"])
    diff = (cert.get("diff_sha256") or "—")[:12]
    line = (f"{cert['verdict']} — {cert['repo']} @ {commit} · "
            f"chequeos {passed}/{total} · diff {diff}")
    sig = cert.get("signature") or {}
    if sig.get("status") == "signed":
        fp = (sig.get("public_key_fingerprint") or "")[:12]
        line += f" · firmado ed25519 {fp}"
    else:
        line += " · sin firmar"
    if cert["verdict"] == NOT_VERIFIED and cert.get("reasons"):
        line += f" · motivo: {cert['reasons'][0]}"
    return line
