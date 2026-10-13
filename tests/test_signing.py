"""Tests de la firma ed25519 de certificados (R-05 fase 2).

Se saltan si la librería opcional `cryptography` no está instalada: sin
ella el CLI debe seguir funcionando sin firmar (eso lo cubre test_check).
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="extra 'sign' no instalado")

from veredicto_cli.check import VERIFIED, run_check, verify_chain
from veredicto_cli.cli import main
from veredicto_cli.signing import (
    ENV_KEY_VAR, SigningError, chain_hash, load_private_key,
    public_key_fingerprint, sign_block, unsigned_block, verify_certificate,
    write_keypair,
)

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

PASSING = {"test_ok.py": "def test_ok():\n    assert 1 + 1 == 2\n"}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
        env={**os.environ, **_GIT_ENV},
    )


def make_repo(tmp_path: Path, files: dict) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)],
                   check=True, capture_output=True)
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


@pytest.fixture()
def keypair(tmp_path):
    priv, pub, fingerprint = write_keypair(tmp_path / "keys")
    return priv, pub, fingerprint


def _write_cert(tmp_path: Path, cert: dict, name: str = "cert.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(cert, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

def test_keygen_escribe_par_con_permisos(tmp_path, capsys):
    keys_dir = tmp_path / "keys"
    rc = main(["keygen", "--out", str(keys_dir)])
    assert rc == 0
    priv = keys_dir / "veredicto-private.pem"
    pub = keys_dir / "veredicto-public.pem"
    assert priv.is_file() and pub.is_file()
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert b"PRIVATE KEY" in priv.read_bytes()
    assert b"PRIVATE KEY" not in pub.read_bytes()
    out = capsys.readouterr().out
    # la huella se muestra; el contenido de la privada NUNCA se imprime
    assert public_key_fingerprint(
        load_private_key(priv).public_key().public_bytes_raw()
    ) in out
    assert "PRIVATE KEY" not in out


def test_keygen_no_sobrescribe_privada_existente(tmp_path):
    keys_dir = tmp_path / "keys"
    assert main(["keygen", "--out", str(keys_dir)]) == 0
    assert main(["keygen", "--out", str(keys_dir)]) == 2


# ---------------------------------------------------------------------------
# check con clave → firma que verifica
# ---------------------------------------------------------------------------

def test_check_firmado_verifica_ok(tmp_path, keypair):
    priv, pub, fingerprint = keypair
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo, key_path=priv)
    assert cert["verdict"] == VERIFIED
    sig = cert["signature"]
    assert sig["status"] == "signed"
    assert sig["algorithm"] == "ed25519"
    assert sig["public_key_fingerprint"] == fingerprint
    assert verify_chain(cert) is True  # la capa de hash sigue intacta
    result = verify_certificate(cert)
    assert result.status == "valid"
    assert result.fingerprint == fingerprint
    # y verificando contra la clave pública de confianza, también
    result2 = verify_certificate(cert, expected_public_pem=pub.read_bytes())
    assert result2.status == "valid"


def test_veredicto_firmado_via_variable_de_entorno(tmp_path, keypair,
                                                   monkeypatch):
    priv, _pub, fingerprint = keypair
    monkeypatch.setenv(ENV_KEY_VAR, str(priv))
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo)  # sin key_path: sale de $VEREDICTO_KEY
    assert cert["signature"]["status"] == "signed"
    assert cert["signature"]["public_key_fingerprint"] == fingerprint


def test_cli_check_firmado_y_verify_ok(tmp_path, keypair):
    priv, _pub, _fp = keypair
    repo = make_repo(tmp_path, PASSING)
    out = tmp_path / "cert.json"
    rc = main(["check", "--repo", str(repo), "--out", str(out),
               "--key", str(priv)])
    assert rc == 0
    assert main(["verify", str(out)]) == 0


# ---------------------------------------------------------------------------
# Manipulación tras firmar → rechazo
# ---------------------------------------------------------------------------

def test_certificado_manipulado_tras_firmar_es_rechazado(tmp_path, keypair):
    priv, _pub, _fp = keypair
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo, key_path=priv)
    cert["verdict"] = "NOT_VERIFIED"  # retoque posterior a la firma
    result = verify_certificate(cert)
    assert result.status == "invalid"
    path = _write_cert(tmp_path, cert)
    assert main(["verify", str(path)]) == 1


def test_manipulacion_solo_en_checks_tambien_rechazada(tmp_path, keypair):
    priv, _pub, _fp = keypair
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo, key_path=priv)
    cert["checks"][0]["detail"] += " (retocado)"
    assert verify_certificate(cert).status == "invalid"


def test_clave_sustituida_no_pasa_contra_la_de_confianza(tmp_path, keypair):
    """Ataque: retocar, re-sellar el hash y re-firmar con OTRA clave.

    Contra la clave incluida pasa (es su modelo: integridad + posesión),
    pero contra la clave pública de confianza del emisor real → inválido.
    """
    priv, pub, _fp = keypair
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo, key_path=priv)
    atacante_dir = tmp_path / "atacante"
    a_priv, _a_pub, _a_fp = write_keypair(atacante_dir)
    cert["verdict"] = "NOT_VERIFIED"
    cert.pop("signature")
    cert["signature"] = sign_block(cert, load_private_key(a_priv))
    cert["certificate_sha256"] = chain_hash(cert)
    assert verify_certificate(cert).status == "valid"  # contra la incluida
    contra_confianza = verify_certificate(
        cert, expected_public_pem=pub.read_bytes())
    assert contra_confianza.status == "invalid"
    path = _write_cert(tmp_path, cert)
    assert main(["verify", str(path), "--pubkey", str(pub)]) == 1


# ---------------------------------------------------------------------------
# Sin firma: se dice, no se da por bueno
# ---------------------------------------------------------------------------

def test_verify_sin_firma_lo_dice(tmp_path):
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo)  # sin clave
    assert cert["signature"] == unsigned_block() == {"status": "unsigned"}
    result = verify_certificate(cert)
    assert result.status == "unsigned"
    path = _write_cert(tmp_path, cert)
    assert main(["verify", str(path)]) == 2  # jamás 0


def test_certificado_legacy_sin_bloque_es_unsigned(tmp_path):
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo)
    cert.pop("signature")  # como los de v0.1.0
    assert verify_certificate(cert).status == "unsigned"


def test_sin_clave_todo_como_antes(tmp_path):
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo)
    assert cert["verdict"] == VERIFIED
    assert verify_chain(cert) is True
    assert cert["signature"]["status"] == "unsigned"


def test_clave_inexistente_es_error_no_silencio(tmp_path):
    repo = make_repo(tmp_path, PASSING)
    with pytest.raises(SigningError):
        run_check(repo, key_path=tmp_path / "no-existe.pem")
    rc = main(["check", "--repo", str(repo),
               "--key", str(tmp_path / "no-existe.pem"),
               "--out", str(tmp_path / "c.json")])
    assert rc == 2
