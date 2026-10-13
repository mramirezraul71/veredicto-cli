"""Tests del núcleo de VEREDICTO CLI.

Cada caso construye un repo git de juguete en tmp_path y comprueba el
veredicto y el certificado contra la realidad del repo.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from veredicto_cli.check import NOT_VERIFIED, VERIFIED, run_check, verify_chain
from veredicto_cli.cli import main

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    import os
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


PASSING = {"test_ok.py": "def test_ok():\n    assert 1 + 1 == 2\n"}
FAILING = {"test_bad.py": "def test_bad():\n    assert 1 + 1 == 3\n"}


def _check_by_name(cert: dict, name: str) -> dict:
    for c in cert["checks"]:
        if c["name"] == name:
            return c
    raise AssertionError(f"check {name} no está en el certificado: "
                         f"{[c['name'] for c in cert['checks']]}")


def test_verified_repo_con_tests_que_pasan(tmp_path):
    repo = make_repo(tmp_path, {**PASSING, "mod.py": "X = 1\n"})
    cert = run_check(repo)
    assert cert["verdict"] == VERIFIED
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert cert["commit"] == head
    assert cert["working_tree_clean"] is True
    assert len(cert["diff_sha256"]) == 64
    assert _check_by_name(cert, "tests-pytest")["passed"] is True
    assert cert["reasons"] == []
    assert verify_chain(cert) is True


def test_not_verified_tests_que_fallan(tmp_path):
    repo = make_repo(tmp_path, FAILING)
    cert = run_check(repo)
    assert cert["verdict"] == NOT_VERIFIED
    assert _check_by_name(cert, "tests-pytest")["passed"] is False
    assert cert["commit"] is not None  # HEAD sí era identificable
    assert verify_chain(cert) is True


def test_not_verified_sin_suite(tmp_path):
    repo = make_repo(tmp_path, {"README.md": "# hola\n"})
    cert = run_check(repo)
    assert cert["verdict"] == NOT_VERIFIED
    suite = _check_by_name(cert, "test-suite")
    assert suite["passed"] is False
    assert "sin suite verificable" in suite["detail"]
    assert any("sin suite verificable" in r for r in cert["reasons"])


def test_not_verified_no_es_repo_git(tmp_path):
    plain = tmp_path / "plano"
    plain.mkdir()
    (plain / "test_ok.py").write_text(PASSING["test_ok.py"])
    cert = run_check(plain)
    assert cert["verdict"] == NOT_VERIFIED
    assert cert["commit"] is None
    assert _check_by_name(cert, "git-head")["passed"] is False


def test_arbol_sucio_se_registra_pero_no_invalida(tmp_path):
    repo = make_repo(tmp_path, {**PASSING, "mod.py": "X = 1\n"})
    clean = run_check(repo)
    (repo / "mod.py").write_text("X = 2\n")
    dirty = run_check(repo)
    assert dirty["verdict"] == VERIFIED
    assert dirty["working_tree_clean"] is False
    assert dirty["diff_sha256"] != clean["diff_sha256"]


def test_cadena_de_hash_detecta_manipulacion(tmp_path):
    repo = make_repo(tmp_path, PASSING)
    cert = run_check(repo)
    assert verify_chain(cert) is True
    cert["verdict"] = VERIFIED if cert["verdict"] == NOT_VERIFIED else NOT_VERIFIED
    assert verify_chain(cert) is False


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm no disponible")
def test_verified_suite_npm(tmp_path):
    pkg = {"package.json": json.dumps(
        {"name": "toy", "scripts": {"test": 'node -e "process.exit(0)"'}})}
    repo = make_repo(tmp_path, pkg)
    cert = run_check(repo)
    assert cert["verdict"] == VERIFIED
    assert _check_by_name(cert, "tests-npm")["passed"] is True


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm no disponible")
def test_not_verified_suite_npm_que_falla(tmp_path):
    pkg = {"package.json": json.dumps(
        {"name": "toy", "scripts": {"test": 'node -e "process.exit(1)"'}})}
    repo = make_repo(tmp_path, pkg)
    cert = run_check(repo)
    assert cert["verdict"] == NOT_VERIFIED
    assert _check_by_name(cert, "tests-npm")["passed"] is False


def test_cli_exit_codes_y_out(tmp_path):
    repo = make_repo(tmp_path, PASSING)
    out = tmp_path / "cert.json"
    rc = main(["check", "--repo", str(repo), "--out", str(out)])
    assert rc == 0
    cert = json.loads(out.read_text(encoding="utf-8"))
    assert cert["verdict"] == VERIFIED

    # repo con tests que fallan → exit 1
    bad = tmp_path / "bad"
    bad.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(bad)],
                   check=True, capture_output=True)
    (bad / "test_bad.py").write_text(FAILING["test_bad.py"])
    _git(bad, "add", "-A")
    _git(bad, "commit", "-q", "-m", "init")
    rc = main(["check", "--repo", str(bad), "--out", str(tmp_path / "c2.json")])
    assert rc == 1
