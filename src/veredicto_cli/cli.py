"""CLI de VEREDICTO.

Uso:
    veredicto check [--repo PATH] [--out CERT.json] [--timeout SEGUNDOS]
                    [--key PRIVADA.pem]
    veredicto keygen [--out DIR]
    veredicto verify CERT.json [--pubkey PUBLICA.pem]

Códigos de salida:
    check:   0 si VERIFIED, 1 si NOT_VERIFIED, 2 si error de uso/config.
    keygen:  0 ok, 2 si error (p. ej. la privada ya existe).
    verify:  0 firma válida, 1 firma inválida, 2 sin firma / no
             verificable / error de uso.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .check import NOT_VERIFIED, VERIFIED, one_line, run_check
from .signing import SigningError, verify_certificate, write_keypair


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veredicto",
        description="Verificación determinista y fail-closed de un repo: "
                    "ejecuta su suite de tests de verdad y emite un "
                    "certificado. Si no puede verificar, dice NOT_VERIFIED.",
    )
    parser.add_argument("--version", action="version",
                        version=f"veredicto {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser(
        "check", help="verifica un repo git y emite el certificado")
    p_check.add_argument("--repo", default=".",
                         help="ruta del repo (defecto: directorio actual)")
    p_check.add_argument("--out", default=None,
                         help="ruta del certificado JSON a escribir; "
                              "si se omite, el certificado va a stdout")
    p_check.add_argument("--timeout", type=int, default=300,
                         help="timeout por suite de tests, en segundos "
                              "(defecto: 300)")
    p_check.add_argument("--key", default=None,
                         help="clave privada ed25519 (PEM) para firmar el "
                              "certificado; si se omite se usa $VEREDICTO_KEY "
                              "y, sin ninguna, el certificado sale sin firmar")

    p_keygen = sub.add_parser(
        "keygen", help="genera el par de claves ed25519 del emisor")
    p_keygen.add_argument("--out", default=".",
                          help="directorio donde escribir veredicto-private.pem "
                               "(0600) y veredicto-public.pem "
                               "(defecto: directorio actual)")

    p_verify = sub.add_parser(
        "verify", help="verifica la firma de un certificado emitido")
    p_verify.add_argument("cert", help="ruta del certificado JSON")
    p_verify.add_argument("--pubkey", default=None,
                          help="clave pública (PEM) de confianza: la incluida "
                               "en el certificado debe ser exactamente esta")
    return parser


def _cmd_check(args) -> int:
    try:
        cert = run_check(args.repo, timeout=args.timeout, key_path=args.key)
    except SigningError as exc:
        print(f"error de firma: {exc}", file=sys.stderr)
        return 2
    print(one_line(cert))
    payload = json.dumps(cert, indent=2, ensure_ascii=False)
    if args.out:
        out = Path(args.out)
        out.write_text(payload + "\n", encoding="utf-8")
        print(f"certificado: {out}")
    else:
        print(payload)
    return 0 if cert["verdict"] == VERIFIED else 1


def _cmd_keygen(args) -> int:
    try:
        priv_path, pub_path, fingerprint = write_keypair(args.out)
    except SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"clave privada: {priv_path} (permisos 0600 — no compartir)")
    print(f"clave pública: {pub_path}")
    print(f"huella de la clave pública (sha256): {fingerprint}")
    print("para firmar:  veredicto check --key "
          f"{priv_path}   (o exporta VEREDICTO_KEY={priv_path})")
    return 0


def _cmd_verify(args) -> int:
    cert_path = Path(args.cert)
    try:
        cert = json.loads(cert_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: no se pudo leer el certificado {cert_path}: {exc}",
              file=sys.stderr)
        return 2
    if not isinstance(cert, dict):
        print("error: el certificado no es un objeto JSON", file=sys.stderr)
        return 2
    expected_pem = None
    if args.pubkey:
        try:
            expected_pem = Path(args.pubkey).read_bytes()
        except OSError as exc:
            print(f"error: no se pudo leer la clave pública: {exc}",
                  file=sys.stderr)
            return 2
    result = verify_certificate(cert, expected_public_pem=expected_pem)
    fp = f" · clave {(result.fingerprint or '')[:16]}…" \
        if result.fingerprint else ""
    if result.status == "valid":
        print(f"SIGNATURE VALID{fp} — {result.detail}")
        return 0
    if result.status == "invalid":
        print(f"SIGNATURE INVALID{fp} — {result.detail}")
        return 1
    if result.status == "unsigned":
        print(f"UNSIGNED — {result.detail}")
        return 2
    print(f"SIGNATURE UNVERIFIABLE — {result.detail}")
    return 2


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "keygen":
        return _cmd_keygen(args)
    if args.command == "verify":
        return _cmd_verify(args)
    return 2  # pragma: no cover — argparse ya exige subcomando


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
